# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Resources for Nova Server Auto Scale.
"""

import copy

from heat.engine import properties
from heat.engine import environment
from heat.engine import resource
from heat.engine import stack_resource
from heat.engine import signal_responder
from heat.engine.properties import Properties
from heat.engine.resources import autoscaling
from heat.engine.resources import server
from heat.db.sqlalchemy import api as db_api
from heat.common import exception

from heat.openstack.common import log as logging
from heat.openstack.common.gettextutils import _
from heat.openstack.common import timeutils

logger = logging.getLogger(__name__)

class CooldownMixin(object):
    '''
    Utility class to encapsulate Cooldown related logic which is shared
    between AutoScalingGroup and ScalingPolicy
    '''
    def _cooldown_inprogress(self):
        inprogress = False
        try:
            # Negative values don't make sense, so they are clamped to zero
            cooldown = max(0, int(self.properties['cooldown']))
        except TypeError:
            # If not specified, it will be None, same as cooldown == 0
            cooldown = 0

        metadata = self.metadata
        if metadata and cooldown != 0:
            last_adjust = metadata.keys()[0]
            if not timeutils.is_older_than(last_adjust, cooldown):
                inprogress = True
        return inprogress

    def _cooldown_timestamp(self, reason):
        # Save resource metadata with a timestamp and reason
        # If we wanted to implement the AutoScaling API like AWS does,
        # we could maintain event history here, but since we only need
        # the latest event for cooldown, just store that for now
        metadata = {timeutils.strtime(): reason}
        self.metadata = metadata

class ServerGroup(stack_resource.StackResource):
    tags_schema = {'Key': {'Type': 'String',
                           'Required': True},
                   'Value': {'Type': 'String',
                             'Required': True}}
    properties_schema = {
        'launch_configuration_name': {
            'Required': True,
            'Type': 'String',
            'Description': _('Name of launch_configuration resource.')},
        'size': {
            'Required': True,
            'Type': 'Number',
            'Description': _('Desired number of instances.')},
        'load_balancer_names': {
            'Type': 'List',
            'Description': _('List of LoadBalancer resources.')},
        'tags': {
            'Type': 'List',
            'Schema': {'Type': 'Map', 'Schema': tags_schema},
            'Description': _('Tags to attach to this group.')}
    }
    update_allowed_keys = ('properties', 'update_policy',)
    update_allowed_properties = ('size', 'launch_configuration_name',)
    attributes_schema = {
        "server_list": _("A comma-delimited list of server ip addresses. "
                          "(Heat extension).")
    }
    rolling_update_schema = {
        'min_instances_in_service': properties.Schema(properties.NUMBER,
                                                   default=0),
        'max_batch_size': properties.Schema(properties.NUMBER,
                                          default=1),
        'pause_time': properties.Schema(properties.STRING,
                                       default='PT0S')
    }
    update_policy_schema = {
        'rolling_update': properties.Schema(properties.MAP,
                                           schema=rolling_update_schema)
    }

    def __init__(self, name, json_snippet, stack):
        """
        update_policy is currently only specific to ServerGroup and
        AutoScalingServerGroup. Therefore, init is overridden to parse for the
        update_policy.
        """
        super(ServerGroup, self).__init__(name, json_snippet, stack)
        self.update_policy = Properties(self.update_policy_schema,
                                        self.t.get('update_policy', {}),
                                        parent_name=self.name)

    def validate(self):
        """
        Add validation for update_policy
        """
        super(ServerGroup, self).validate()
        if self.update_policy:
            self.update_policy.validate()

    def get_instance_names(self):
        """Get a list of resource names of the instances in this InstanceGroup.

        Failed resources will be ignored.
        """
        return sorted(x.name for x in self.get_instances())

    def get_instances(self):
        """Get a set of all the server resources managed by this group."""
        return [resource for resource in self.nested()
                if resource.state[1] != resource.FAILED]

    def handle_create(self):
        """Create a nested stack and add the initial resources to it."""
        num_instances = int(self.properties['size'])
        initial_template = self._create_template(num_instances)
        return self.create_with_template(initial_template, {})

    def check_create_complete(self, task):
        """
        When stack creation is done, update the load balancer.

        If any instances failed to be created, delete them.
        """
        done = super(ServerGroup, self).check_create_complete(task)
        if done:
            self._lb_reload()
        return done

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        """
        If properties has changed, update self.properties, so we
        get the new values during any subsequent adjustment.
        """
        if tmpl_diff:
            # parse update policy
            if 'update_policy' in tmpl_diff:
                self.update_policy = Properties(
                    self.update_policy_schema,
                    json_snippet.get('update_policy', {}),
                    parent_name=self.name)

        if prop_diff:
            self.properties = Properties(self.properties_schema,
                                         json_snippet.get('properties', {}),
                                         self.stack.resolve_runtime_data,
                                         self.name)

            # Get the current capacity, we may need to adjust if
            # size has changed
            if 'size' in prop_diff:
                inst_list = self.get_instances()
                if len(inst_list) != int(self.properties['size']):
                    self.resize(int(self.properties['size']))

    def _tags(self):
        """
        Make sure that we add a tag that Ceilometer can pick up.
        These need to be prepended with 'metering.'.
        """
        tags = self.properties.get('tags') or []
        for t in tags:
            if t['Key'].startswith('metering.'):
                # the user has added one, don't add another.
                return tags
        return tags + [{'Key': 'metering.groupname',
                        'Value': self.FnGetRefId()}]

    def handle_delete(self):
        return self.delete_nested()

    def _create_template(self, num_instances):
        """
        Create a template with a number of instance definitions based on the
        launch configuration.
        """
        conf_name = self.properties['launch_configuration_name']
        conf = self.stack.resource_by_refid(conf_name)
        instance_definition = copy.deepcopy(conf.t)
        instance_definition['Type'] = 'OS::Nova::Server'
        # resolve references within the context of this stack.
        fully_parsed = self.stack.resolve_runtime_data(instance_definition)

        resources = {}
        for i in range(num_instances):
            resources["%s-%d" % (self.name, i)] = fully_parsed
        return {"Resources": resources}

    def resize(self, new_capacity):
        """
        Resize the instance group to the new capacity.

        When shrinking, the newest instances will be removed.
        """
        logger.info("Resizing the ServerGroup to %s " % new_capacity)
        new_template = self._create_template(new_capacity)
        logger.info("Template looks like %s " % new_template)
        try:
            updater = self.update_with_template(new_template, {})
            logger.info("updater is %s " % updater)
            updater.run_to_completion()
            self.check_update_complete(updater)
        finally:
            # Reload the LB in any case, so it's only pointing at healthy
            # nodes.
            self._lb_reload()

    def _lb_reload(self):
        '''
        Notify the LoadBalancer to reload its config to include
        the changes in instances we have just made.

        This must be done after activation (instance in ACTIVE state),
        otherwise the instances' IP addresses may not be available.
        '''
        if self.properties['load_balancer_names']:
            id_list = [inst.FnGetRefId() for inst in self.get_instances()]
            for lb in self.properties['load_balancer_names']:
                lb_resource = self.stack[lb]
                if 'servers' in lb_resource.properties_schema:
                    lb_resource.json_snippet['properties']['servers'] = (
                        id_list)
                elif 'members' in lb_resource.properties_schema:
                    lb_resource.json_snippet['properties']['members'] = (
                        id_list)
                else:
                    raise exception.Error(
                        "Unsupported resource '%s' in load_balancer_names" %
                        (lb,))
                resolved_snippet = self.stack.resolve_static_data(
                    lb_resource.json_snippet)
                scheduler.TaskRunner(lb_resource.update, resolved_snippet)()


    def _resolve_attribute(self, name):
        '''
        heat extension: "server_list" returns comma delimited list of server
        ip addresses.
        '''
        if name == 'server_list':
            return inst.addresses

    def _environment(self):
        """Return the environment for the nested stack."""
        return {
            environment.PARAMETERS: {},
            environment.RESOURCE_REGISTRY: {
                SCALED_RESOURCE_TYPE: 'OS::Nova::Server',
            },
        }


class AutoScalingServerGroup(ServerGroup, CooldownMixin):
    tags_schema = {'Key': {'Type': 'String',
                           'Required': True},
                   'Value': {'Type': 'String',
                             'Required': True}}
    properties_schema = {
        'launch_configuration_name': {
            'Required': True,
            'Type': 'String',
            'Description': _('Name of LaunchConfiguration resource.')},
        'max_size': {
            'Required': True,
            'Type': 'String',
            'Description': _('Maximum number of instances in the group.')},
        'min_size': {
            'Required': True,
            'Type': 'String',
            'Description': _('Minimum number of instances in the group.')},
        'cooldown': {
            'Type': 'Number',
            'Description': _('Cooldown period, in seconds.')},
        'desired_capacity': {
            'Type': 'Number',
            'Description': _('Desired initial number of instances.')},
        'health_check_grace_period': {
            'Type': 'Integer',
            'Implemented': False,
            'Description': _('Not Implemented.')},
        'health_check_type': {
            'Type': 'String',
            'AllowedValues': ['ELB'],
            'Implemented': False,
            'Description': _('Not Implemented.')},
        'load_balancer_names': {
            'Type': 'List',
            'Description': _('List of LoadBalancer resources.')},
        'tags': {
            'Type': 'List',
            'Schema': {'Type': 'Map', 'Schema': tags_schema},
            'Description': _('Tags to attach to this group.')}
    }
    rolling_update_schema = {
        'min_instances_in_service': properties.Schema(properties.NUMBER,
                                                   default=0),
        'max_batch_size': properties.Schema(properties.NUMBER,
                                          default=1),
        'pause_time': properties.Schema(properties.STRING,
                                       default='PT0S')
    }
    update_policy_schema = {
        'auto_scaling_rolling_update': properties.Schema(
            properties.MAP, schema=rolling_update_schema)
    }

    # template keys and properties supported for handle_update,
    # note trailing comma is required for a single item to get a tuple
    update_allowed_keys = ('properties', 'update_policy',)
    update_allowed_properties = ('launch_configuration_name',
                                 'max_size', 'min_size',
                                 'cooldown', 'desired_capacity',)

    def handle_create(self):
        if self.properties['desired_capacity']:
            num_to_create = int(self.properties['desired_capacity'])
        else:
            num_to_create = int(self.properties['min_size'])
        initial_template = self._create_template(num_to_create)
        return self.create_with_template(initial_template, {})

    def check_create_complete(self, task):
        """Invoke the cooldown after creation succeeds."""
        done = super(AutoScalingServerGroup, self).check_create_complete(task)
        if done:
            self._cooldown_timestamp(
                "%s : %s" % ('exact_capacity', len(self.get_instances())))
        return done

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        """
        If Properties has changed, update self.properties, so we get the new
        values during any subsequent adjustment.
        """
        if tmpl_diff:
            # parse update policy
            if 'update_policy' in tmpl_diff:
                self.update_policy = Properties(
                    self.update_policy_schema,
                    json_snippet.get('update_policy', {}),
                    parent_name=self.name)

        if prop_diff:
            self.properties = Properties(self.properties_schema,
                                         json_snippet.get('properties', {}),
                                         self.stack.resolve_runtime_data,
                                         self.name)

            # Get the current capacity, we may need to adjust if
            # MinSize or MaxSize has changed
            capacity = len(self.get_instances())

            # Figure out if an adjustment is required
            new_capacity = None
            if 'min_size' in prop_diff:
                if capacity < int(self.properties['min_size']):
                    new_capacity = int(self.properties['min_size'])
            if 'max_size' in prop_diff:
                if capacity > int(self.properties['max_size']):
                    new_capacity = int(self.properties['max_size'])
            if 'desired_capacity' in prop_diff:
                if self.properties['desired_capacity']:
                    new_capacity = int(self.properties['desired_capacity'])

            if new_capacity is not None:
                self.adjust(new_capacity, adjustment_type='exact_capacity')

    def adjust(self, adjustment, adjustment_type='change_in_capacity'):
        """
        Adjust the size of the scaling group if the cooldown permits.
        """
        if self._cooldown_inprogress():
            logger.info("%s NOT performing scaling adjustment, cooldown %s" %
                        (self.name, self.properties['cooldown']))
            return

        capacity = len(self.get_instances())
        logger.info("Checking group capacity and it's currently %d " % capacity)
        logger.info("Adjustment type is %s " % adjustment_type)
        if adjustment_type == 'change_in_capacity':
            new_capacity = capacity + adjustment
        elif adjustment_type == 'exact_capacity':
            new_capacity = adjustment
        else:
            # PercentChangeInCapacity
            new_capacity = capacity + (capacity * adjustment / 100)

        if new_capacity > int(self.properties['max_size']):
            logger.warn('can not exceed %s' % self.properties['max_size'])
            return
        if new_capacity < int(self.properties['min_size']):
            logger.warn('can not be less than %s' % self.properties['min_size'])
            return

        if new_capacity == capacity:
            logger.debug('no change in capacity %d' % capacity)
            return

        result = self.resize(new_capacity)

        self._cooldown_timestamp("%s : %s" % (adjustment_type, adjustment))

        return result

    def _tags(self):
        """Add Identifing Tags to all servers in the group.

        This is so the Dimensions received from cfn-push-stats all include
        the groupname and stack id.
        Note: the group name must match what is returned from FnGetRefId
        """
        autoscaling_tag = [{'Key': 'auto_scaling_group_name',
                            'Value': self.FnGetRefId()}]
        return super(AutoScalingServerGroup, self)._tags() + autoscaling_tag

    def validate(self):
        res = super(AutoScalingServerGroup, self).validate()
        if res:
            return res

class LaunchConfiguration(resource.Resource):
    tags_schema = {'Key': {'Type': 'String',
                           'Required': True},
                   'Value': {'Type': 'String',
                             'Required': True}}
    properties_schema = server.Server.properties_schema

class ScalingPolicy(signal_responder.SignalResponder, CooldownMixin):
    properties_schema = {
        'name': {
            'Type': 'String',
            'Required': True,
            'Description': _('AutoScaling group name to apply policy to.')},
        'scaling_adjustment': {
            'Type': 'Number',
            'Required': True,
            'Description': _('Size of adjustment.')},
        'adjustment_type': {
            'Type': 'String',
            'AllowedValues': ['change_in_capacity',
                              'exact_capacity',
                              'percent_change_in_capacity'],
            'Required': True,
            'Description': _('Type of adjustment (absolute or percentage).')},
        'cooldown': {
            'Type': 'Number',
            'Description': _('Cooldown period, in seconds.')},
    }

    update_allowed_keys = ('properties',)
    update_allowed_properties = ('scaling_adjustment', 'adjustment_type',
                                 'cooldown',)
    attributes_schema = {
        "alarm_url": _("A signed url to handle the alarm. "
                      "(Heat extension).")
    }

    def handle_update(self, json_snippet, tmpl_diff, prop_diff):
        """
        If Properties has changed, update self.properties, so we get the new
        values during any subsequent adjustment.
        """
        if prop_diff:
            self.properties = Properties(self.properties_schema,
                                         json_snippet.get('properties', {}),
                                         self.stack.resolve_runtime_data,
                                         self.name)

    def handle_signal(self, details=None):
        # ceilometer sends details like this:
        # {u'alarm_id': ID, u'previous': u'ok', u'current': u'alarm',
        #  u'reason': u'...'})
        # in this policy we currently assume that this gets called
        # only when there is an alarm. But the template writer can
        # put the policy in all the alarm notifiers (nodata, and ok).
        #
        # our watchrule has upper case states so lower() them all.
        if details is None:
            alarm_state = 'alarm'
        else:
            alarm_state = details.get('current',
                                      details.get('state', 'alarm')).lower()

        logger.info('%s Alarm, new state %s' % (self.name, alarm_state))

        if alarm_state != 'alarm':
            return
        if self._cooldown_inprogress():
            logger.info("%s NOT performing scaling action, cooldown %s" %
                        (self.name, self.properties['cooldown']))
            return

        asgn_id = self.properties['name']
        group = self.stack.resource_by_refid(asgn_id)

        logger.info('%s Alarm, adjusting Group %s by %s' %
                    (self.name, group.name,
                     self.properties['scaling_adjustment']))
        group.adjust(int(self.properties['scaling_adjustment']),
                     self.properties['adjustment_type'])

        self._cooldown_timestamp("%s : %s" %
                                 (self.properties['adjustment_type'],
                                  self.properties['scaling_adjustment']))

    def _resolve_attribute(self, name):
        '''
        heat extension: "AlarmUrl" returns the url to post to the policy
        when there is an alarm.
        '''
        if name == 'alarm_url' and self.resource_id is not None:
            return unicode(self._get_signed_url())

    def FnGetRefId(self):
        if self.resource_id is not None:
            return unicode(self._get_signed_url())
        else:
            return unicode(self.name)


def resource_mapping():
    return {
        'Nova::AutoScaling::LaunchConfiguration': LaunchConfiguration,
        'Nova::AutoScaling::AutoScalingServerGroup': AutoScalingServerGroup,
        'Nova::AutoScaling::ScalingPolicy': ScalingPolicy,
        'Nova::AutoScale::ServerGroup': ServerGroup,
    }
