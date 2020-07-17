#  Copyright (c) 2017 Cisco Systems, Inc.
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

import copy
from networking_vpp.compat import context
from networking_vpp.compat import db_context_writer
from networking_vpp.compat import events
from networking_vpp.compat import n_provider as provider
from networking_vpp.compat import portbindings
from networking_vpp.compat import registry
from networking_vpp.compat import resource_extend
from networking_vpp.compat import resources
from networking_vpp.compat import trunk_const
from networking_vpp import constants as nvpp_const
from networking_vpp.db import db
from networking_vpp.mech_vpp import JournalManager

from neutron.db import db_base_plugin_common

from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects

from neutron_lib.api.definitions import port as port_def
from neutron_lib.plugins import directory
try:
    from neutron_lib.plugins import utils as plugin_utils
except ImportError:
    from neutron.plugins.common import utils as plugin_utils

from neutron.services.trunk import callbacks
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import rules
from neutron_lib.services import base as service_base

from oslo_log import log as logging
from oslo_utils import uuidutils

LOG = logging.getLogger(__name__)


def kick_communicator_on_end(func):
    # Give the etcd communicator a kick after the method returns
    def new_func(obj, *args, **kwargs):
        return_value = func(obj, *args, **kwargs)
        obj.communicator.kick()
        return return_value
    return new_func


@resource_extend.has_resource_extenders
class VppTrunkPlugin(service_base.ServicePluginBase):
    """Implementation of the VPP Trunk Service Plugin.

    This class implements the trunk service plugin that provides
    support for launching an instance on a vhostuser trunk port.
    """

    supported_extension_aliases = ["trunk", "trunk-details"]

    def __init__(self):
        super(VppTrunkPlugin, self).__init__()
        self.communicator = JournalManager()
        # Supported segmentation type is VLAN
        self._segmentation_types = {
            trunk_const.VLAN: plugin_utils.is_valid_vlan_tag
            }
        # This is needed to prevent deletion of trunk's parent or sub port
        # without first deleting the trunk itself
        registry.subscribe(rules.enforce_port_deletion_rules,
                           resources.PORT, events.BEFORE_DELETE)
        # Subscribe to trunk parent-port binding events
        # We use this event to trigger the etcd trunk key update.
        registry.subscribe(self._trigger_etcd_trunk_update,
                           resources.PORT, events.AFTER_UPDATE)
        registry.notify(trunk_const.TRUNK_PLUGIN, events.AFTER_INIT, self)
        LOG.debug('vpp-trunk: vpp trunk service plugin has initialized')

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_trunk_details(port_res, port_db):
        """Add trunk details to a port."""
        if port_db.trunk_port:
            subports = {
                x.port_id: {'segmentation_id': x.segmentation_id,
                            'segmentation_type': x.segmentation_type,
                            'port_id': x.port_id}
                for x in port_db.trunk_port.sub_ports
            }
            core_plugin = directory.get_plugin()
            ports = core_plugin.get_ports(
                context.get_admin_context(), filters={'id': subports})
            for port in ports:
                subports[port['id']]['mac_address'] = port['mac_address']
            trunk_details = {'trunk_id': port_db.trunk_port.id,
                             'sub_ports': [x for x in subports.values()]}
            port_res['trunk_details'] = trunk_details

        return port_res

    @classmethod
    def get_plugin_type(cls):
        return "trunk"

    def get_plugin_description(self):
        return "Trunk port service plugin for VPP"

    def _get_core_plugin(self):
        return directory.get_plugin()

    def validate_trunk(self, context, trunk):
        """Validate the input trunk data and return a valid trunk object."""
        trunk_details = trunk
        trunk_validator = rules.TrunkPortValidator(trunk['port_id'])
        trunk_details['port_id'] = trunk_validator.validate(context)
        trunk_details['sub_ports'] = self.validate_subports(context,
                                                            trunk['sub_ports'],
                                                            trunk)
        return trunk_details

    def validate_subports(self, context, subports, trunk,
                          basic_validation=False, trunk_validation=True):
        """Validate subports data in the trunk and return a valid subport."""
        subports_validator = rules.SubPortsValidator(
            self._segmentation_types, subports, trunk['port_id'])
        subports = subports_validator.validate(
            context,
            basic_validation=basic_validation,
            trunk_validation=trunk_validation)
        return subports

    def _trunk_path(self, host, port_id):
        return nvpp_const.LEADIN + "/nodes/" + host + "/trunks/" + port_id

    # TODO(najoy): Refactor code for managing remote security-groups by both
    # mech_vpp and trunk_vpp
    def _remote_group_path(self, secgroup_id, port_id):
        remote_group_key_space = nvpp_const.LEADIN + '/global/remote_group'
        return remote_group_key_space + "/" + secgroup_id + "/" + port_id

    def _remote_group_paths(self, port):
        """Compute the remote group paths of a trunk subport."""
        security_groups = port.get('security_groups', [])
        return [self._remote_group_path(secgroup_id, port['port_id'])
                for secgroup_id in security_groups]

    @db_context_writer
    def _write_trunk_journal(self, context, trunk_path, trunk_data):
        """Write the trunk journal to etcd."""
        LOG.info("trunk-service: writing trunk trunk interface journal for "
                 "trunk:%s", trunk_data)
        # Remove extra keys from the trunk_data before writing to etcd
        extra_keys = {'updated_at', 'id', 'port_id', 'revision_number'}
        if isinstance(trunk_data, dict):
            etcd_data = {k: trunk_data[k]
                         for k in set(trunk_data.keys()) - extra_keys}
        else:
            etcd_data = trunk_data
        db.journal_write(context.session, trunk_path, etcd_data)

    @db_context_writer
    def _write_remote_group_journal(self, context, subport_data,
                                    remove_key=False):
        """Writes the remote group journal for a trunk subport.

        subport_data format:
        {'allowed_address_pairs': [],
         'port_id': '6bbf981c-68d4-4664-92b6-ec40eeeb5226',
         'uplink_seg_id': 158,
         'mac_address': u'fa:16:3e:a1:b7:c1',
         'fixed_ips': [{'subnet_id': u'05cfd12c-9db8-4f55-a2b9-aca89f412932',
                        'ip_address': u'10.110.110.6'}],
         'uplink_seg_type': u'vlan',
         'security_groups': [u'8d55a44a-935d-4296-99ab-b0749b725df4'],
         'segmentation_id': 101,
         'port_security_enabled': True,
         'segmentation_type': u'vlan',
         'physnet': u'physnet'}

         To remove a key from etcd, set remove_key=True
        """
        LOG.debug("trunk_service: writing trunk sub-port remote-group "
                  "journal for sub-port %s", subport_data)
        if remove_key:
            data = None
        else:
            data = [item['ip_address'] for item in subport_data['fixed_ips']]

        for remote_group_path in self._remote_group_paths(subport_data):
            LOG.debug('Updating etcd with remote group trunk subport data %s',
                      data)
            db.journal_write(context.session, remote_group_path, data)

    @db_base_plugin_common.convert_result_to_dict
    def _get_trunk_data(self, trunk_obj):
        """Create and return a trunk dict"""
        return trunk_obj

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunk(self, context, trunk_id, fields=None):
        return self._get_trunk(context, trunk_id)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunks(self, context, filters=None, fields=None, sorts=None,
                   limit=None, marker=None, page_reverse=None):
        """Return available trunks."""
        filters = filters or {}
        pager = objects_base.Pager(sorts=sorts, limit=limit,
                                   page_reverse=page_reverse, marker=marker)
        return trunk_objects.Trunk.get_objects(context, _pager=pager,
                                               **filters)

    def _get_trunk(self, context, trunk_id):
        """Return the trunk object or None if not found."""
        trunk_obj = trunk_objects.Trunk.get_object(context, id=trunk_id)
        if trunk_obj is None:
            raise trunk_exc.TrunkNotFound(trunk_id=trunk_id)
        return trunk_obj

    @db_base_plugin_common.convert_result_to_dict
    def create_trunk(self, context, trunk):
        """Create a trunk object."""
        LOG.debug("Creating trunk %s", trunk)
        trunk = self.validate_trunk(context, trunk['trunk'])
        sub_ports = [trunk_objects.SubPort(
            context=context,
            port_id=p['port_id'],
            segmentation_id=p['segmentation_id'],
            segmentation_type=p['segmentation_type'])
            for p in trunk['sub_ports']]
        trunk_obj = trunk_objects.Trunk(
            context=context,
            admin_state_up=trunk.get('admin_state_up', True),
            id=uuidutils.generate_uuid(),
            name=trunk.get('name', ""),
            description=trunk.get('description', ""),
            project_id=trunk['tenant_id'],
            port_id=trunk['port_id'],
            # Trunk will turn active only after it has been bound on a host
            status=trunk_const.DOWN_STATUS,
            sub_ports=sub_ports)
        with db_context_writer.using(context):
            trunk_obj.create()
            payload = callbacks.TrunkPayload(context, trunk_obj.id,
                                             current_trunk=trunk_obj)
            registry.notify(trunk_const.TRUNK,
                            events.PRECOMMIT_CREATE, self,
                            payload=payload)
        registry.notify(trunk_const.TRUNK,
                        events.AFTER_CREATE, self,
                        payload=payload)
        return trunk_obj

    def add_data_to_subports(self, context, trunk_data):
        """Add network and security data to trunk subports.

        Side effect: Updates the parameter trunk_data to include
        the uplink network info and subport security/mac/ip address info.
        """
        for subport in trunk_data['sub_ports']:
            port_id = subport['port_id']
            port = self._get_core_plugin().get_port(context, port_id)
            network = self._get_core_plugin().get_network(context,
                                                          port['network_id'])
            subport['physnet'] = network[provider.PHYSICAL_NETWORK]
            subport['uplink_seg_type'] = network[provider.NETWORK_TYPE]
            subport['uplink_seg_id'] = network[provider.SEGMENTATION_ID]
            subport['allowed_address_pairs'] = port['allowed_address_pairs']
            subport['port_security_enabled'] = port['port_security_enabled']
            subport['security_groups'] = port['security_groups']
            subport['mac_address'] = port['mac_address']
            subport['fixed_ips'] = port['fixed_ips']
        LOG.debug('Updated trunk data %s for trunk port %s', trunk_data,
                  trunk_data['port_id'])
        return trunk_data

    @kick_communicator_on_end
    def _trigger_etcd_trunk_update(self, resource, event, trigger, **kwargs):
        """Trigger an etcd update on a network trunk update event.

        This method triggers an etcd key update for the network trunk. A
        trunk update event calls this method during parent port binds or
        subport adds and removals.When invoked, this method fetches the
        updated trunk object and writes to the etcd journal.
        """
        context = kwargs['context']
        original_port = kwargs['original_port']
        current_port = kwargs['port']
        port_id = current_port['id']
        # return if the port is not a trunk
        trunk_details = current_port.get('trunk_details')
        # Check if the port is a parent of a trunk
        if not trunk_details:
            return
        LOG.debug("Triggering a trunk update with data %s", kwargs)
        LOG.debug("Fetching trunk data for port %s", port_id)
        trunk_obj = trunk_objects.Trunk.get_object(context,
                                                   port_id=port_id)
        if trunk_obj:
            trunk_data = self._get_trunk_data(trunk_obj)
            # Add uplink network data to trunk to enable binding
            trunk_data = self.add_data_to_subports(context, trunk_data)
            # Bind - write to etcd
            if (current_port[portbindings.VIF_TYPE] ==
                    portbindings.VIF_TYPE_VHOST_USER):
                # Update the original trunk port if it's already bound
                if (original_port[portbindings.VIF_TYPE] ==
                        portbindings.VIF_TYPE_VHOST_USER):
                    LOG.debug('Updating the bound trunk port %s', port_id)
                else:
                    LOG.debug('Binding the trunk port %s', port_id)
                # Write remote-group etcd keys for subports
                for subport_data in trunk_data['sub_ports']:
                    self._write_remote_group_journal(context, subport_data)
                host = current_port['binding:host_id']
                LOG.debug('Updating etcd with trunk_data %s', trunk_data)
                self.update_trunk(context, trunk_obj.id,
                                  {'trunk': {'status':
                                             trunk_const.ACTIVE_STATUS}})
                update_etcd = True
            # Unbind - delete from etcd
            elif (current_port[portbindings.VIF_TYPE] ==
                    portbindings.VIF_TYPE_UNBOUND and
                    original_port[portbindings.VIF_TYPE] ==
                    portbindings.VIF_TYPE_VHOST_USER):
                LOG.debug('Unbinding trunk port %s', port_id)
                host = original_port[portbindings.HOST_ID]
                # Remove all remote-group subport keys from etcd
                for subport_data in trunk_data['sub_ports']:
                    self._write_remote_group_journal(context,
                                                     subport_data,
                                                     remove_key=True)
                # remove the trunk key from etcd
                trunk_data = None
                self.update_trunk(context, trunk_obj.id,
                                  {'trunk': {'status':
                                             trunk_const.DOWN_STATUS}})
                update_etcd = True
            else:
                # This does not affect a vhostuser port, so no
                # change is required
                update_etcd = False

            if update_etcd:
                trunk_path = self._trunk_path(host, port_id)
                self._write_trunk_journal(context, trunk_path, trunk_data)

    @db_base_plugin_common.convert_result_to_dict
    def update_trunk(self, context, trunk_id, trunk):
        """Update the trunk object."""
        LOG.debug("Updating trunk %s trunk_id %s", trunk, trunk_id)
        trunk_data = trunk['trunk']
        with db_context_writer.using(context):
            trunk_obj = self._get_trunk(context, trunk_id)
            original_trunk = copy.deepcopy(trunk_obj)
            trunk_obj.update_fields(trunk_data, reset_changes=True)
            trunk_obj.update()
            payload = callbacks.TrunkPayload(context, trunk_id,
                                             original_trunk=original_trunk,
                                             current_trunk=trunk_obj)
            registry.notify(trunk_const.TRUNK,
                            events.PRECOMMIT_UPDATE, self,
                            payload=payload)
        registry.notify(trunk_const.TRUNK,
                        events.AFTER_UPDATE, self,
                        payload=payload)
        return trunk_obj

    def delete_trunk(self, context, trunk_id):
        """Delete the trunk port."""
        LOG.debug("Deleting trunk_id %s", trunk_id)
        deleted_from_db = False
        with db_context_writer.using(context):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)
            trunk_port_validator = rules.TrunkPortValidator(trunk.port_id)
            if not trunk_port_validator.is_bound(context):
                trunk.delete()
                deleted_from_db = True
                payload = callbacks.TrunkPayload(context, trunk_id,
                                                 original_trunk=trunk)
                registry.notify(trunk_const.TRUNK,
                                events.PRECOMMIT_DELETE, self,
                                payload=payload)
            else:
                raise trunk_exc.TrunkInUse(trunk_id=trunk_id)
        if deleted_from_db:
            registry.notify(trunk_const.TRUNK,
                            events.AFTER_DELETE, self,
                            payload=payload)

    @db_base_plugin_common.convert_result_to_dict
    def add_subports(self, context, trunk_id, subports):
        """Add one or more subports to a trunk."""
        LOG.debug("Adding subports %s to trunk %s", subports, trunk_id)
        trunk = self._get_trunk(context, trunk_id)
        subports = subports['sub_ports']
        subports = self.validate_subports(context, subports, trunk,
                                          basic_validation=True)
        added_subports = []
        rules.trunk_can_be_managed(context, trunk)
        original_trunk = copy.deepcopy(trunk)
        # The trunk should not be in the ERROR_STATUS
        if trunk.status == trunk_const.ERROR_STATUS:
            raise trunk_exc.TrunkInErrorState(trunk_id=trunk_id)
        else:
            # The trunk will transition to DOWN and subsequently to ACTIVE
            # when a subport is added.
            trunk.update(status=trunk_const.DOWN_STATUS)
        with db_context_writer.using(context):
            for subport in subports:
                subport_obj = trunk_objects.SubPort(
                    context=context,
                    trunk_id=trunk_id,
                    port_id=subport['port_id'],
                    segmentation_type=subport['segmentation_type'],
                    segmentation_id=subport['segmentation_id'])
                subport_obj.create()
                trunk['sub_ports'].append(subport_obj)
                added_subports.append(subport_obj)
            payload = callbacks.TrunkPayload(context, trunk_id,
                                             current_trunk=trunk,
                                             original_trunk=original_trunk,
                                             subports=added_subports)
            if added_subports:
                registry.notify(trunk_const.SUBPORTS,
                                events.PRECOMMIT_CREATE,
                                self, payload=payload)
                self.send_subport_update_to_etcd(context, trunk)
        if added_subports:
            registry.notify(trunk_const.SUBPORTS,
                            events.AFTER_CREATE,
                            self, payload=payload)
        return trunk

    def send_subport_update_to_etcd(self, context, trunk):
        """After a trunk subport update, write the current value in etcd."""
        LOG.debug('Sending etcd subport update for the parent port %s',
                  trunk.port_id)
        port = self._get_core_plugin().get_port(context, trunk.port_id)
        # The parent port is unchanged when subports are updated
        kwargs = {'context': context,
                  'original_port': port,
                  'port': port}
        self._trigger_etcd_trunk_update(trunk_const.SUBPORTS,
                                        events.AFTER_UPDATE,
                                        self,
                                        **kwargs)

    @db_base_plugin_common.convert_result_to_dict
    def remove_subports(self, context, trunk_id, subports):
        """Remove one or more subports from the trunk.

        param: subports:
        {u'sub_ports': [{u'port_id': u'fa006724-dbca-4e7f-bb6b-ec70162eb681'}]}
        """
        LOG.debug("Removing subports %s from trunk %s", subports, trunk_id)
        trunk = self._get_trunk(context, trunk_id)
        original_trunk = copy.deepcopy(trunk)
        # key-value data corresponding to original trunk
        original_trunk_data = self._get_trunk_data(trunk)
        # ID's of subports to remove
        subports_to_remove = [pid['port_id'] for pid in subports['sub_ports']]
        LOG.debug('trunk subports to remove: %s', subports_to_remove)
        subports = subports['sub_ports']
        subports = self.validate_subports(context, subports, trunk,
                                          basic_validation=True,
                                          trunk_validation=False)
        removed_subports = []
        rules.trunk_can_be_managed(context, trunk)
        # The trunk should not be in the ERROR_STATUS
        if trunk.status == trunk_const.ERROR_STATUS:
            raise trunk_exc.TrunkInErrorState(trunk_id=trunk_id)
        else:
            # The trunk will transition to DOWN and subsequently to ACTIVE
            # when a subport is removed.
            trunk.update(status=trunk_const.DOWN_STATUS)
        current_subports = {p.port_id: p for p in trunk.sub_ports}
        # Ensure that all sub-ports to be removed are actually present
        for subport in subports:
            if subport['port_id'] not in current_subports:
                raise trunk_exc.SubPortNotFound(trunk_id=trunk_id,
                                                port_id=subport['port_id'])
        with db_context_writer.using(context):
            for subport in subports:
                subport_obj = current_subports.pop(subport['port_id'])
                subport_obj.delete()
                removed_subports.append(subport_obj)
            if removed_subports:
                del trunk.sub_ports[:]
                trunk.sub_ports.extend(current_subports.values())
                payload = callbacks.TrunkPayload(
                    context, trunk_id,
                    current_trunk=trunk,
                    original_trunk=original_trunk,
                    subports=removed_subports
                    )
                registry.notify(trunk_const.SUBPORTS,
                                events.PRECOMMIT_DELETE,
                                self, payload=payload)
                self.send_subport_update_to_etcd(context, trunk)
                # Subport data to remove
                subports = [
                    subport for subport in original_trunk_data['sub_ports'] if
                    subport['port_id'] in subports_to_remove]
                original_trunk_data['sub_ports'] = subports
                trunk_data = self.add_data_to_subports(context,
                                                       original_trunk_data)
                # Remove all remote-group subport keys from etcd
                LOG.debug('trunk data with subports to remove: %s',
                          trunk_data)
                for subport_data in trunk_data['sub_ports']:
                    self._write_remote_group_journal(context,
                                                     subport_data,
                                                     remove_key=True)
        if removed_subports:
            registry.notify(trunk_const.SUBPORTS,
                            events.AFTER_DELETE,
                            self, payload=payload)
        return trunk

    @db_base_plugin_common.filter_fields
    def get_subports(self, context, trunk_id, fields=None):
        trunk = self.get_trunk(context, trunk_id)
        return {'sub_ports': trunk['sub_ports']}
