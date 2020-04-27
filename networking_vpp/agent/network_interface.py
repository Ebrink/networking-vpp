# Copyright (c) 2017 Cisco Systems, Inc.
# All Rights Reserved
#
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

# Defines network types and network interface APIs
from abc import ABCMeta
from abc import abstractmethod
from networking_vpp.agent import server
from oslo_log import log as logging
import six
import sys

LOG = logging.getLogger(__name__)


@six.add_metaclass(ABCMeta)
class NetworkInterface(object):
    @abstractmethod
    def ensure_network(self, physnet, net_type, segmentation_id):
        """Ensures the specified network type in VPP.

        Params:
            physnet: Physical network name (string)
            net_type: Network type (flat, vlan or gpe)
            segmentation_id: Virtual Network Identifier (integer)

        Returns:
            Network Data:
            {
                'physnet': physnet,
                'if_physnet': physical_interface_name,
                'bridge_domain_id': bridge_idx,
                'network_type': net_type,
                'segmentation_id': segmentation_id,
                'if_uplink_idx': if_uplink
            }
        """
        pass

    @abstractmethod
    def delete_network(self, physnet, net_type, segmentation_id):
        """Deletes the specified network type from VPP.

        Params:
            physnet: Physical network name (string)
            net_type: Network type (flat, vlan or gpe)
            segmentation_id: Virtual Network Identifier (integer)

        Returns:
            None
        """
        pass

    @abstractmethod
    def get_network(self, physnet, net_type, segmentation_id):
        """Gets the network data.

        Params:
            physnet: Physical network name (string)
            net_type: Network type (flat, vlan or gpe)
            segmentation_id: Virtual Network Identifier (integer)

        Returns:
            Network Data:
            {
                'physnet': physnet,
                'if_physnet': physical_interface_name,
                'bridge_domain_id': bridge_idx,
                'network_type': net_type,
                'segmentation_id': segmentation_id,
                'if_uplink_idx': if_uplink
            }
        """
        pass


class NetworkInterfaceDriver(NetworkInterface):
    """Implements the Network Interface"""
    def __init__(self, vppf):
        self.vppf = vppf
        self.vpp = self.vppf.vpp
        self.networks = {}   # (physnet, type, ID): datastruct

    def ensure_network(self, physnet, net_type, segmentation_id):
        intf, ifidx = self.vppf.get_if_for_physnet(physnet)
        if intf is None:
            LOG.error('net-driver: cannot create network because physnet '
                      '%s config is broken', physnet)
            return None

        # Ensure network for the specified type
        if (physnet, net_type, segmentation_id) not in self.networks:
            net = self._ensure_network_for_type(
                net_type,
                physnet=physnet,
                segmentation_id=segmentation_id,
                intf=intf,
                ifidx=ifidx)
            if net:
                self.networks[(physnet, net_type, segmentation_id)] = net
            else:
                LOG.debug("net-driver: ensuring network %s failed for type %s",
                          net, net_type)
                sys.exit(1)
        return self.networks.get((physnet, net_type, segmentation_id), None)

    def delete_network(self, physnet, net_type, segmentation_id):
        net = self.networks.get((physnet,
                                 net_type,
                                 segmentation_id,), None)
        if net is not None:
            self._delete_network_for_type(net_type, **net)
            self.networks.pop((physnet,
                               net_type,
                               segmentation_id,))

    def get_network(self, physnet, net_type, segmentation_id):
        return self.networks.get((physnet, net_type, segmentation_id), None)

    def _ensure_network_for_type(self, net_type, **kwargs):
        f_name = "_ensure_" + net_type + "_network"
        return self._get_func(f_name, net_type)(**kwargs)

    def _delete_network_for_type(self, net_type, **kwargs):
        f_name = "_delete_" + net_type + "_network"
        self._get_func(f_name, net_type)(**kwargs)

    def _get_func(self, f_name, net_type):
        func = getattr(self, f_name, None)
        if func is None:
            LOG.error('net-driver: cannot manage network because the network '
                      'type:%s is not supported', net_type)
            sys.exit(1)
        return func

    def _ensure_network_bridge(self, bridge_idx):
        self.vppf.ensure_bridge_domain_in_vpp(bridge_idx)

    def _delete_network_bridge(self, net):
        """Delete a bridge corresponding to a network from VPP

        params:
           net: VPPF network data
                {
                    'physnet': physnet,
                    'if_physnet': physical_interface_name,
                    'bridge_domain_id': bridge_idx,
                    'network_type': net_type,
                    'segmentation_id': segmentation_id,
                    'if_uplink_idx': if_uplink
                }
        Usable on restart - uses nothing but the data in VPP.
        """
        net_type = net['network_type']
        bridge_domain_id = net['bridge_domain_id']
        uplink_if_idx = net.get('if_uplink_idx', None)
        self.vppf.delete_network_bridge_on_host(net_type,
                                                bridge_domain_id,
                                                uplink_if_idx)

    def _ensure_flat_network(self, **kwargs):
        LOG.debug('net-driver: ensuring flat network')
        if_uplink = bridge_idx = kwargs['ifidx']
        self.vppf.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)
        self.vpp.ifup(if_uplink)
        return {
            'physnet': kwargs['physnet'],
            'if_physnet': kwargs['intf'],
            'bridge_domain_id': bridge_idx,
            'network_type': 'flat',
            'segmentation_id': kwargs['segmentation_id'],
            'if_uplink_idx': if_uplink
            }

    def _delete_flat_network(self, **kwargs):
        net = kwargs
        self._delete_network_bridge(net)

    def _ensure_vlan_network(self, **kwargs):
        LOG.debug('net-driver: ensuring vlan network')
        # Get network data
        intf, ifidx, segmentation_id = (kwargs['intf'],
                                        kwargs['ifidx'],
                                        kwargs['segmentation_id'])
        # Besides the vlan sub-interface we need to also bring
        # up the primary uplink interface for Vlan networking
        self.vpp.ifup(ifidx)
        if_uplink = self.vpp.get_vlan_subif(intf, segmentation_id)
        if if_uplink is None:
            if_uplink = self.vpp.create_vlan_subif(ifidx,
                                                   segmentation_id)
        self.vpp.ifup(if_uplink)
        # Our bridge IDs have one uplink interface in so we simply use
        # that ID as their domain ID
        # This means we can find them on resync from the tagged interface
        bridge_idx = if_uplink
        self.vppf.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)
        self.vpp.set_interface_tag(if_uplink,
                                   server.uplink_tag(kwargs['physnet'],
                                                     'vlan',
                                                     segmentation_id))
        rv = {
            'physnet': kwargs['physnet'],
            'if_physnet': intf,
            'bridge_domain_id': bridge_idx,
            'network_type': 'vlan',
            'segmentation_id': segmentation_id,
            'if_uplink_idx': if_uplink
            }
        return rv

    def _delete_vlan_network(self, **kwargs):
        net = kwargs
        LOG.debug('net-driver: deleting vlan network: %s', net)
        # Deleting the network bridge, cleans up the Vlan uplink
        self._delete_network_bridge(net)

    def _ensure_gpe_network(self, **kwargs):
        LOG.debug('net-driver: ensuring gpe network')
        segmentation_id = kwargs['segmentation_id']
        self.vppf.gpe.ensure_gpe_link()
        bridge_idx = self.vppf.gpe.bridge_idx_for_segment(segmentation_id)
        self._ensure_network_bridge(bridge_idx)
        self.vppf.gpe.ensure_gpe_vni_to_bridge_mapping(segmentation_id,
                                                       bridge_idx)

        # We attach the bridge to GPE without use of an uplink interface
        # as we affect forwarding in the bridge.
        if_uplink = None
        return {
            'physnet': kwargs['physnet'],
            'if_physnet': kwargs['intf'],
            'bridge_domain_id': bridge_idx,
            'network_type': 'gpe',
            'segmentation_id': segmentation_id,
            'if_uplink_idx': if_uplink
            }

    def _delete_gpe_network(self, **kwargs):
        net = kwargs
        bridge_domain_id = net['bridge_domain_id']
        segmentation_id = net['segmentation_id']
        self.vppf.gpe.delete_vni_from_gpe_map(segmentation_id)
        # Delete all remote mappings corresponding to this VNI
        self.vppf.gpe.clear_remote_gpe_mappings(segmentation_id)
        # Delete VNI to bridge domain mapping
        self.vppf.gpe.delete_gpe_vni_to_bridge_mapping(
            segmentation_id, bridge_domain_id)
        self._delete_network_bridge(net)
