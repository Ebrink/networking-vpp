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
from abc import abstractmethod
from networking_vpp.agent import server
from networking_vpp.extension import VPPAgentExtensionBase
from oslo_config import cfg
from oslo_log import log as logging
import stevedore.driver
import sys
from typing import Dict

LOG = logging.getLogger(__name__)


# TODO(ijw): is this an agent extension?  Unclear, but it would be
# nice if it worked out the dependency needs since other extensions
# might depend on it
class NetworkTypeBase(VPPAgentExtensionBase):
    """An abstract base class for creating network types.

    Any network type supported by the vpp-agent must be subclassed from
    this abstract base class. The vpp-agent will load all the network types
    by instantiating the NetworkInterfaceDriver class.

    When the network types are loaded and initialized, they will hook
    themselves into the NetworkInterfaceDriver class.
    """

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
            Network Data or None, if the network is not present
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

    def initialize(self, manager):
        pass

    def run(self, host, client_factory, vpp_forwarder, gthread_pool):
        pass


class GenericNetworkType(NetworkTypeBase):
    """This type provides common type-driver logic to all network types.

    Concrete Network Types inherit from this type and implement its two
    abstract methods: create_network_in_vpp() & remove_network_from_vpp()
    """

    def __init__(self, net_type, vppf, vpp):
        self.net_type = net_type
        self.vppf = vppf
        self.vpp = vpp

        self.networks = {}       # (physnet, type, ID): datastruct

    def get_if_for_physnet(self, physnet):
        intf, ifidx = self.vppf.get_if_for_physnet(physnet)
        if intf is None:
            LOG.error('Cannot create network because physnet '
                      '%s config is broken', physnet)
            sys.exit(1)
        return (intf, ifidx)

    def delete_network_bridge(self, net):
        """Delete a bridge corresponding to a network from VPP.

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

    def ensure_network(self, physnet, net_type, segmentation_id):
        LOG.debug('%s net-driver ensuring network for Physnet:%s '
                  'Net-Type:%s, Segmentation_ID:%s',
                  net_type, physnet, net_type, segmentation_id)
        if (physnet, net_type, segmentation_id) not in self.networks:
            if_physnet, if_uplink, bridge_idx = self.create_network_in_vpp(
                physnet, net_type, segmentation_id)
            net = {
                'physnet': physnet,
                'if_physnet': if_physnet,
                'bridge_domain_id': bridge_idx,
                'network_type': net_type,
                'segmentation_id': segmentation_id,
                'if_uplink_idx': if_uplink
                }
            self.networks[(physnet, net_type, segmentation_id)] = net
        return self.networks.get((physnet, net_type, segmentation_id), None)

    def delete_network(self, physnet, net_type, segmentation_id):
        net = self.get_network(physnet, net_type, segmentation_id)
        if net is not None:
            LOG.debug('%s net-driver: deleting network: %s', net_type, net)
            self.remove_network_from_vpp(net)
            self.networks.pop((physnet,
                               net_type,
                               segmentation_id,))

    def get_network(self, physnet, net_type, segmentation_id):
        return self.networks.get((physnet, net_type, segmentation_id), None)

    def initialize(self, manager):
        """Initialization from the VPP Agent Extension Manager.

        When the driver extension is enabled in the ml2_conf.ini, this
        method hooks the network-type into the network interface driver class,
        enabling the network types to be dynamically loaded into the
        Network Interface Driver.
        """
        self.hook_to_driver()

    @abstractmethod
    def create_network_in_vpp(self, physnet, net_type, segmentation_id):
        """Creates the network in VPP.

        Network type drivers subclass this class and implement this
        method to provision the network type in VPP.
        Returns: A 3 element tuple: (if_physnet, if_uplink, bridge_idx)
                 if_physnet      : The Physnet Interface Name in VPP
                 if_uplink       : The Uplink Interface Index in VPP
                 bridge_idx      : Bridge Domain Index in VPP
        """
        pass

    @abstractmethod
    def remove_network_from_vpp(self, net):
        """Remove a provisioned network from VPP.

        Network type drivers subclass this class and implement this
        method to remove a provisioned network type from VPP.
        param: net: VPPF network data
                    {
                         'physnet': physnet,
                         'if_physnet': physical_interface_name,
                         'bridge_domain_id': bridge_idx,
                         'network_type': net_type,
                         'segmentation_id': segmentation_id,
                         'if_uplink_idx': if_uplink
                    }
        Returns: None
        """
        pass


class VlanNetworkType(GenericNetworkType):

    def create_network_in_vpp(self, physnet, net_type, segmentation_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        self.vpp.ifup(ifidx)
        if_uplink = self.vpp.get_vlan_subif(intf, segmentation_id)
        if if_uplink is None:
            if_uplink = self.vpp.create_vlan_subif(ifidx,
                                                   segmentation_id)
        bridge_idx = if_uplink
        self.vpp.set_interface_tag(if_uplink,
                                   server.uplink_tag(physnet,
                                                     net_type,
                                                     segmentation_id))
        self.vppf.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)
        self.vpp.ifup(if_uplink)
        return (intf, if_uplink, bridge_idx)

    def remove_network_from_vpp(self, net):
        self.delete_network_bridge(net)


class FlatNetworkType(GenericNetworkType):

    def create_network_in_vpp(self, physnet, net_type, segmentation_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        if_uplink = bridge_idx = ifidx
        self.vppf.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)
        self.vpp.ifup(if_uplink)
        return (intf, if_uplink, bridge_idx)

    def remove_network_from_vpp(self, net):
        self.delete_network_bridge(net)


class GpeNetworkType(GenericNetworkType):

    def create_network_in_vpp(self, physnet, net_type, segmentation_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        self.vpp.ifup(ifidx)
        self.vppf.gpe.ensure_gpe_link()
        bridge_idx = self.vppf.gpe.bridge_idx_for_segment(segmentation_id)
        self.vppf.ensure_bridge_domain_in_vpp(bridge_idx)
        self.vppf.gpe.ensure_gpe_vni_to_bridge_mapping(segmentation_id,
                                                       bridge_idx)
        # We attach the bridge to GPE without use of an uplink interface
        # as we affect forwarding in the bridge.
        if_uplink = None
        return (intf, if_uplink, bridge_idx)

    def remove_network_from_vpp(self, net):
        bridge_domain_id = net['bridge_domain_id']
        segmentation_id = net['segmentation_id']
        self.vppf.gpe.delete_vni_from_gpe_map(segmentation_id)
        # Delete all remote mappings corresponding to this VNI
        self.vppf.gpe.clear_remote_gpe_mappings(segmentation_id)
        # Delete VNI to bridge domain mapping
        self.vppf.gpe.delete_gpe_vni_to_bridge_mapping(
            segmentation_id, bridge_domain_id)
        self.delete_network_bridge(net)


class BadDriver(Exception):
    """If we have a driver load failure, we raise this"""
    pass


class NetworkInterfaceDriver(object):
    """A Driver that loads and manages all network types"""

    # Class Attributes VPPF and VPP are set on driver init

    def __init__(self, vppf):
        self.vppf = vppf
        self.vpp = vppf.vpp

        # dict is populated when net_types register with the driver
        # Network-Type: DriverObj
        self.net_types: Dict[str, GenericNetworkType] = {}

        # Register network types with the Driver
        self.register_network_types()

    def register_network_types(self):
        """Registers all configured network types."""

        failure = {'msg': ''}

        def add_failure(msg):
            failure['msg'] += msg + "\n"

        def on_failure(mgr, entrypoint, ex):
            # Record any driver loading problems so we see them all together
            add_failure(
                '%s: failed to load %s: %s' % (mgr.namespace,
                                               entrypoint,
                                               ex))

        drivers_to_load = cfg.CONF.ml2_vpp.network_types.split(',')
        drivers_to_load = [f.strip().rstrip()
                           for f in drivers_to_load]

        for name in drivers_to_load:
            try:
                mgr = stevedore.driver.DriverManager(
                    'networking_vpp.networks',
                    name,
                    invoke_on_load=True,
                    invoke_args=(name, self.vppf, self.vpp),
                    on_load_failure_callback=on_failure)

                driver = mgr.driver

                if not isinstance(driver, NetworkTypeBase):
                    add_failure("Network driver %s does not implement the"
                                " NetworkTypeBase API and cannot be loaded"
                                % name)
                else:
                    self.net_types[name] = driver
                    LOG.info("Loaded driver %s", name)

            except stevedore.exception.NoMatches:
                add_failure('Cannot find VPP network driver %s' % name)
            except stevedore.exception.MultipleMatches:
                add_failure(
                    'Multiple copies of VPP network driver %s available'
                    % name)

        if failure['msg'] != '':
            raise BadDriver(failure['msg'])

    def ensure_network(self, physnet, net_type, segmentation_id):
        # Ensures network for a network-type & returns network data
        return self._get_driver(net_type).ensure_network(
            physnet,
            net_type,
            segmentation_id)

    def delete_network(self, physnet, net_type, segmentation_id):
        # Deletes network for a network-type
        self._get_driver(net_type).delete_network(
            physnet,
            net_type,
            segmentation_id)

    def get_network(self, physnet, net_type, segmentation_id):
        # Gets the network data for a network-type
        return self._get_driver(net_type).get_network(
            physnet,
            net_type,
            segmentation_id)

    def _get_driver(self, net_type):
        try:
            return self.net_types[net_type]
        except KeyError:
            LOG.error('net-driver: The network type '
                      '%s is not supported', net_type)

            # TODO(ijw): maybe we only have to dail to find the
            # socket?  I don't think it's the end of the world if we
            # don't support a network type, because another host or
            # driver (e.g. SRIOV) might support it
            sys.exit(1)
