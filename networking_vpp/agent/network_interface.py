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
from networking_vpp.extension import VPPAgentExtensionBase
from oslo_log import log as logging
import six
import sys
from typing import Dict

LOG = logging.getLogger(__name__)


@six.add_metaclass(ABCMeta)
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

    def __init__(self):
        self.net_type = ''      # network types set this field upon init
        # vppf & vpp attributes are set by hooking the network type into
        # the network-interface driver class
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

    def hook_to_driver(self):
        """A hook into the Network Interface Driver.

        This method hooks the network type into the network interface
        driver class.
        """
        LOG.debug("Hooking %s network-type to the net-driver", self.net_type)
        NetworkInterfaceDriver.register(self)

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
    def __init__(self):
        super(VlanNetworkType, self).__init__()
        self.net_type = 'vlan'

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
    def __init__(self):
        super(FlatNetworkType, self).__init__()
        self.net_type = 'flat'

    def create_network_in_vpp(self, physnet, net_type, segmentation_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        if_uplink = bridge_idx = ifidx
        self.vppf.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)
        self.vpp.ifup(if_uplink)
        return (intf, if_uplink, bridge_idx)

    def remove_network_from_vpp(self, net):
        self.delete_network_bridge(net)


class GpeNetworkType(GenericNetworkType):
    def __init__(self):
        super(GpeNetworkType, self).__init__()
        self.net_type = 'gpe'

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


class NetworkInterfaceDriver(object):
    """A Driver that loads and manages all network types"""

    # dict is populated when net_types register with the driver
    net_types: Dict[str, GenericNetworkType] = {}  # Network-Type: DriverObj

    # Class Attributes VPPF and VPP are set on driver init

    def __init__(self, vppf):
        self.__class__.vppf = vppf
        self.__class__.vpp = vppf.vpp
        # Register network types with the Driver
        self.register_network_types()
        # Ensure all types are valid
        self.ensure_valid_types()

    def ensure_valid_types(self):
        """Ensures that a registered network type object is valid.

        Ensures that the network type is a valid subclass of the base type
        Sets the VPPF & VPP attribute for the network type.
        """
        for net_type, typeObj in self.net_types.items():
            LOG.debug("Checking %s network type",
                      net_type)
            if not isinstance(typeObj, NetworkTypeBase):
                LOG.error("Invalid network-type %s. "
                          "Network type is expected to be an instance of the "
                          "NetworkTypeBase Class", net_type)
                sys.exit(1)
            # Set the VPPF & VPP attribute of the type driver
            LOG.debug("Setting VPPF & VPP attributes for the %s network type",
                      net_type)
            setattr(typeObj, 'vppf', self.__class__.vppf)
            setattr(typeObj, 'vpp', self.__class__.vpp)

    @classmethod
    def register(cls, typeObj):
        """Registers a Network Type Object with this Driver Class.

        This is a class level method to enable arbitrary network types
        to register with the driver without instantiating a driver object.

        :param typeObj: A Network Type Object subclassed from
                        GenericNetworkType
        """
        net_type = typeObj.net_type
        LOG.debug("Registering network type %s with type driver",
                  net_type)
        if net_type not in cls.net_types:
            cls.net_types[net_type] = typeObj
            LOG.debug("Registered network type %s with the Type Driver",
                      net_type)
        else:
            LOG.debug("%s network type is already registered",
                      net_type)

    def register_network_types(self):
        """Registers all base network types with the Driver."""
        for net_type in [VlanNetworkType, FlatNetworkType, GpeNetworkType]:
            net_type().hook_to_driver()

    def ensure_network(self, physnet, net_type, segmentation_id):
        # Ensures network for a network-type & returns network data
        return self._get_func("ensure_network", net_type)(physnet,
                                                          net_type,
                                                          segmentation_id)

    def delete_network(self, physnet, net_type, segmentation_id):
        # Deletes network for a network-type
        self._get_func("delete_network", net_type)(physnet,
                                                   net_type,
                                                   segmentation_id)

    def get_network(self, physnet, net_type, segmentation_id):
        # Gets the network data for a network-type
        return self._get_func("get_network", net_type)(physnet,
                                                       net_type,
                                                       segmentation_id)

    def _get_func(self, f_name, net_type):
        try:
            driver = self.net_types[net_type]
            func = getattr(driver, f_name)
            return func
        except KeyError:
            LOG.error('net-driver: The network type '
                      '%s is not supported', net_type)
            sys.exit(1)
