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

import etcd
from ipaddress import ip_address
from ipaddress import ip_interface
from ipaddress import ip_network
from networking_vpp.constants import LEADIN
from networking_vpp import etcdutils
from networking_vpp.extension import VPPAgentExtensionBase
from networking_vpp import vpp_constants as vpp_const
import neutron.agent.linux.ip_lib as ip_lib
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)


def ipnet(ip):
    return ip_network(ip)


def ipaddr(ip):
    return ip_address(ip)


class TaasServiceAgentWatcher(etcdutils.EtcdChangeWatcher):
    """Watch for changes in TaaS flow destinations."""

    path = 'taas_service'

    def __init__(self, host, etcd_client_factory, vppf):
        self._node_key_space = LEADIN + '/nodes/%s/%s' % (host, self.path)
        self._state_key_space = LEADIN + \
            '/state_taas/%s/%s' % (host, self.path)
        self.etcd_client = etcd_client_factory.client()
        self.vppf = vppf
        self._host = host
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._node_key_space)
        etcd_helper.ensure_dir(self._state_key_space)
        super(TaasServiceAgentWatcher, self).__init__(self.etcd_client,
                                                      self.path,
                                                      self._node_key_space)

    def added(self, key, value):
        """New TAP service created

        The TAP service nominates a port, which should be subverted for
        tapping purposes.
        """
        tap_service_id = key
        # Structure is created in taas_vpp.py in mech driver
        data = jsonutils.loads(value)

        # TODO(ijw): this does not respond to changes in the port after this
        # moment
        port_path = (LEADIN + '/nodes/' + self._host + '/ports/' +
                     str(data['tap_service']['port_id']))
        try:
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            physnet = port_info['physnet']
            if data['dest_type'] == 'ERSPAN_INT':
                network_type = 'vlan'
            else:
                network_type = port_info['network_type']

            # Tapped packets for this destination will be put on their own
            # overlay
            # NB we use VXLAN flows if the port was attached to a VXLAN
            # network originally.  The TaaS service object can't express
            # carrying networks properly, and if we're using VXLAN networks
            # there may be no L2 transport between hosts.
            # For unknown types we fall back to VLAN - for VXLAN we require
            # the GPE config.
            if network_type != 'vxlan':
                network_type = 'vlan'

            port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                         str(data['tap_service']['port_id']))
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            port_sw_if_idx = port_info['iface_idx']
            old_bridge_domain_id = port_info['net_data']['bridge_domain_id']

            if network_type == 'vxlan':
                # TODO(ijw): magic number - will go away when we
                # get BD tags
                bd_idx = data['taas_id'] + 64000
                self.vppf.ensure_bridge_domain_in_vpp(bd_idx)
                bridge_data = {
                    'physnet': physnet,
                    'if_physnet': -1,
                    'bridge_domain_id': bd_idx,
                    'network_type': network_type,
                    'segmentation_id': data['taas_id'],
                }

            else:
                bridge_data = self.vppf.net_driver.ensure_network(
                    physnet,
                    network_type,
                    data['taas_id'])

            # Since we want all packets regardless of MAC to go to the other
            # end, we want the bridge to flood
            if data['dest_type'] != 'ERSPAN_INT':
                self.vppf.vpp.bridge_enable_flooding(
                    bridge_data['bridge_domain_id'])

            # Tapped interfaces feed this bridge; this interface will
            # receive the results.
            # TODO(ijw): this does not prevent the receiving interface
            # from transmitting traffic.
            self.vppf.vpp.add_to_bridge(bridge_data['bridge_domain_id'],
                                        port_sw_if_idx)

            # TODO(ijw) we should not be using etcd for state storage -
            # we might not get to store this if we're reset
            # Instead we should be tagging the interface to mark it
            # for finding on resync
            props = {"ts": data,
                     "service_bridge": bridge_data,
                     "port": {"iface_idx": port_sw_if_idx,
                              "bridge_domain_id": old_bridge_domain_id}}

            self.etcd_client.write(self._state_key_space +
                                   '/%s' % tap_service_id,
                                   jsonutils.dumps(props))
        except etcd.EtcdKeyNotFound:
            pass

    def removed(self, key):
        """A TAP Service has been deleted."""

        try:
            # TODO(ijw): this should discover info from VPP tags, not use
            # etcd as a state store.
            taas_path = self._state_key_space + '/' + key
            tap_service_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)

            # put back the port to the old bridge
            # TODO(ijw): this should just bind the port conventionally,
            # using the port info, as this info can get outdated.
            self.vppf.vpp.add_to_bridge(
                tap_service_info['port']['bridge_domain_id'],
                tap_service_info['port']['iface_idx'])

            # In the nominal case, the tap flows are deleted before the tap
            # service.
            # TODO(jb): The code needs to manage properly the case of deleting
            # tap service with remaining tap flows.
            # TODO(ijw): delete any mirroring on the host for this
            # service.

            physnet = tap_service_info['service_bridge']['physnet']
            net_type = tap_service_info['service_bridge']['network_type']
            seg_id = tap_service_info['service_bridge']['segmentation_id']
            if net_type == 'vxlan':
                bd_idx = tap_service_info['service_bridge']['bridge_domain_id']
                self.vppf.vpp.delete_bridge_domain(bd_idx)
            else:
                self.vppf.net_driver.delete_network(physnet, net_type, seg_id)

            self.etcd_client.delete(taas_path)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass


class TaasFlowAgentWatcher(etcdutils.EtcdChangeWatcher):
    """Monitor state changes on flows

    Flows are packet sources being mirrored.
    """
    path = 'taas_flow'

    def __init__(self, host, etcd_client_factory, vppf):
        self._node_key_space = LEADIN + '/nodes/%s/%s' % (host, self.path)
        self._state_key_space = LEADIN + \
            '/state_taas/%s/%s' % (host, self.path)
        self.etcd_client = etcd_client_factory.client()
        self.vppf = vppf
        self._host = host
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._node_key_space)
        etcd_helper.ensure_dir(self._state_key_space)
        self.iputils = ip_lib.IPWrapper()

        # ERSPan IP address/prefix len
        self.esp_src_cidr = cfg.CONF.ml2_vpp.esp_src_cidr
        if self.esp_src_cidr is not None and self.esp_src_cidr != '':
            (self.esp_src_addr,
             esp_plen) = self.esp_src_cidr.split('/')
        self.esp_plen = int(esp_plen)

        # Name of the ERspan physnet
        self.esp_physnet = cfg.CONF.ml2_vpp.esp_physnet

        super(TaasFlowAgentWatcher, self).__init__(self.etcd_client,
                                                   self.path,
                                                   self._node_key_space)

    def _ensure_ext_link(self):
        """Ensures that the EXT link interface is present and configured.

        The ext_link is used for ERPSAN_EXT mode to reach the external tap
        service.
        The physical interface of ext_link is specified by the paramter
        esp_phynet of the configuration. The address of ext_link is given by
        the parameter esp_src_cidr of the configuration.
        Returns:-
        The name and the software_if_index of the EXT link or None in case
        of error.
        """
        intf, if_physnet = self.vppf.get_if_for_physnet(self.esp_physnet)
        LOG.debug('Setting EXT attachment interface: %s',
                  intf)
        if if_physnet is None:
            LOG.error('Cannot create a EXT network because the esp_'
                      'physnet config value:%s is broken. Make sure this '
                      'value is set to a valid physnet name used as the '
                      'EXT interface',
                      self.esp_physnet)
            return
        self.vppf.vpp.ifup(if_physnet)
        LOG.debug('Configuring EXT ip address %s on '
                  'interface %s', self.esp_src_cidr, intf)
        physnet_ip_addrs = self.vppf.vpp.get_interface_ip_addresses(if_physnet)
        LOG.debug('Exising IP addresses %s', str(physnet_ip_addrs))
        if ip_interface((self.esp_src_addr, self.esp_plen)) \
           not in physnet_ip_addrs:
            self.vppf.vpp.set_interface_ip(
                if_physnet,
                ip_interface((self.esp_src_addr, self.esp_plen,))
                )
        return (intf, if_physnet)

    def _find_port_idx(self, port_id, host):
        port_path = (LEADIN + '/state/' + host + '/ports/' +
                     str(port_id))
        try:
            # TODO(ijw): shouldn't be reading the port info, or relying on
            # etcd's picture of the world.  This is in an internal
            # datastructure already.
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            port_idx = port_info['iface_idx']
        except etcd.EtcdKeyNotFound:
            port_idx = -1
        return port_idx

    def _create_vxlan_tunnel(self, dst_adr, vni):
        """Create a tunnel to a remote destination VTEP."""
        # TODO(ijw) this reads all VXLAN tunnels from VPP every time
        # and as such is not amazingly efficient.
        vxtuns = self.vppf.vpp.get_vxlan_tunnels()
        tidx = vxtuns.get((vni, ipaddr(dst_adr),))
        if tidx is not None:
            return tidx

        self.vppf.gpe.ensure_gpe_link()
        src_adr = self.vppf.gpe.gpe_underlay_addr
        idx = self.vppf.vpp.create_vxlan_tunnel(
            src_adr,
            dst_adr,
            vni)
        return idx

    def _delete_vxlan_tunnel(self, dst_adr, vni):
        """Remove a VXLAN tunnel from VPP."""
        self.vppf.gpe.ensure_gpe_link()
        src_adr = self.vppf.gpe.gpe_underlay_addr
        self.vppf.vpp.delete_vxlan_tunnel(
            src_adr,
            dst_adr,
            vni)

    def _create_erspan_tunnel(self, src_adr, dst_adr, session_id):
        """Create a tunnel to a remote destination VTEP."""
        if ip_network(src_adr).version == 6:
            is_ipv6 = 1
        else:
            is_ipv6 = 0
        if ip_network(dst_adr).version == 6:
            is_ipv6d = 1
        else:
            is_ipv6d = 0
        if is_ipv6 != is_ipv6d:
            LOG.error('Cannot create an erspan tunnel because the IP version'
                      ' of src_adr and dst_adr are different',
                      self.src_adr, self.dst_adr)
            return None
        esptuns = self.vppf.vpp.get_erspan_tunnels()
        tidx = esptuns.get((int(session_id), ipaddr(dst_adr)))
        if tidx is not None:
            return tidx

        idx = self.vppf.vpp.create_erspan_tunnel(
            src_adr,
            dst_adr,
            is_ipv6,
            int(session_id))
        return idx

    def _delete_erspan_tunnel(self, src_adr, dst_adr, session_id):
        """Remove a VXLAN tunnel from VPP."""
        if ip_network(src_adr).version == 6:
            is_ipv6 = 1
        else:
            is_ipv6 = 0
        self.vppf.vpp.delete_erspan_tunnel(
            src_adr,
            dst_adr,
            is_ipv6,
            int(session_id))

    def _get_remote_addr(self, port_mac):
        self.vppf.load_gpe_mappings()
        remote_ip = ''
        for mac_vni_tpl in self.vppf.gpe_map['remote_map'].keys():
            mac, vni = mac_vni_tpl
            if mac == port_mac:
                remote_ip = self.vppf.gpe_map['remote_map'][(mac, vni)]
        return remote_ip

    def _get_num_flow(self, tf_host, taas_id):
        """Get the number of open tap flows associated with a given taas_id"""
        num = 0
        watch_space = LEADIN + '/nodes/%s/taas_flow' % (tf_host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['taas_id'] == taas_id:
                    num = num + 1

        return num

    def added(self, key, value):
        """New TAP flow created."""
        flow_id = key
        data = jsonutils.loads(value)

        # Check Span direction
        direction = data['tap_flow']['direction']
        if direction == 'IN':
            direction = vpp_const.SPAN_RX
        elif direction == 'OUT':
            direction = vpp_const.SPAN_TX
        else:
            direction = vpp_const.SPAN_RX_TX

        # Check Destination type
        if 'dest_type' in data:
            dest_type = data['dest_type']
        else:
            dest_type = 'Port'

        if dest_type == 'ERSPAN_EXT' or dest_type == 'ERSPAN_INT':
            tap_srv_id = data['tap_flow']['tap_service_id']
            ts_host = ''
            if dest_type == 'ERSPAN_INT':
                ts_host = data['ts_host']
                ts_path = (LEADIN + '/state_taas/' + ts_host +
                           '/taas_service/' + tap_srv_id)
            else:
                ts_path = (LEADIN + '/global' +
                           '/taas_service/' + tap_srv_id)
            try:
                ts_info = jsonutils.loads(self.etcd_client.read(ts_path).value)
                if dest_type == 'ERSPAN_INT':
                    physnet = ts_info['service_bridge']['physnet']
                    esp_dst_addr = \
                        ts_info['ts']['tap_service']['erspan_dst_ip']
                else:
                    physnet = self.esp_physnet
                    esp_dst_addr = ts_info['tap_service']['erspan_dst_ip']
                network_type = 'vlan'
                esp_src_addr = self.esp_src_addr
                esp_session_id = data['tap_flow']['erspan_session_id']
                if ip_network(esp_dst_addr).version == 6:
                    esp_isv6 = 1
                else:
                    esp_isv6 = 0

                # Create the ERSpan tunnel
                tun_idx = self._create_erspan_tunnel(
                    esp_src_addr, esp_dst_addr, esp_session_id)

                tf_host = data['tf_host']
                source_port_idx = self._find_port_idx(
                    data['tap_flow']['source_port'], tf_host)

                # Mirror the src port to the ERSpan tunnel
                self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                    tun_idx,
                                                    direction)

                if dest_type == 'ERSPAN_EXT':
                    self._ensure_ext_link()
                    loop_idx = -1
                elif dest_type == 'ERSPAN_INT':
                    # Create or find the TF bridge
                    bridge_data = self.vppf.net_driver.ensure_network(
                        physnet,
                        network_type,
                        data['taas_id'])

                    # Connect the tunnel to the bridge
                    self.vppf.vpp.add_to_bridge(
                        bridge_data['bridge_domain_id'],
                        tun_idx)

                    # Create the loopback intf as BVI for TF bridge
                    loop_idx = self.vppf.vpp.get_bridge_bvi(
                        bridge_data['bridge_domain_id'])
                    if loop_idx is None:
                        loop_idx = self.vppf.vpp.create_loopback()
                        self.vppf.vpp.set_loopback_bridge_bvi(
                            loop_idx, bridge_data['bridge_domain_id'])
                        self.vppf.vpp.set_interface_vrf(loop_idx, 0, esp_isv6)
                        self.vppf.vpp.set_interface_ip(
                            loop_idx,
                            ip_interface((self.esp_src_addr, self.esp_plen,))
                        )
                        esp_inet = ip_interface((esp_dst_addr, self.esp_plen,))
                        esp_net = ("%s" % (esp_inet.network)).split('/')[0]
                        self.vppf.vpp.add_ip_route(
                            0, self.vppf._pack_address(esp_net),
                            self.esp_plen, None, loop_idx, esp_isv6, False)
                        self.vppf.vpp.ifup(loop_idx)

                # Activate the ERspan tunnel
                self.vppf.vpp.ifup(tun_idx)

                # Set the tap_flow state in etcd
                data = {"tf": data,
                        "dst_idx": tun_idx,
                        "port_idx": source_port_idx,
                        'span_mode': 3,  # ERSPAN
                        'dst_adr': esp_dst_addr,
                        'session_id': esp_session_id,
                        'loop_idx': loop_idx,
                        'physnet': physnet,
                        'ts_host': ts_host
                        }

                self.etcd_client.write(self._state_key_space +
                                       '/%s' % flow_id,
                                       jsonutils.dumps(data))

            except etcd.EtcdKeyNotFound:
                pass
        else:
            taas_id = data['taas_id']
            ts_host = data['ts_host']
            tf_host = data['tf_host']

            tap_srv_id = data['tap_flow']['tap_service_id']
            ts_path = (LEADIN + '/state_taas/' + ts_host +
                       '/taas_service/' + tap_srv_id)
            try:
                ts_info = jsonutils.loads(self.etcd_client.read(ts_path).value)
                network_type = ts_info['service_bridge']['network_type']
                physnet = ts_info['service_bridge']['physnet']

                if network_type != 'vxlan':
                    network_type = 'vlan'

                # Check if tapflow and tapservice are located in the same node
                # Local Span
                if ts_host == tf_host:
                    source_port_idx = self._find_port_idx(
                        data['tap_flow']['source_port'], tf_host)
                    srv_port_idx = ts_info['port']['iface_idx']
                    # Local Span
                    dst_idx = srv_port_idx
                    self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                        srv_port_idx,
                                                        direction)
                    # Set the tap_flow state in etcd
                    data = {"tf": data,
                            "port_idx": source_port_idx,
                            'dst_idx': dst_idx,
                            'span_mode': 0,  # Local
                            'tfn': True
                            }
                # Remote Span via vlan
                elif network_type == 'vlan':
                    if self._host == tf_host:
                        source_port_idx = self._find_port_idx(
                            data['tap_flow']['source_port'], tf_host)

                        # get/create a numbered bridge domain for the service

                        service_bridge = self.vppf.net_driver.ensure_network(
                            physnet, network_type, taas_id)
                        service_bridge_id = service_bridge['bridge_domain_id']
                        self.vppf.vpp.bridge_enable_flooding(service_bridge_id)

                        # Remote Span
                        srv_uplink_idx = service_bridge['if_uplink_idx']
                        dst_idx = srv_uplink_idx
                        self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                            srv_uplink_idx,
                                                            direction)

                        # Set the tap_flow state in etcd
                        data = {"tf": data,
                                "service_bridge": service_bridge,
                                "port_idx": source_port_idx,
                                'dst_idx': dst_idx,
                                'span_mode': 1,  # vlan
                                'tfn': True
                                }
                    else:
                        # Set the tap_flow state in etcd
                        data = {"tf": data,
                                'span_mode': 1,  # vlan
                                'tfn': False
                                }

                # Remote Span via vxlan
                else:
                    if self._host == tf_host:
                        dst_adr = self._get_remote_addr(data['ts_port_mac'])
                    else:
                        dst_adr = self._get_remote_addr(data['port_mac'])
                    source_port_idx = self._find_port_idx(
                        data['tap_flow']['source_port'], tf_host)
                    vni = taas_id
                    tun_idx = self._create_vxlan_tunnel(dst_adr, vni)
                    # source_port_idx = -1
                    if self._host == tf_host:
                        tfn = True
                        self.vppf.vpp.cross_connect(tun_idx, 0)
                        self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                            tun_idx,
                                                            direction)
                    else:
                        tfn = False
                        bd_idx = taas_id + 64000
                        self.vppf.vpp.add_to_bridge(bd_idx,
                                                    tun_idx)

                    self.vppf.vpp.ifup(tun_idx)
                    # Set the tap_flow state in etcd
                    data = {"tf": data,
                            "dst_idx": tun_idx,
                            "port_idx": source_port_idx,
                            'span_mode': 2,  # vxlan
                            'tfn': tfn,
                            'dst_adr': dst_adr,
                            'vni': vni
                            }

                self.etcd_client.write(self._state_key_space +
                                       '/%s' % flow_id,
                                       jsonutils.dumps(data))
            except etcd.EtcdKeyNotFound:
                pass

    def removed(self, key):
        # Removing key == desire to unbind
        flow_id = key
        try:
            taas_path = self._state_key_space + '/' + key
            tap_flow_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)

            span_mode = tap_flow_info['span_mode']
            if span_mode == 3:  # ERSPAN
                dest_type = tap_flow_info['tf']['dest_type']
                dst_idx = tap_flow_info['dst_idx']
                source_port_idx = tap_flow_info['port_idx']
                self.vppf.vpp.disable_port_mirroring(source_port_idx,
                                                     dst_idx)
                if dest_type == 'ERSPAN_INT':
                    self.vppf.vpp.delete_from_bridge(dst_idx)
                taas_id = tap_flow_info['tf']['taas_id']
                tf_host = tap_flow_info['tf']['tf_host']
                ts_host = tap_flow_info['ts_host']
                session_id = tap_flow_info['session_id']
                dst_addr = tap_flow_info['dst_adr']
                src_addr = self.esp_src_addr
                self._delete_erspan_tunnel(src_addr, dst_addr, session_id)
                if dest_type == 'ERSPAN_INT':
                    tf_nb = self._get_num_flow(tf_host, taas_id)
                    if tf_nb == 0:
                        loop_idx = tap_flow_info['loop_idx']
                        self.vppf.vpp.delete_loopback(loop_idx)
                        if tf_host != ts_host:
                            physnet = tap_flow_info['physnet']
                            net_type = 'vlan'
                            seg_id = taas_id
                            self.vppf.net_driver.delete_network(
                                physnet, net_type, seg_id)
            else:
                tfn = tap_flow_info['tfn']
                if tfn:
                    dst_idx = tap_flow_info['dst_idx']
                    source_port_idx = tap_flow_info['port_idx']
                    self.vppf.vpp.disable_port_mirroring(source_port_idx,
                                                         dst_idx)

                if span_mode == 1 and tfn:
                    service_bridge = tap_flow_info['service_bridge']

                    physnet = service_bridge['physnet']
                    net_type = service_bridge['network_type']
                    seg_id = service_bridge['segmentation_id']
                    # check if the local service bridge needs to be removed
                    spans = self.vppf.vpp.dump_port_mirroring()
                    cnt = 0
                    for sp in spans:
                        if sp.sw_if_index_to == dst_idx:
                            cnt += 1
                    if cnt == 0:
                        self.vppf.net_driver.delete_network(
                            physnet, net_type, seg_id)

                elif span_mode == 2:  # vxlan
                    taas_id = tap_flow_info['tf']['taas_id']
                    tf_host = tap_flow_info['tf']['tf_host']
                    tf_nb = self._get_num_flow(tf_host, taas_id)
                    if tf_nb == 0:
                        if tfn is False:
                            self.vppf.vpp.delete_from_bridge(
                                tap_flow_info['dst_idx'])
                        vni = tap_flow_info['vni']
                        dst_adr = tap_flow_info['dst_adr']
                        self._delete_vxlan_tunnel(dst_adr, vni)

            self.etcd_client.delete(self._state_key_space +
                                    '/%s' % flow_id)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass


# This watcher is needed to manage the out of order etcd messages
# (e.g when the agent is restarted)
class TaasPortAgentWatcher(etcdutils.EtcdChangeWatcher):
    path = 'taas_port'

    def __init__(self, host, etcd_client_factory, tsw, tfw):
        self._port_key_space = LEADIN + '/state/%s/ports' % (host)
        self.etcd_client = etcd_client_factory.client()
        self._host = host
        self._tsw = tsw
        self._tfw = tfw
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._port_key_space)
        super(TaasPortAgentWatcher, self).__init__(self.etcd_client,
                                                   self.path,
                                                   self._port_key_space)

    def _trigger_tap_service(self, key, value):
        """Manage the creation of the tap services when agent is restarted"""
        self._tsw.added(key, value)

    def _trigger_tap_flow(self, key, value):
        """Manage the creation of the tap flows when agent is restarted"""
        self._tfw.added(key, value)

    def _check_etcd_taas(self, port_id):
        """Check pending taas creation

        Wen the agent is restarted, the requests of port creation and
        tap creation will occur in a random order. This function is used
        to check if there is a pending tap service or flow creation for the
        port that has just been created. It is required to properly manage
        the case when the port creation request is received after the tap
        creation request.
        """
        watch_space = LEADIN + '/nodes/%s/taas_service' % (self._host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        tap_srv_lst = list()
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['tap_service']['port_id'] == port_id:
                    tap_srv_lst.append(f.key)
                    self._trigger_tap_service(f.key, f.value)

        watch_space = LEADIN + '/nodes/%s/taas_flow' % (self._host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['tap_flow']['source_port'] == port_id:
                    self._trigger_tap_flow(f.key, f.value)
                elif data['tap_flow']['tap_service_id'] in tap_srv_lst:
                    self._trigger_tap_flow(f.key, f.value)

    def added(self, key, value):
        self._check_etcd_taas(key)

    def removed(self, key):
        pass


class TaasVPPAgentExtension(VPPAgentExtensionBase):
    def initialize(self, manager):
        pass

    def run(self, host, client_factory, vpp_forwarder, gthread_pool):
        self.taas_service_watcher = TaasServiceAgentWatcher(host,
                                                            client_factory,
                                                            vpp_forwarder)
        self.taas_flow_watcher = TaasFlowAgentWatcher(host,
                                                      client_factory,
                                                      vpp_forwarder)
        self.taas_port_watcher = TaasPortAgentWatcher(
            host,
            client_factory,
            self.taas_service_watcher,
            self.taas_flow_watcher)
        gthread_pool.spawn(self.taas_service_watcher.watch_forever)
        gthread_pool.spawn(self.taas_flow_watcher.watch_forever)
        gthread_pool.spawn(self.taas_port_watcher.watch_forever)
