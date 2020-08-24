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


from __future__ import absolute_import
import collections
import fnmatch
import grp
import ipaddress
# logging is included purely for typechecks and pep8 objects to its inclusion
import logging  # noqa
from networking_vpp import constants as nvpp_const
from networking_vpp import vpp_constants as vpp_const
import os
# Pep8 check fails, if json is used instead of jsonutils
from oslo_serialization import jsonutils
import pkgutil
import pwd
import sys
# typing is included purely for typechecks and pep8 objects to its inclusion
from typing import List, Dict, Optional, Set, Tuple, Iterator  # noqa
import vpp_papi  # type: ignore
from vpp_papi import VppEnum


def mac_to_bytes(mac):
    # type: (str) -> bytes
    # py3 note:
    # TODO(onong): PAPI has introduced a new macaddress object which seemingly
    # takes care of conversion to/from MAC addr to string.
    # TODO(onong): move to common file in phase 2
    return bytes.fromhex(mac.replace(':', ''))


def fix_string(s):
    # type: (bytes) -> str
    # py3 note:
    # This function chops off any trailing NUL chars/bytes from strings that
    # we get from VPP. Now, in case of py2, str and bytes are the same but
    # there's a strict distinction between the two in py3. The code ensures
    # that within the ML2 agent we follow the dictum of always dealing with
    # strings and this function acts as the boundary where the conversion to
    # string happens.
    #
    # TODO(onong): watch out for the upcoming PAPI change which introduces a
    # string type for printable strings, so no longer the need for the funny
    # chopping off of 0's at the end. But this function will still act as the
    # boundary at which input is converted to string type.
    #
    # TODO(onong): move to common file in phase 2
    # This consistently returns a string in py2 and 3, and since we know
    # the input is binary ASCII we can safely make the cast in py2.
    #
    #
    # Note(onong): VPP 19.08.1 onwards interface_name and tag fields are type
    # "string" instead of the earlier "u8". Alas, this change happened only
    # for the sw_interface_dump/sw_interface_details API pair which implies
    # fix_string is still needed in the other places it is in use currently.
    # Once the other APIs too change to "string" type, fix_string may/will no
    # longer be needed.
    return str(s.decode('ascii').rstrip('\0'))


def bytes_to_mac(mbytes):
    # type: (str) -> str
    return ':'.join(['%02x' % ord(x) for x in mbytes[:6]])


def bytes_to_ip(ip_bytes, is_ipv6):
    # type: (bytes, bool) -> str
    if is_ipv6:
        return str(ipaddress.ip_address(ip_bytes))
    else:
        return str(ipaddress.ip_address(ip_bytes[:4]))


def singleton(cls):
    instances = {}

    def getinstance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return getinstance


def get_api_messages():
    # Returns a tuple. (List of PAPI_calls+CRCs , List of whitelisted APIs)
    manifest, whitelist = [], []
    # Get the data files regardless of where or how the package has been
    # installed
    try:
        manifest_data = pkgutil.get_data('networking_vpp',
                                         nvpp_const.API_MANIFEST_FILE)
        whitelist_data = pkgutil.get_data('networking_vpp',
                                          nvpp_const.API_WHITELIST_FILE)
        manifest, whitelist = (jsonutils.loads(manifest_data),
                               jsonutils.loads(whitelist_data))
    except Exception:
        # If the files cannot be located or loaded, empty data will be
        # returned, which will cause the agent to log an error and exit
        pass
    return (manifest, whitelist)


@singleton
class VPPInterface(object):
    """The interface to VPP (through PAPI - VPP Python API)

       This class encapsulates everything that has got to do with the agent's
       interaction with VPP via PAPI.
    """
    def __init__(
        self,
        log,  # type: logging.Logger
        vpp_cmd_queue_len=None,  # type: Optional[int]
        ):
        self.LOG = log
        jsonfiles = []
        for root, dirnames, filenames in os.walk('/usr/share/vpp/api/'):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        # NB(onong):
        # The async_thread param tells PAPI whether to spawn the thread
        # which invokes the user registered callback and it is set to True by
        # default. Since we use synchronous mode for the API calls we should
        # be setting it to False.
        self._vpp = vpp_papi.VPP(jsonfiles, async_thread=False)

        args = {}
        if vpp_cmd_queue_len is not None:
            args['rx_qlen'] = vpp_cmd_queue_len

        self._vpp.connect("python-VPPInterface", **args)
        # VPP API manifest and API whitelist
        message_table, self.api_whitelist = get_api_messages()
        if not message_table or not self.api_whitelist:
            self.LOG.error("Unable to load VPP API files: %s, %s",
                           nvpp_const.API_MANIFEST_FILE,
                           nvpp_const.API_WHITELIST_FILE)
            # The vpp-agent requires both the API manifest and whitelist files
            # to start
            sys.exit(1)
        try:
            self.LOG.debug("Validating VPP API messages")
            api_changes = self._vpp.validate_message_table(message_table)
            if api_changes:
                # All changed VPP APIs
                updated = ['_'.join(api.split('_')[:-1])
                           for api in api_changes]
                # Changed VPP whitelisted APIs
                changed_apis = []
                # Check if any of the whitelisted APIs have changed
                for api in self.api_whitelist:
                    if api in updated:
                        changed_apis.append(api)
                if changed_apis:
                    self.LOG.critical("VPP API signature mismatch: %s",
                                      changed_apis)
                else:
                    self.LOG.info("Successfully validated VPP API CRCs")
        except AttributeError:
            # message table validation is unsupported by VPP
            self.LOG.critical("VPP does not support message "
                              "CRC validation")
            sys.exit(1)

    def call_vpp(self, func, *args, **kwargs):
        """Wrapper which invokes the VPP APIs through PAPI """
        # Disabling to prevent message debug flooding
        # self.LOG.debug('VPP: %s(%s, %s): ',
        # func, ', '.join(args), str(kwargs))

        # VPP version 18.04 onwards, the VPP APIs are attributes of the "api"
        # object within the VPPInterface object whereas before 18.04, VPP APIs
        # are attributes of the VPPInterface object itself. The following
        # ensures that we work with VPP version 18.04 and onwards while still
        # being backwards compatible.
        try:
            func_call = getattr(self._vpp.api, func)
        except AttributeError:
            func_call = getattr(self._vpp, func)
            # There should not be a need for the debug logs but just in case
            # there is just uncomment them below:
            # self.LOG.debug("Switching to old way of invoking VPP APIs")
            # self.LOG.debug(e)

        # Ensure that the API is whitelisted, if not don't proceed
        if func not in self.api_whitelist:
            self.LOG.critical('VPP func_call %s is not whitelisted in %s',
                              func, nvpp_const.API_WHITELIST_FILE)
            sys.exit(1)

        try:
            t = func_call(*args, **kwargs)
        except IOError as e:
            self.LOG.exception(e)

            # We cannot guarantee the state of VPP at this point
            # and our best option is to exit.
            sys.exit(1)

        # Turning this on produces a continuous sequence of debug messages
        # self.LOG.debug('VPP: %s returned %s', func, str(t))

        # Many - but not all - return values have a 'retval'
        # flag that we can make use of to confirm success.
        # This isn't possible with multivalue calls, though.
        if getattr(t, 'retval', 0) != 0:
            self.LOG.critical('Failed VPP call to %(func)s(%(f_args)s, '
                              '%(f_kwargs)s): retval is %(rv)s',
                              {'func': func,
                               'f_args': ','.join(args),
                               'f_kwargs': kwargs,
                               'rv': t.retval})
            sys.exit(1)

        return t

    def get_version(self):
        # type: () -> str
        t = self.call_vpp('show_version')

        return t.version

    def semver(self):
        # type: () -> Tuple[int, int, bool]
        """Return the 'semantic' version components of a VPP version"""

        # version string is in the form yy.mm{cruft}*
        # the cruft is there if it's an interstitial version during
        # the dev cycle, and note that these versions may have a
        # changed and unpredictable API.
        version_string = self.get_version()
        yy = int(version_string[:2])
        mm = int(version_string[3:5])
        plus = len(version_string[5:]) != 0

        return (yy, mm, plus)

    def ver_ge(self, tyy, tmm):
        # type: (int, int) -> bool
        (yy, mm, plus) = self.semver()
        if tyy < yy:
            return True
        elif tyy == yy and tmm <= mm:
            return True
        else:
            return False

    def get_interfaces(self):
        # type: () -> Iterator[dict]
        t = self.call_vpp('sw_interface_dump')

        for iface in t:
            # Note(onong): VPP 19.08.1 onwards interface_name and tag fields
            # are type "string" instead of the earlier "u8". In python3, PAPI
            # converts "string" type to python str whereas in python2 it
            # converts to Unicode. So, no need for fix_string on interface_name
            # and tag fields anymore.
            #
            # NB: PLEASE READ THIS: the current usage of interface_name and tag
            # in the rest of the code does not pose any problems in python2 but
            # for any new usage case please make sure to understand that the
            # said fields are "Unicode" and not "bytes/str" in python2 from VPP
            # 19.08.1 onwards.
            yield {'name': iface.interface_name,
                   'tag': iface.tag,
                   'mac': iface.l2_address,
                   'sw_if_idx': iface.sw_if_index,
                   'sup_sw_if_idx': iface.sup_sw_if_index
                   }

    def get_ifidx_by_name(self, name):
        # type: (str) -> Optional[int]
        for iface in self.get_interfaces():
            if iface['name'] == name:
                return iface['sw_if_idx']
        return None

    def get_ifidx_mac_address(self, ifidx):
        # type: (int) -> Optional[bytes]

        for iface in self.get_interfaces():
            if iface['sw_if_idx'] == ifidx:
                return iface['mac']
        return None

    def get_ifidx_by_tag(self, tag):
        # type: (str) -> Optional[int]
        for iface in self.get_interfaces():
            if iface['tag'] == tag:
                return iface['sw_if_idx']
        return None

    def set_interface_tag(self, if_idx, tag):
        # type: (int, str) -> None
        """Define interface tag field.

        VPP papi does not allow to set interface tag
        on interface creation for subinterface or loopback).
        """
        # TODO(ijw): this is a race condition - we should create the
        # interface with a tag.
        self.call_vpp('sw_interface_tag_add_del',
                      is_add=1,
                      sw_if_index=if_idx,
                      # Note(onong): VPP 19.08.1 onwards, the 'tag' field is
                      # of type 'string' and PAPI cribs if it is passed the old
                      # bytes/str type in python3.
                      #
                      # What about python2?
                      # Well, python2 is pretty cool about the intermingling of
                      # bytes/str/unicode and hence things work fine.
                      tag=tag)

    ########################################

    def create_tap(self, ifname, mac=None, tag=""):
        # type: (str, str, str) -> int
        if mac is not None:
            mac_bytes = mac_to_bytes(mac)
            use_random_mac = False
        else:
            mac_bytes = mac_to_bytes('00:00:00:00:00:00')
            use_random_mac = True

        # Note(onong): In VPP 20.01, the following API changes have happened:
        #      host_ip4_addr_set --> host_ip4_prefix_set
        #      host_ip6_addr_set --> host_ip6_prefix_set
        #      type of host_if_name changed from u8 to string
        #      type of tag changed from u8 to string
        t = self.call_vpp('tap_create_v2',
                          use_random_mac=use_random_mac,
                          mac_address=mac_bytes,
                          host_if_name_set=True,
                          host_if_name=ifname,
                          id=0xffffffff,  # choose ifidx automatically
                          host_ip4_prefix_set=False,
                          host_ip6_prefix_set=False,
                          host_bridge_set=False,
                          host_namespace_set=False,
                          host_mac_addr_set=False,
                          tx_ring_sz=1024,
                          rx_ring_sz=1024,
                          tag=tag)

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        # type: (int) -> None
        self.call_vpp('tap_delete_v2',
                      sw_if_index=idx)

    #############################

    def create_vhostuser(self, ifpath, mac, tag,
                         qemu_user=None, qemu_group=None, is_server=False):
        # type: (str, str, str, Optional[str], Optional[str], bool) -> int

        # Note(onong): In VPP 20.01, the following API changes have happened:
        #      type of sock_filename changed from u8 to string
        #      type of tag changed from u8 to string
        t = self.call_vpp('create_vhost_user_if',
                          is_server=is_server,
                          sock_filename=ifpath,
                          renumber=False,
                          custom_dev_instance=0,
                          use_custom_mac=True,
                          mac_address=mac_to_bytes(mac),
                          tag=tag)

        if is_server and qemu_user is not None and qemu_group is not None:
            # The permission that qemu runs as.
            uid = pwd.getpwnam(qemu_user).pw_uid
            gid = grp.getgrnam(qemu_group).gr_gid
            os.chown(ifpath, uid, gid)
            os.chmod(ifpath, 0o770)

        if t.sw_if_index >= 0:
            # TODO(ijw): This is a temporary fix to a 17.01 bug where new
            # interfaces sometimes come up with VLAN rewrites set on them.
            # It breaks atomicity of this call and it should be removed.
            self.disable_vlan_rewrite(t.sw_if_index)

        return t.sw_if_index

    def delete_vhostuser(self, idx):
        # type: (int) -> None
        self.call_vpp('delete_vhost_user_if',
                      sw_if_index=idx)

    def get_vhostusers(self):
        # type: () -> Iterator[Tuple[str, int]]
        t = self.call_vpp('sw_interface_vhost_user_dump')

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    # def is_vhostuser(self, iface_idx):
    #     # type: (int) -> bool
    #     for vhost in self.get_vhostusers():
    #         if vhost.sw_if_index == iface_idx:
    #             return True
    #     return False

    ########################################

    def create_bridge_domain(self, id, mac_age):
        # type: (int, int) -> None
        self.call_vpp(
            'bridge_domain_add_del',
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            mac_age=mac_age,  # set bridge domain MAC aging TTL
            is_add=True  # is an add
        )

    def delete_bridge_domain(self, id):
        # type: (int) -> None
        self.call_vpp(
            'bridge_domain_add_del',
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            is_add=False  # is a delete
        )

    def get_bridge_domains(self):
        # type: () -> Set[int]
        t = self.call_vpp('bridge_domain_dump', bd_id=0xffffffff)
        return set([bd.bd_id for bd in t])

    def bridge_set_flags(self, bridge_domain_id, flags):
        # type: (int, int) -> None
        """Reset and set flags for a bridge domain.

        TODO(ijw): NOT ATOMIC
        """
        self.call_vpp('bridge_flags',
                      bd_id=bridge_domain_id,
                      is_set=False,
                      flags=(vpp_const.L2_LEARN | vpp_const.L2_FWD |
                             vpp_const.L2_FLOOD |
                             vpp_const.L2_UU_FLOOD |
                             vpp_const.L2_ARP_TERM))
        self.call_vpp('bridge_flags',
                      bd_id=bridge_domain_id,
                      is_set=True, flags=flags)

    def bridge_enable_flooding(self, bridge_domain_id):
        # type: (int) -> None
        self.LOG.debug("Enable flooding (disable mac learning) for bridge %d",
                       bridge_domain_id)
        self.bridge_set_flags(bridge_domain_id, vpp_const.L2_UU_FLOOD)

    def get_ifaces_in_bridge_domains(self):
        # type: () -> Dict[int, List[int]]
        """Read current bridge configuration in VPP.

        - returns a dict
          key: bridge id
          values: array of connected sw_if_index
        """
        t = self.call_vpp('bridge_domain_dump',
                          bd_id=0xffffffff)

        # With the old API, this method returns an array containing
        # 2 types of object:
        # - bridge_domain_details
        # - bridge_domain_sw_if_details
        # With the new API, this method returns just
        # bridge_domain_details, but that
        # object now has an array of details on it.

        bridges = collections.defaultdict(list)  # type: Dict[int, List[int]]
        for bd_info in t:
            if bd_info.__class__.__name__.endswith('sw_if_details'):
                # with the old semantics, add found indexes.
                # For new ones, no objects of this type are returned
                bridges[bd_info.bd_id].append(bd_info.sw_if_index)
            else:
                # Deal with new API semantics, and create an empty array
                # with the old
                bridges[bd_info.bd_id] = [
                    x.sw_if_index
                    for x in getattr(bd_info, 'sw_if_details', [])]
        return bridges

    def get_ifaces_in_bridge_domain(self, bd_id):
        # type: (int) -> List[int]
        return self.get_ifaces_in_bridge_domains().get(bd_id, [])

    ########################################

    def add_to_bridge(self, bridx, *ifidxes):
        # type: (int, *int) -> None
        for ifidx in ifidxes:
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=ifidx, bd_id=bridx,
                port_type=vpp_const.L2_API_PORT_TYPE_NORMAL,  # 18.10+
                shg=0,              # shared horizon group
                enable=True)        # enable bridge mode

    def delete_from_bridge(self, *ifidxes):
        # type: (*int) -> None
        for ifidx in ifidxes:
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=ifidx,
                bd_id=0,            # no bridge id is necessary
                port_type=vpp_const.L2_API_PORT_TYPE_NORMAL,  # 18.10+
                shg=0,              # shared horizon group
                enable=False)       # disable bridge mode (sets l3 mode)

    def set_loopback_bridge_bvi(self, loopback, bridge_id):
        # type: (int, int) -> None
        # Sets the specified loopback interface to act as  the BVI
        # for the bridge. This interface will act as a gateway and
        # terminate the VLAN.
        self.call_vpp(
            'sw_interface_set_l2_bridge',
            rx_sw_if_index=loopback,
            bd_id=bridge_id,
            shg=0,
            port_type=vpp_const.L2_API_PORT_TYPE_BVI,  # 18.10+
            enable=True)

    def get_bridge_bvi(self, bd_id):
        # type: (int) -> Optional[int]
        # Returns a BVI interface index for the specified bridge id
        br_details = self.call_vpp('bridge_domain_dump', bd_id=bd_id)
        if (br_details and br_details[0].bvi_sw_if_index and
                int(br_details[0].bvi_sw_if_index) != vpp_const.NO_BVI_SET):
            return br_details[0].bvi_sw_if_index

        return None

    ########################################

    def create_vlan_subif(self, if_id, vlan_tag, exact_match=0):
        # type: (int, int, int) -> int
        flags = VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_ONE_TAG
        if exact_match:
            flags |= VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH

        t = self.call_vpp('create_subif',
                          sw_if_index=if_id,
                          sub_id=vlan_tag,
                          outer_vlan_id=vlan_tag,
                          sub_if_flags=flags)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def get_vlan_subif(self, if_name, seg_id):
        # type: (str, int) -> Optional[int]
        # We know how VPP makes names up so we can do this
        return self.get_ifidx_by_name('%s.%s' % (if_name, seg_id))

    def delete_vlan_subif(self, sw_if_index):
        # type: (int) -> None
        self.call_vpp('delete_subif',
                      sw_if_index=sw_if_index)

    ########################################

    def acl_add_replace(self, acl_index, tag, rules):
        # type: (int, str, List[dict]) -> int
        t = self.call_vpp('acl_add_replace',
                          acl_index=acl_index,
                          tag=tag,
                          r=rules,
                          count=len(rules))
        return t.acl_index

    def set_acl_list_on_interface(self, sw_if_index, input_acls, output_acls):
        # type: (int, List[int], List[int]) -> None
        self.call_vpp('acl_interface_set_acl_list',
                      sw_if_index=sw_if_index,
                      count=len(input_acls) + len(output_acls),
                      n_input=len(input_acls),
                      acls=input_acls + output_acls)

    def delete_acl_list_on_interface(self, sw_if_index):
        self.call_vpp('acl_interface_set_acl_list',
                      sw_if_index=sw_if_index,
                      count=0,
                      n_input=0,
                      acls=[])

    def get_interface_acls(self, sw_if_index):
        t = self.call_vpp('acl_interface_list_dump',
                          sw_if_index=sw_if_index)
        # We're dumping one interface
        t = t[0]
        return t.acls[:t.n_input], t.acls[t.n_input:]

    def acl_delete(self, acl_index):
        self.call_vpp('acl_del',
                      acl_index=acl_index)

    def get_acl_tags(self):
        t = self.call_vpp('acl_dump', acl_index=0xffffffff)
        for acl in t:
            if hasattr(acl, 'acl_index'):
                yield (acl.acl_index, acl.tag)

    ########################################

    def macip_acl_add(self, rules, count):
        t = self.call_vpp('macip_acl_add',
                          count=count,
                          r=rules)
        return t.acl_index

    def set_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.call_vpp('macip_acl_interface_add_del',
                      is_add=True,
                      sw_if_index=sw_if_index,
                      acl_index=acl_index)

    def delete_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.call_vpp('macip_acl_interface_add_del',
                      is_add=False,  # delete
                      sw_if_index=sw_if_index,
                      acl_index=acl_index)

    def delete_macip_acl(self, acl_index):
        self.call_vpp('macip_acl_del',
                      acl_index=acl_index)

    def get_macip_acl_dump(self):
        t = self.call_vpp('macip_acl_interface_get')
        return t

    ########################################

    def set_vlan_remove(self, if_id):
        self.set_vlan_tag_rewrite(if_id, vpp_const.L2_VTR_POP_1, 0, 0, 0)

    def disable_vlan_rewrite(self, if_id):
        self.set_vlan_tag_rewrite(if_id, vpp_const.L2_VTR_DISABLED, 0, 0, 0)

    def set_vlan_tag_rewrite(self, if_id, vtr_op, push_dot1q, tag1, tag2):
        t = self.call_vpp('l2_interface_vlan_tag_rewrite',
                          sw_if_index=if_id,
                          vtr_op=vtr_op,
                          push_dot1q=push_dot1q,
                          tag1=tag1,
                          tag2=tag2)
        self.LOG.info("Set subinterface vlan tag pop response: %s",
                      str(t))

    ########################################

    def ifup(self, *ifidxes):
        """Bring a list of interfaces up

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            # Note(onong): VPP 20.01 onwards, admin_up_down field is replaced
            # by 'flags' which is of type vl_api_if_status_flags_t
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx, flags=vpp_const.IF_ADMIN_UP)

    def ifdown(self, *ifidxes):
        """Bring a list of interfaces down

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            # Note(onong): VPP 20.01 onwards, admin_up_down field is replaced
            # by 'flags' which is of type vl_api_if_status_flags_t
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx, flags=vpp_const.IF_ADMIN_DOWN)

    ########################################

    def create_loopback(self, mac_address=None):
        # Create a loopback interface to act as a BVI
        if mac_address:
            mac_address = mac_to_bytes(mac_address)
            loop = self.call_vpp('create_loopback', mac_address=mac_address)
        else:
            # We'll let VPP decide the mac-address
            loop = self.call_vpp('create_loopback')
        self.ifdown(loop.sw_if_index)

        return loop.sw_if_index

    def delete_loopback(self, loopback):
        # Delete a loopback interface, this also removes it automatically
        # from the bridge that it was set as the BVI for.
        self.call_vpp('delete_loopback', sw_if_index=loopback)

    ########################################

    def set_interface_vrf(self, if_idx, vrf_id, is_ipv6=False):
        # Set the interface's VRF to the routers's table id
        # allocated by neutron. If the VRF table does not exist, create it.
        table = {'table_id': vrf_id, 'is_ip6': is_ipv6}
        self.call_vpp('ip_table_add_del', table=table, is_add=True)
        self.call_vpp('sw_interface_set_table', sw_if_index=if_idx,
                      vrf_id=vrf_id, is_ipv6=is_ipv6)

    def get_interface_vrf(self, if_idx):
        # Get the interface VRF
        return self.call_vpp('sw_interface_get_table',
                             sw_if_index=if_idx).vrf_id

    def set_interface_ip(self, if_idx, ip, prefixlen):
        # Set the interface IP address, usually the subnet's
        # gateway IP.
        #
        # Note(onong): VPP 20.01 onwards, the ip address needs to be passed as
        # the new vl_api_address_with_prefix_t type which maps to the python
        # IPv4/IPv6Interface object in PAPI.
        prefix = ip + "/" + str(prefixlen)
        prefix = ipaddress.ip_interface(prefix)
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=if_idx, is_add=True,
                      del_all=False, prefix=prefix)

    def del_interface_ip(self, if_idx, ip, prefixlen):
        # Delete an ip address from the specified interface
        #
        # Note(onong): VPP 20.01 onwards, the ip address needs to be passed as
        # the new vl_api_address_with_prefix_t type which maps to the python
        # IPv4/IPv6Interface object in PAPI.
        prefix = ip + "/" + str(prefixlen)
        prefix = ipaddress.ip_interface(prefix)
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=if_idx, is_add=False,
                      del_all=False, prefix=prefix)

    def encode_route_path_labels(self):
        """Fill up/initialize the route's path label stack.

        In VPP 19.08, ip_add_del_route has been replaced by
        ip_route_add_del and the following is required otherwise the
        api throws an error.
        """
        label_stack = {'is_uniform': 0,
                       'label': 0,
                       'ttl': 0,
                       'exp': 0}
        label_stack_list = []
        for i in range(16):
            label_stack_list.append(label_stack)

        return label_stack_list

    def encode_route_path(self, vrf, is_local, is_ipv6, next_hop_address=None,
                          next_hop_sw_if_index=None):
        """Fill up/initialize the route's path.

        In VPP 19.08, ip_add_del_route has been replaced by
        ip_route_add_del and the route's path component is now a bona-fide
        type of its own, namely, vl_api_fib_path_t, and it has the following
        fields:

            {'weight': 1,
             'preference': 0,
             'table_id': self.nh_table_id,
             'nh': self.nh.encode(),
             'next_hop_id': self.next_hop_id,
             'sw_if_index': self.nh_itf,
             'rpf_id': self.rpf_id,
             'proto': self.proto,
             'type': self.type,
             'flags': self.flags,
             'n_labels': len(self.nh_labels),
             'label_stack': self.encode_labels()}
        """
        label_stack_list = self.encode_route_path_labels()
        path = {'table_id': vrf,
                # Note(onong): if we ever need the MPLS labels then fill
                # 'label_stack_list' with whatever values and uncomment the
                # following:
                # 'n_labels': len(label_stack_list),
                #
                # For our current usage, we need to pass 'n_labels=0' otherwise
                # routes are not set.
                'n_labels': 0,
                'label_stack': label_stack_list}

        # Type of route = local/normal
        if is_local:
            path['type'] = vpp_const.ROUTE_LOCAL
        else:
            path['type'] = vpp_const.ROUTE_NORMAL

        # IPv4/IPv6
        if is_ipv6:
            path['proto'] = vpp_const.PROTO_IPV6
        else:
            path['proto'] = vpp_const.PROTO_IPV4

        # Is there a next hop address?
        if next_hop_address:
            address = ipaddress.ip_address(
                bytes_to_ip(next_hop_address, is_ipv6))
            if not is_ipv6:
                path['nh'] = {'address': {'ip4': address}}
            else:
                path['nh'] = {'address': {'ip6': address}}

        # Is there a next hop intf index?
        if next_hop_sw_if_index:
            path['sw_if_index'] = next_hop_sw_if_index

        return path

    def encode_route(self, vrf, prefix, paths):
        """Fill up/initialize the route data structure.

        In VPP 19.08, ip_add_del_route has been replaced by
        ip_route_add_del and route is now a bona-fide type of its own,
        namely, vl_api_ip_route_t, and is now a field in the object returned
        in ip_route_details. In addition, the route prefix too is now returned
        as the new vl_api_prefix_t type which maps to IPv4Network/IPv6Network
        type in Python.

        typedef ip_route
        {
            u32 table_id;
            u32 stats_index;
            vl_api_prefix_t prefix;
            u8 n_paths;
            vl_api_fib_path_t paths[n_paths];
        };
        """
        route = {'table_id': vrf,
                 'prefix': prefix,
                 'n_paths': len(paths),
                 'paths': paths}
        return route

    def add_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                     next_hop_sw_if_index, is_ipv6=False, is_local=False):
        """Adds an IP route in the VRF or exports it from another VRF.

        Checks to see if a matching route is already present in the VRF.
        If not, the route is added or exported.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address. To export a
        route from another VRF, the next_hop_addesss is set to None and the
        next_hop_sw_if_index of the interface in the target VRF is provided.
        If is_local is True, a local route is added in the specified VRF.
        """
        if not self.route_in_vrf(vrf, ip_address, prefixlen,
                                 next_hop_address, next_hop_sw_if_index,
                                 is_ipv6, is_local):
            ip = ipaddress.ip_address(bytes_to_ip(ip_address, is_ipv6))
            # Note(onong): VPP 19.08 onwards, the destination needs to be in
            # the form of network/prefix, ie, of type ipaddress.IPv4Network
            prefix = ipaddress.ip_network(ip.exploded + "/" + str(prefixlen))

            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(
                    bytes_to_ip(next_hop_address, is_ipv6))

            if is_local:
                self.LOG.debug('Adding a local route %s/%s in router vrf:%s',
                               ip, prefixlen, vrf)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local,
                             is_ipv6))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=1, is_multipath=0,
                              route=route)
            elif next_hop_address is not None:
                self.LOG.debug('Adding route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local, is_ipv6,
                             next_hop_address=next_hop_address,
                             next_hop_sw_if_index=next_hop_sw_if_index))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=1, is_multipath=0,
                              route=route)
            elif next_hop_sw_if_index:
                self.LOG.debug('Exporting route %s/%s from vrf:%s to '
                               'next_hop_swif_idx: %s',
                               ip, prefixlen, vrf, next_hop_sw_if_index)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local, is_ipv6,
                             next_hop_sw_if_index=next_hop_sw_if_index))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=1, is_multipath=0,
                              route=route)

    def delete_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                        next_hop_sw_if_index, is_ipv6=False, is_local=False):
        """Deleted an IP route in the VRF.

        Checks to see if a matching route is present in the VRF.
        If present, the route is deleted.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address.
        """
        if self.route_in_vrf(vrf, ip_address, prefixlen,
                             next_hop_address, next_hop_sw_if_index,
                             is_ipv6, is_local):
            ip = ipaddress.ip_address(
                bytes_to_ip(ip_address, is_ipv6))
            # Note(onong): VPP 19.08 onwards, the destination needs to be in
            # the form of network/prefix, ie, of type ipaddress.IPv4Network
            prefix = ipaddress.ip_network(ip.exploded + "/" + str(prefixlen))

            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(
                    bytes_to_ip(next_hop_address, is_ipv6))

            if is_local:
                self.LOG.debug('Deleting a local route %s/%s in router vrf:%s',
                               ip, prefixlen, vrf)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local,
                             is_ipv6))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=0, is_multipath=0,
                              route=route)
            elif next_hop_address is not None:
                self.LOG.debug('Deleting route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local, is_ipv6,
                             next_hop_address=next_hop_address,
                             next_hop_sw_if_index=next_hop_sw_if_index))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=0, is_multipath=0,
                              route=route)
            elif next_hop_sw_if_index:
                self.LOG.debug('Deleting exported net:%s/%s in router '
                               'vrf:%s to next_hop_swif_idx: %s',
                               ip, prefixlen, vrf, next_hop_sw_if_index)
                paths = []
                paths.append(self.encode_route_path(vrf, is_local, is_ipv6,
                             next_hop_sw_if_index=next_hop_sw_if_index))
                route = self.encode_route(vrf, prefix, paths)
                self.call_vpp('ip_route_add_del', is_add=0, is_multipath=0,
                              route=route)

    def route_in_vrf(self, vrf, ip_address, prefixlen,
                     next_hop_address, sw_if_index, is_ipv6=False,
                     is_local=False):
        """Returns True, if the route if present in the VRF.

        Pulls the VPP FIB to see if the route is present in the VRF.
        The route is identified by the tuple,
        (ip_address, prefixlen, next_hop_address)
        If the route is present, returns True or else returns False.
        The params: ip_address and next_hop_address are integer
        representations of the IPv4 or Ipv6 address.
        """
        # VPP 19.08 onwards ip_fib_dump/ip6_fib_dump are replaced by
        # ip_route_dump
        table = {'table_id': vrf, 'is_ip6': is_ipv6}
        routes = self.call_vpp('ip_route_dump', table=table)
        # Iterate though the routes and check for a matching route tuple
        # in the VRF table by checking the ip_address, prefixlen and
        # Convert the ip & next_hop addresses to an ipaddress format for
        # comparison
        ip = ipaddress.ip_address(bytes_to_ip(ip_address,
                                              is_ipv6))
        if next_hop_address is not None:
            next_hop = ipaddress.ip_address(
                bytes_to_ip(next_hop_address, is_ipv6))
        else:
            next_hop = next_hop_address

        # Note(onong): Utility functions. Move out to wider scope or a common
        # module perhaps if ever needed in future.
        def nexthop_ipaddr(p):
            # Return the ipaddress.IPvXAddress in the route path 'p'
            addr = p.nh.address.ip6 if is_ipv6 else p.nh.address.ip4
            return addr

        def any_local_routes(paths):
            # Check if there's any local route
            return any((p.type == vpp_const.ROUTE_LOCAL for p in paths))

        for route in routes:
            # VPP 19.08 onwards route is a bona-fide type of its own,
            # namely vl_api_ip_route_t, and is now a field in the object
            # returned in ip_route_details. In addition, the route prefix
            # too is now returned as the new vl_api_prefix_t type which
            # maps to IPv4Network/IPv6Network type in Python.
            route = route.route
            paths = route.paths
            table_id = route.table_id
            address = route.prefix.network_address
            address_len = route.prefix.prefixlen
            # if there's a valid next_hop_address check for the route by
            # including it
            if (next_hop_address and table_id == vrf and
                address_len == prefixlen and
                # check if route.address == ip
                address == ip and
                # check if the next_hop is present the list
                # of next hops in the route's path
                    (next_hop in [nexthop_ipaddr(p) for p in paths])):
                self.LOG.debug('Route: %s/%s to %s exists in VRF:%s',
                               ip, prefixlen, next_hop, vrf)
                return True
            elif (sw_if_index and table_id == vrf and
                  address_len == prefixlen and
                  # check if route.address == ip
                  address == ip and
                  # check if the next_hop matches
                  sw_if_index in [p.sw_if_index for p in paths]):
                self.LOG.debug('Route: %s/%s to sw_if_idx:%s is imported '
                               'into VRF:%s', ip, prefixlen, sw_if_index,
                               vrf)
                return True
            elif (is_local and table_id == vrf and
                  address_len == prefixlen and
                  address == ip and any_local_routes(paths)):
                self.LOG.debug('Local route: %s/%s exists in VRF:%s',
                               ip, prefixlen, vrf)
                return True
            # Note: The else clause in 'for' loop is executed when the
            # loop terminates without finding a matching route
        else:
            self.LOG.debug('Route: %s/%s to %s does not exist in VRF:%s',
                           ip, prefixlen, next_hop, vrf)
            return False

    def get_local_ip_address(self, ext_intf_ip, is_ipv6=False, vrf=0):
        """A generator of local IP addresses in VPP in a VRF.

        This generates local IPv4 or IPv6 addresses on the same subnet as the
        ext_intf_ip argument in the specified VRF.

        :Param: ext_intf_ip: The external interface address specified in
                             the CIDR (IP/Prefixlen) notation.
        """

        # Note(onong):
        # IN VPP 19.08, a new type is introduced, vl_api_prefix_t,
        # which is used as the type for an IP address in the CIDR/prefix
        # notation (eg: 10.0.0.10/8) as well as a network prefix (eg:
        # 10.0.0.0/8). Since the PAPI code maps this type to
        # IPv4Network/IPv6Network type in Python, it leads to the
        # conversion of a perfectly legitimate IP address, say,
        # 10.0.0.10/8 to it's network prefix, ie, 10.0.0.0/8, which is
        # incorrect and leads to undesirable results.
        #
        # Bug report: https://jira.fd.io/browse/VPP-1769
        #
        # In order to rectify it, in VPP 19.08.1, a new type is introduced,
        # namely, vl_api_address_with_prefix_t, which will denote an IP address
        # in the CIDR/prefix notation. This new type is mapped by PAPI to an
        # IPv4Interface/IPv6Interface type in Python.
        #
        # NB: Use VPP 19.08.1 and above only

        ext_intf_ip = ipaddress.ip_interface(ext_intf_ip)
        # VPP 19.08.1 onwards ip_fib_dump/ip6_fib_dump are replaced by
        # ip_route_dump
        table = {'table_id': vrf, 'is_ip6': is_ipv6}
        routes = self.call_vpp('ip_route_dump', table=table)

        for route in routes:
            # VPP 19.08 onwards route is a bona-fide type of its own,
            # named vl_api_ip_route_t, and is now a field in the object
            # returned in ip_route_details
            route = route.route
            paths = route.paths
            # VPP 19.08 onwards the route prefix is of the new
            # vl_api_prefix_t type mapped to [IPv4|IPv6]Network by PAPI
            address = route.prefix.network_address
            # NOTE(onong): not checking table_id == vrf anymore as it is
            # explicitly passed to the call to ip_route_dump
            if (any((p.type == vpp_const.ROUTE_LOCAL for p in paths)) and
                    address in ext_intf_ip.network):
                # TODO(onong): watch out in py3
                yield address.exploded

    def get_interface_ip_addresses(self, sw_if_idx):
        """Returns a list of all IP addresses assigned to an interface.

        This will return both v4 and v6 adressess in a list of tuples
        that contains the ip address and subnet mask. e.g.
        [(ipaddress(10.0.0.1), 24), (ipaddress(2001:db8:1234::1), 64)]
        using types from the ipaddress module.
        """

        # Note(onong):
        # IN VPP 19.08, a new type is introduced, vl_api_prefix_t,
        # which is used as the type for an IP address in the CIDR/prefix
        # notation (eg: 10.0.0.10/8) as well as a network prefix (eg:
        # 10.0.0.0/8). Since the PAPI code maps this type to
        # IPv4Network/IPv6Network type in Python, it leads to the
        # conversion of a perfectly legitimate IP address, say,
        # 10.0.0.10/8 to it's network prefix, ie, 10.0.0.0/8, which is
        # incorrect and leads to undesirable results.
        #
        # Bug report: https://jira.fd.io/browse/VPP-1769
        #
        # In order to rectify it, in VPP 19.08.1, a new type is introduced,
        # namely, vl_api_address_with_prefix_t, which will denote an IP address
        # in the CIDR/prefix notation. This new type is mapped by PAPI to an
        # IPv4Interface/IPv6Interface type in Python.
        #
        # NB: Use VPP 19.08.1 and above only
        int_addrs = []
        v4_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=False)
        for v4_addr in v4_addrs:
            # VPP 19.08.1 and onwards PAPI returns IPv4Interface object
            sanitized_v4 = v4_addr.prefix.ip
            prefix_len = v4_addr.prefix.network.prefixlen
            # The standard library has ipinterface, but it's hard
            # to construct with a numeric netmask
            int_addrs.append((sanitized_v4, prefix_len))

        v6_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=True)
        for v6_addr in v6_addrs:
            # VPP 19.08.1 and onwards PAPI returns IPv6Interface object
            sanitized_v6 = v6_addr.prefix.ip
            prefix_len = v6_addr.prefix.network.prefixlen
            int_addrs.append((sanitized_v6, prefix_len))
        return int_addrs

    ########################################

    def set_interface_mtu(self, sw_if_idx, mtu):
        # In VPP 18.07, the mtu field is an array which allows for setting
        # MTU for L3, IPv4, IPv6 and MPLS:
        #
        #     u32 mtu[4]; /* 0 - L3, 1 - IP4, 2 - IP6, 3 - MPLS */
        #
        # Details in the following link:
        #     https://docs.fd.io/vpp/18.07/md_src_vnet_MTU.html
        #
        # TODO(onong): This is a quick fix for 18.07. Further changes may be
        # required after the discussion around jumbo frames
        self.call_vpp('sw_interface_set_mtu', sw_if_index=sw_if_idx,
                      mtu=[mtu, 0, 0, 0])

    ########################################

    # Enables or Disables the NAT feature on an interface
    def set_snat_on_interface(self, sw_if_index, is_inside=1, is_add=1):
        # In VPP 19.08, the is_inside field is part of the new flags
        # field which is a bitmask
        flags = vpp_const.IS_INSIDE if is_inside else vpp_const.IS_OUTSIDE
        self.call_vpp('nat44_interface_add_del_feature',
                      sw_if_index=sw_if_index,
                      flags=flags,
                      is_add=is_add)

    # Enable or Disable the dynamic NAT feature on the outside interface
    def snat_overload_on_interface_address(self, sw_if_index, is_add=1):
        """Sets/Removes 1:N NAT overload on the outside interface address."""
        self.call_vpp('nat44_add_del_interface_addr',
                      is_add=is_add,
                      sw_if_index=sw_if_index)

    def get_outside_snat_interface_indices(self):
        """Returns the sw_if_indices of ext. interfaces with SNAT enabled"""
        ifidxlist = []
        for intf in self.call_vpp('nat44_interface_dump'):
            # In VPP 19.08, the is_inside field is part of the new flags
            # field which is a bitmask
            if intf.flags & vpp_const.IS_OUTSIDE:
                ifidxlist.append(intf.sw_if_index)
        return ifidxlist

    def get_snat_interfaces(self):
        """Returns the sw_if_indices of all interfaces with SNAT enabled"""
        snat_interface_list = []
        snat_interfaces = self.call_vpp('nat44_interface_dump')
        for intf in snat_interfaces:
            snat_interface_list.append(intf.sw_if_index)
        return snat_interface_list

    def get_snat_local_ipaddresses(self):
        # NB: Only IPv4 SNAT addresses are supported.
        snat_local_ipaddresses = []
        snat_static_mappings = self.call_vpp('nat44_static_mapping_dump')
        for static_mapping in snat_static_mappings:
            addr = ""
            # In VPP 19.08, vl_api_ip4_address_t type is returned by VPP
            # and which is mapped to IPv4Address by PAPI
            # TODO(onong): watch out in py3
            addr = static_mapping.local_ip_address.exploded
            snat_local_ipaddresses.append(addr)
        return snat_local_ipaddresses

    def clear_snat_sessions(self, ip_addr):
        """Clear any dynamic NAT translations if present for the ip_addr."""
        user_vrf = None
        snat_users = self.call_vpp('nat44_user_dump')
        for user in snat_users:
            if ipaddress.IPv4Address(ip_addr) == ipaddress.IPv4Address(
                    user.ip_address):
                user_vrf = user.vrf_id
                break
        # A NAT session exists if the user_vrf is set
        if user_vrf is not None:
            # Note(onong): nat44_user_session_dump expects the binary IPv4
            # address and IPv4Address(ip_addr).packed works fine for python2 as
            # well as python3; no need for str(...)
            packed_ip_addr = ipaddress.IPv4Address(ip_addr).packed
            user_sessions = self.call_vpp('nat44_user_session_dump',
                                          ip_address=packed_ip_addr,
                                          vrf_id=user_vrf
                                          )
            for session in user_sessions:
                # Delete all dynamic NAT translations
                # In VPP 19.08, IS_INSIDE, IS_STATIC etc need to be
                # specified in the new field flags
                if not session.flags & vpp_const.IS_STATIC:
                    flags = vpp_const.IS_INSIDE
                    self.call_vpp('nat44_del_session',
                                  flags=flags,   # inside
                                  protocol=session.protocol,
                                  address=packed_ip_addr,
                                  vrf_id=user_vrf,
                                  port=session.inside_port)

    def get_snat_static_mappings(self):
        return self.call_vpp('nat44_static_mapping_dump')

    def set_snat_static_mapping(self, local_ip, external_ip, tenant_vrf,
                                is_add=1):
        # Note(onong): watch out for py3
        # In py3 str() will give unicode and not bytes and the API expects a
        # bytes like object. local_ip and external_ip are coming from neutron
        # and they are of type unicode. We need to convert it into bytes like
        # object. str() works on py27 bcoz str and bytes are the same. But on
        # py3, str is unicode so this will need changes in py3
        local_ip = ipaddress.IPv4Address(local_ip).packed
        external_ip = ipaddress.IPv4Address(external_ip).packed
        self.call_vpp('nat44_add_del_static_mapping',
                      local_ip_address=local_ip,
                      external_ip_address=external_ip,
                      external_sw_if_index=0xFFFFFFFF,  # -1 = Not used
                      local_port=0,     # 0 = ignore
                      external_port=0,  # 0 = ignore
                      flags=vpp_const.ADDR_ONLY,  # 1 = address only mapping
                      vrf_id=tenant_vrf,
                      is_add=is_add)    # 1 = add, 0 = delete

    def get_snat_addresses(self):
        ret_addrs = []
        addresses = self.call_vpp('nat44_address_dump')
        for addr in addresses:
            ret_addrs.append(str(ipaddress.ip_address(addr[3][:4]).exploded))

        return ret_addrs

    ########################################

    def lisp_enable(self):
        self.call_vpp('lisp_enable_disable', is_enable=True)

    def is_lisp_enabled(self):
        t = self.call_vpp('show_lisp_status')
        return t.is_gpe_enabled

    def get_lisp_vni_to_bd_mappings(self):
        """Retrieve LISP mappings between the VNI and Bridge Domain."""
        t = self.call_vpp('lisp_eid_table_map_dump', is_l2=True)
        return [(eid_map.vni, eid_map.dp_table) for eid_map in t]

    def add_lisp_vni_to_bd_mapping(self, vni, bridge_domain):
        """Add a LISP mapping between a VNI and bridge-domain."""
        self.call_vpp('lisp_eid_table_add_del_map',
                      is_add=True,
                      vni=vni,
                      dp_table=bridge_domain,
                      is_l2=True)

    def del_lisp_vni_to_bd_mapping(self, vni, bridge_domain):
        """Delete the LISP mapping between a VNI and bridge-domain."""
        self.call_vpp('lisp_eid_table_add_del_map',
                      is_add=False,
                      vni=vni,
                      dp_table=bridge_domain,
                      is_l2=True)

    def add_lisp_local_mac(self, mac, vni, locator_set_name):
        """Add a local mac address to VNI association in LISP"""
        # Note(onong): In 20.05, eid and eid_type are subsumed in a new type,
        # namely, vl_api_eid_t
        eid = {"type": vpp_const.EID_MAC,
               "address": {"mac": mac_to_bytes(mac)}}
        self.call_vpp('lisp_add_del_local_eid',
                      is_add=True,
                      eid=eid,
                      locator_set_name=locator_set_name,
                      vni=vni)

    def del_lisp_local_mac(self, mac, vni, locator_set_name):
        """Delete a local mac address to VNI association in LISP"""
        # Note(onong): In 20.05, eid and eid_type are subsumed in a new type,
        # namely, vl_api_eid_t
        eid = {"type": vpp_const.EID_MAC,
               "address": {"mac": mac_to_bytes(mac)}}
        self.call_vpp('lisp_add_del_local_eid',
                      is_add=False,
                      eid=eid,
                      locator_set_name=locator_set_name,
                      vni=vni)

    def add_lisp_remote_mac(self, mac, vni, underlay):
        """Add a LISP entry for a remote mac address to the underlay IP.

        Arguments:-
        mac - remote mac_address
        vni - virtual network identifier
        underlay - An underlay IP represented within a dict. as below:
                           {"is_ip4": <value>,
                           "priority": <priority>,
                           "weight": <weight>,
                           "addr": <binary IPv4 or IPv6 address>}])
        """
        # Note(onong): In 20.05, eid and eid_type are subsumed in a new type,
        # namely, vl_api_eid_t
        eid = {"type": vpp_const.EID_MAC,
               "address": {"mac": mac_to_bytes(mac)}}
        self.call_vpp('lisp_add_del_remote_mapping',
                      is_add=True,
                      vni=vni,
                      deid=eid,
                      rlocs=[underlay],
                      rloc_num=1,
                      is_src_dst=False)

    def del_lisp_remote_mac(self, mac, vni):
        """Delete a LISP entry for a remote mac address.

        Arguments:-
        mac - remote mac_address
        vni - virtual network identifier
        """
        # Note(onong): In 20.05, eid and eid_type are subsumed in a new type,
        # namely, vl_api_eid_t
        eid = {"type": vpp_const.EID_MAC,
               "address": {"mac": mac_to_bytes(mac)}}
        self.call_vpp('lisp_add_del_remote_mapping',
                      is_add=False,
                      vni=vni,
                      deid=eid,
                      rlocs=[],
                      rloc_num=0,
                      is_src_dst=False)

    def add_lisp_locator_set(self, locator_set_name):
        """Adds a LISP locator set.

        A LISP locator set is a set of underlay interfaces used by GPE.
        """
        t = self.call_vpp('lisp_add_del_locator_set',
                          is_add=True,
                          locator_set_name=locator_set_name,
                          locator_num=0,
                          locators=[])
        return t.ls_index

    def add_lisp_locator(self, locator_set_name, sw_if_index,
                         priority=1, weight=1):
        """Adds a LISP locator to the locator set.

        A LISP locator is the software interface index of the underlay
        interface.
        """
        self.call_vpp('lisp_add_del_locator',
                      is_add=True,
                      locator_set_name=locator_set_name,
                      sw_if_index=sw_if_index,
                      priority=priority,
                      weight=weight)

    def del_lisp_locator(self, locator_set_name, sw_if_index):
        """Removes a LISP locator from the locator set.

        A LISP locator is the software interface index of the underlay
        interface.
        """
        self.call_vpp('lisp_add_del_locator',
                      is_add=False,
                      locator_set_name=locator_set_name,
                      sw_if_index=sw_if_index)

    def add_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Adds a static ARP entry to LISP.

        ipv4_address is an integer representation of the IPv4 address.
        """
        # Note(onong): In 20.05, mac and ip4 have been combined to a new type,
        # namely, vl_api_one_l2_arp_entry_t
        arp_entry = {"mac": mac_to_bytes(mac), "ip4": ipv4_address}
        self.call_vpp('one_add_del_l2_arp_entry',
                      is_add=True,
                      entry=arp_entry,
                      bd=bridge_domain
                      )

    def add_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Adds a static IPv6 NDP entry to LISP.

        ipv6_address is the packed representation of a IPv6 address.
        """
        # Note(onong): In 20.05, mac and ip6 have been combined to a new type,
        # namely, vl_api_one_ndp_entry_t
        ndp_entry = {"mac": mac_to_bytes(mac), "ip6": ipv6_address}
        self.call_vpp('one_add_del_ndp_entry',
                      is_add=True,
                      entry=ndp_entry,
                      bd=bridge_domain
                      )

    def del_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Removes a static ARP entry from LISP.

        ipv4_address is an integer representation of the IPv4 address.
        """
        # Note(onong): In 20.05, mac and ip4 have been combined to a new type,
        # namely, vl_api_one_l2_arp_entry_t
        arp_entry = {"mac": mac_to_bytes(mac), "ip4": ipv4_address}
        self.call_vpp('one_add_del_l2_arp_entry',
                      is_add=False,
                      entry=arp_entry,
                      bd=bridge_domain
                      )

    def del_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Removes a static IPv6 NDP entry from LISP.

        ipv6_address is the packed representation of a v6 address.
        """
        # Note(onong): In 20.05, mac and ip6 have been combined to a new type,
        # namely, vl_api_one_ndp_entry_t
        ndp_entry = {"mac": mac_to_bytes(mac), "ip6": ipv6_address}
        self.call_vpp('one_add_del_ndp_entry',
                      is_add=False,
                      entry=ndp_entry,
                      bd=bridge_domain
                      )

    def replace_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Replaces the LISP ARP entry in a bridge domain for the IP address.

        ipv4_adddress is an integer representation of the IPv4 address.
        """
        # Delete the current ARP entry for the ipv4_address in the BD
        for mac_addr, ip4 in [(arp.mac, arp.ip4) for arp in
                              self.call_vpp('one_l2_arp_entries_get',
                                            bd=bridge_domain).entries
                              if arp.ip4 == ipv4_address]:
            # Note(onong): In 20.05, mac and ip4 have been combined to a new
            # type, namely, vl_api_one_l2_arp_entry_t
            arp_entry = {"mac": mac_addr.mac_binary, "ip4": ip4}
            self.call_vpp('one_add_del_l2_arp_entry',
                          is_add=False, entry=arp_entry, bd=bridge_domain)
        # Add the new ARP entry
        self.add_lisp_arp_entry(mac, bridge_domain, ipv4_address)

    def replace_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Replaces the LISP NDP entry in a bridge domain for the v6 address.

        ipv6_adddress is a packed representation of the IPv6 address.
        """
        # Delete the current NDP entry for the ipv6_address in the BD
        for mac_addr, ip6 in [(ndp_entry.mac, ndp_entry.ip6) for ndp_entry in
                              self.call_vpp('one_ndp_entries_get',
                                            bd=bridge_domain).entries
                              if ndp_entry.ip6 == ipv6_address]:
            # Note(onong): In 20.05, mac and ip6 have been combined to a new
            # type, namely, vl_api_one_ndp_entry_t
            ndp_entry = {"mac": mac_addr.mac_binary, "ip6": ip6}
            self.call_vpp('one_add_del_ndp_entry',
                          is_add=0, entry=ndp_entry, bd=bridge_domain)
        # Add the new v6 NDP entry
        self.add_lisp_ndp_entry(mac, bridge_domain, ipv6_address)

    def exists_lisp_arp_entry(self, bridge_domain, ipv4_address):
        """Return True if a LISP ARP entry exists in the bridge_domain.

        ipv4_address is an integer representation of the IPv4 address.
        """
        return ipv4_address in [arp.ip4 for arp in
                                self.call_vpp('one_l2_arp_entries_get',
                                              bd=bridge_domain).entries]

    def exists_lisp_ndp_entry(self, bridge_domain, ipv6_address):
        """Return True if a LISP NDP entry exists in the bridge_domain.

        ipv6_address is the packed representation of the IPv6 address.
        """
        return ipv6_address in [ndp_entry.ip6 for ndp_entry in
                                self.call_vpp('one_ndp_entries_get',
                                              bd=bridge_domain).entries]

    def clear_lisp_arp_entries(self, bridge_domain):
        """Clear LISP ARP entries in the bridge_domain."""
        for mac, ip4 in [(arp.mac, arp.ip4) for arp in
                         self.call_vpp('one_l2_arp_entries_get',
                                       bd=bridge_domain).entries]:
            # Note(onong): In 20.05, mac and ip4 have been combined to a new
            # type, namely, vl_api_one_l2_arp_entry_t
            arp_entry = {"mac": mac.mac_binary, "ip4": ip4}
            self.call_vpp('one_add_del_l2_arp_entry',
                          is_add=0, entry=arp_entry, bd=bridge_domain)

    def clear_lisp_ndp_entries(self, bridge_domain):
        """Clear LISP NDP entries in the bridge_domain."""
        for mac, ip6 in [(ndp_entry.mac, ndp_entry.ip6) for ndp_entry in
                         self.call_vpp('one_ndp_entries_get',
                                       bd=bridge_domain).entries]:
            # Note(onong): In 20.05, mac and ip6 have been combined to a new
            # type, namely, vl_api_one_ndp_entry_t
            ndp_entry = {"mac": mac_to_bytes(mac), "ip6": ip6}
            self.call_vpp('one_add_del_ndp_entry',
                          is_add=0, entry=ndp_entry, bd=bridge_domain)

    def get_lisp_local_locators(self, name):
        """Get lisp local locator sets and their corresponding locators.

        GPE uses a locator-set to group the available underlay interfaces.
        Each underlay interface is called a locator. This method is used to
        retrieve the list of locators present within VPP for a certain
        locator-set.

        Arguments:-
        name: The name of the locator set

        Returns:-
        A list of locators.
        Each locator is a dictionary and has as key named "sw_if_idxs" used
        to identify all the software indexes within VPP functioning as the
        underlay interfaces for the locator set.

        """
        locators = []
        # filter=1 for local locators
        t = self.call_vpp('lisp_locator_set_dump',
                          filter=vpp_const.FILTER_LOCAL)
        for ls in t:
            ls_set_name = ls.ls_name
            if ls_set_name == name:
                locators.append({'locator_set_name': ls_set_name,
                                 'locator_set_index': ls.ls_index,
                                 'sw_if_idxs': [intf.sw_if_index for
                                                intf in self.call_vpp(
                                                    'lisp_locator_dump',
                                                    ls_name=ls_set_name)
                                                ]
                                 }
                                )
        return locators

    def get_lisp_locator_ip(self, locator_index):
        """Get the IP address of the locator (i.e. underlay) from its index"""
        t = self.call_vpp('lisp_locator_dump',
                          ls_index=locator_index,
                          is_index_set=1)
        for locator in t:
            ip = ipaddress.ip_address(locator.ip_address)
            return ip.exploded

    def get_lisp_eid_table(self):
        """Query the LISP EID table within VPP and return its contents.

        A LISP EID table keeps a mapping between the mac-addresses, VNI
        and the underlay interfaces known to VPP. The 'is_local' key
        is used to determine whether the mapping is local or remote.
        """
        t = self.call_vpp('lisp_eid_table_dump')
        return [{'is_local': val.is_local,
                 'locator_set_index': val.locator_set_index,
                 'mac': val.seid.address,
                 'vni': val.vni
                 } for val in t]

    ########################################

    def cross_connect(self, source_idx, dest_idx):
        self.LOG.debug("Enable cross connected between %d-->%d",
                       source_idx, dest_idx)
        self.call_vpp('l2_patch_add_del',
                      rx_sw_if_index=source_idx,
                      tx_sw_if_index=dest_idx,
                      is_add=True)

    ########################################

    def enable_port_mirroring(self, src_idx, dst_idx,
                              direction=vpp_const.SPAN_RX_TX, is_l2=True):
        self.LOG.debug("Enable span from %d to %d",
                       src_idx, dst_idx)
        self.call_vpp('sw_interface_span_enable_disable',
                      sw_if_index_from=src_idx,
                      sw_if_index_to=dst_idx,
                      state=direction,
                      is_l2=is_l2)

    def disable_port_mirroring(self, source_idx, dest_idx, is_l2=True):
        self.LOG.debug("Disable span from %d to %d",
                       source_idx, dest_idx)
        self.call_vpp('sw_interface_span_enable_disable',
                      sw_if_index_from=source_idx,
                      sw_if_index_to=dest_idx,
                      state=vpp_const.SPAN_DISABLED,
                      is_l2=is_l2)

    def dump_port_mirroring(self):
        self.LOG.debug("Dump span")
        t = self.call_vpp('sw_interface_span_dump')
        return t

    ########################################

    def create_vxlan_tunnel(self, src_addr, dst_addr, is_ipv6, vni):
        self.LOG.debug("Create vxlan tunnel VNI: %d", vni)
        # Device instance (ifidx) is selected for us (~0)
        # Decap graph node left to its default (~0)
        t = self.call_vpp('vxlan_add_del_tunnel',
                          is_add=True,
                          instance=0xffffffff,
                          src_address=src_addr,
                          dst_address=dst_addr,
                          decap_next_index=0xffffffff,
                          vni=vni)
        return t.sw_if_index

    def delete_vxlan_tunnel(self, src_addr, dst_addr, is_ipv6, vni):
        self.LOG.debug("Delete vxlan tunnel VNI: %d", vni)
        self.call_vpp('vxlan_add_del_tunnel',
                      is_add=False,
                      src_address=src_addr,
                      dst_address=dst_addr,
                      vni=vni)

    def get_vxlan_tunnels(self):
        """Get the list of existing vxlan tunnels in this node

        Tunnels returned as a hash: (vni, dest) => tunnel ifidx
        """
        t = self.call_vpp('vxlan_tunnel_dump', sw_if_index=0xffffffff)
        tuns = {}
        for tun in t:
            tuns[(tun.vni, tun.dst_address,)] = tun.sw_if_index
        return tuns

    def create_erspan_tunnel(self, src_addr, dst_addr, is_ipv6, session_id):
        self.LOG.debug("Create ERSPAN tunnel session_id: %d", session_id)
        # Device instance (ifidx) is selected for us (~0)
        # Note(onong): 19.08 onwards GRE tunnel attributes are encapsulated
        # in the new vl_api_gre_tunnel_t type.
        tun = {"type": vpp_const.TUNNEL_TYPE_ERSPAN,
               "mode": vpp_const.TUNNEL_ENCAP_DECAP_NONE,
               "flags": vpp_const.TUNNEL_MODE_P2P,
               "session_id": session_id,
               "instance": 0xffffffff,
               "outer_table_id": 0,
               "src": src_addr,
               "dst": dst_addr}
        t = self.call_vpp('gre_tunnel_add_del',
                          is_add=True,
                          tunnel=tun)
        return t.sw_if_index

    def delete_erspan_tunnel(self, src_addr, dst_addr, is_ipv6, session_id):
        self.LOG.debug("Delete ERSPAN tunnel session_id: %d", session_id)
        # Note(onong): 19.08 onwards GRE tunnel attributes are encapsulated
        # in the new vl_api_gre_tunnel_t type.
        tun = {"type": vpp_const.TUNNEL_TYPE_ERSPAN,
               "mode": vpp_const.TUNNEL_ENCAP_DECAP_NONE,
               "flags": vpp_const.TUNNEL_MODE_P2P,
               "session_id": session_id,
               "instance": 0xffffffff,
               "outer_table_id": 0,
               "src": src_addr,
               "dst": dst_addr}
        self.call_vpp('gre_tunnel_add_del', is_add=False, tunnel=tun)

    def get_erspan_tunnels(self):
        """Get the list of existing erspan tunnels in this node

        Tunnels returned as a hash: (session_id, dest) => tunnel ifidx
        """
        t = self.call_vpp('gre_tunnel_dump', sw_if_index=0xffffffff)
        tuns = {}
        for tun0 in t:
            tun = tun0.tunnel
            if tun.type == vpp_const.TUNNEL_TYPE_ERSPAN:
                tuns[(tun.session_id, tun.dst,)] = tun.sw_if_index
        return tuns
