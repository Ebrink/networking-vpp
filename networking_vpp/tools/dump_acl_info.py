# Copyright (c) 2017 Cisco Systems, Inc.
# All Rights Reserved.
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

import vpp_papi

conn = vpp_papi.VPP()
conn.connect('debug-acl-client')


def vpp_call(func, *args, **kwargs):
    global conn
    if hasattr(conn, 'api'):
        return getattr(conn.api, func)(*args, **kwargs)
    return getattr(conn, func)(*args, **kwargs)


def decode_acl_rule(t):
    return {
        "is_permit": t.is_permit,
        'src_prefix': t.src_prefix,
        'dst_prefix': t.dst_prefix,
        "proto": t.proto,
        'src_range': [t.srcport_or_icmptype_first, t.srcport_or_icmptype_last],
        'dst_range': [t.dstport_or_icmpcode_first, t.dstport_or_icmpcode_last],
        "tcp_flags_mask": t.tcp_flags_mask,
        "tcp_flags_value": t.tcp_flags_value
    }


def decode_macip_acl_rule(t):
    return {
        "is_permit": t.is_permit,
        "src_mac": t.src_mac,
        'src_mac_mask': t.src_mac_mask,
        'src_prefix': t.src_prefix
    }


def get_interfaces():

    global conn

    t = vpp_call('sw_interface_dump')

    for iface in t:
        yield {'name': iface.interface_name,
               'tag': iface.tag,
               'mac': iface.l2_address,
               'sw_if_index': iface.sw_if_index,
               'sup_sw_if_index': iface.sup_sw_if_index}


def get_acls(self):
    # get all ACLs
    global conn

    t = vpp_call('acl_dump', acl_index=0xffffffff)
    for acl in t:
        if hasattr(acl, 'acl_index'):
            yield {
                'acl_idx': acl.acl_index,
                'acl_tag': acl.tag
            }


def get_if_macip_acls(sw_if_index):
    global conn

    def get_acl_rules(t):
        for f in t.r:
            yield decode_macip_acl_rule(f)

    # This gets all MACIP ACLs, index by interface
    if_acls = vpp_call('macip_acl_interface_get')
    # Ours is indexed...
    # This is a spot of weirdness in the API

    if sw_if_index not in if_acls.acls:
        return  # no ACL, no rules

    f = if_acls.acls[sw_if_index]
    if f == 0xffffffff:
        return  # no ACL, no rules

    t = vpp_call('macip_acl_dump', acl_index=f)
    t = t[0]

    yield {
        'acl_index': t.acl_index,
        'tag': t.tag,
        'rules': get_acl_rules(t)
    }


def get_if_acls(sw_if_index):
    global conn

    t = vpp_call('acl_interface_list_dump',
                 sw_if_index=sw_if_index)
    # We're dumping one interface
    t = t[0]

    def get_acl_rules(l):
        for f in l:
            yield decode_acl_rule(f)

    count = 0
    for det in t.acls:
        is_input = (count < t.n_input)

        dump = vpp_call('acl_dump', acl_index=det)
        dump = dump[0]  # one acl
        yield {
            'is_input': is_input,
            'acl_index': det,
            'tag': dump.tag,
            'rules': get_acl_rules(dump.r)  # an iterator
        }
        count = count + 1


protos = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    46: 'RSVP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'IPv6-ICMP',
    59: 'IPv6-NoNxt',
    60: 'IPv6-Opts',
    88: 'EIGRP',
    89: 'OSPF',
    103: 'PIM',
    112: 'VRRP',
    115: 'L2TP',
}


def decode_proto(num):
    global protos

    return protos.get(num, 'proto-%s' % str(num))


def main():
    for intf in get_interfaces():
        print('Interface %d, name %s tag "%s"'
              % (intf['sw_if_index'], intf['name'], intf['tag']))
        for macip in get_if_macip_acls(intf['sw_if_index']):
            print('    MACIP %d tag "%s"' % (macip['acl_index'], macip['tag']))
            for rule in macip['rules']:
                print('        %s %s: %s mask %s %s' % (
                    ('permit' if rule['is_permit']
                     else 'not permit (%s)' % str(rule['is_permit'])),
                    'ipv6' if rule["src_prefix"].version == 6 else 'ipv4',
                    rule["src_mac"],
                    rule['src_mac_mask'],
                    rule["src_prefix"]))
        for acl in get_if_acls(intf['sw_if_index']):
            print('    ACL %d (%s, %s)' % (acl['acl_index'],
                                           acl['tag'],
                                           'input' if acl['is_input']
                                           else 'output'))
            for rule in acl['rules']:
                print('        %s %s: %s %s[%d-%d] -> %s[%d-%d] '
                      'TCP(%d mask %d)' % (
                          ('permit' if rule['is_permit']
                           else 'not permit (%s)' % str(rule['is_permit'])),
                          ('ipv6' if rule["src_prefix"].version == 6
                           else 'ipv4'),
                          decode_proto(rule["proto"]),
                          rule["src_prefix"],
                          rule['src_range'][0],
                          rule['src_range'][1],
                          rule["dst_prefix"],
                          rule['dst_range'][0],
                          rule['dst_range'][1],
                          rule["tcp_flags_mask"],
                          rule["tcp_flags_value"]))


if __name__ == '__main__':
    main()
