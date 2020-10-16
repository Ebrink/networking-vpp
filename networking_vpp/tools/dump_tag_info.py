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


def get_interfaces():

    global conn

    t = vpp_call('sw_interface_dump')

    for iface in t:
        yield {'name': iface.interface_name,
               'tag': iface.tag,
               'mac': iface.l2_address,
               'sw_if_index': iface.sw_if_index,
               'sup_sw_if_index': iface.sup_sw_if_index}


def main():
    for intf in get_interfaces():
        print('%5d %30s %64s' % (intf['sw_if_index'],
                                 intf['name'],
                                 intf['tag']))


if __name__ == '__main__':
    main()
