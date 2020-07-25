# Copyright (c) 2016 Cisco Systems, Inc.
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

from neutron.agent.linux import bridge_lib  # flake8: noqa: N530
import neutron.conf.agent.securitygroups_rpc
import neutron.conf.plugins.ml2.config
from neutron.tests import base  # flake8: noqa: N530

import networking_vpp.compat


class TestBridgeFunctions(base.BaseTestCase):
    def test_bridge_lib_compatibility(self):
        """Test we're running against a new-ish version of Neutron

        We used to have a compatibility layer for this stuff, but this
        tests we can do without.
        """
        self.assertTrue('owns_interface' in dir(bridge_lib.BridgeDevice))
        self.assertTrue('exists' in dir(bridge_lib.BridgeDevice))
        self.assertTrue(
            'get_log_fail_as_error' in dir(bridge_lib.BridgeDevice))
        self.assertTrue(
            'disable_ipv6' in dir(bridge_lib.BridgeDevice))


class TestOptions(base.BaseTestCase):
    def test_options(self):
        """Confirm options setting functions are where we left them

        Neutron moved these options functions.  As we removed our
        compatibility layer that testes for that we added these tests
        to confirm that they are present where we expect.
        """
        self.assertTrue('register_securitygroups_opts' in
                        dir(neutron.conf.agent.securitygroups_rpc))
        self.assertTrue('register_ml2_plugin_opts' in
                        dir(neutron.conf.plugins.ml2.config))


class TestCompat(base.BaseTestCase):
    def test_compat_imports_provide(self):
        # segment types
        self.assertTrue(hasattr(networking_vpp.compat.n_const, 'TYPE_VXLAN'))
        self.assertTrue(hasattr(networking_vpp.compat.n_const, 'TYPE_VLAN'))
        self.assertTrue(hasattr(networking_vpp.compat.n_const, 'TYPE_FLAT'))
        self.assertTrue(hasattr(networking_vpp.compat.n_const, 'TYPE_NONE'))

        # service extension types
        self.assertTrue(hasattr(networking_vpp.compat.plugin_constants, 'L3'))

        # usefule functions and constants

        self.assertTrue(isinstance(networking_vpp.compat.n_const.UUID_PATTERN,
                                   str))

        self.assertTrue(networking_vpp.compat.net_utils, 'get_random_mac')
