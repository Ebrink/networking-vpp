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

from networking_vpp._i18n import _
from networking_vpp import etcdutils
from oslo_config import cfg

_vpp_opts = [
    cfg.StrOpt('physnets',
               help=_("Comma-separated list of net-name:interface-name for "
                      "physical connections")),
    cfg.StrOpt('gpe_src_cidr', default=None,
               help=_("The source_IP/Mask used for GPE tunnel packets. ")),
    cfg.StrOpt('gpe_locators', default=None,
               help=_("The physnet name(s) used as the underlay "
                      "(i.e. locator) interface by GPE. The agent will "
                      "program the GPE source CIDR on this interface "
                      "and will assume that it has Layer3 reachability "
                      "with all other GPE locator interfaces "
                      "specified on compute and network nodes. In the "
                      "current implementation only a single locator "
                      "is supported.")),
    cfg.ListOpt('gpe_vni_ranges', default=[],
                help=_("A comma-separated list of <tun_min>:<tun_max> "
                       "tuples enumerating ranges of GPE VNI IDs "
                       "available for tenant network allocation")),
    cfg.IntOpt('etcd_write_time', default=20,
               help=_("The period of time alloted to etcd write before it is "
                      "timed out.")),
    cfg.IntOpt('forward_worker_master_lease_time', default=30,
               help=_("The slice of time allotted for a journal forward worker"
                      " thread to run once elected.")),
    cfg.IntOpt('forward_worker_recovery_time', default=3,
               help=_("The worst case time a new forward worker master is "
                      "elected after a forward worker's mastership expires. "
                      "etcd updates may stall for a total of "
                      "forward_worker_master_lease_time plus "
                      "forward_worker_recovery_time.")),
    cfg.IntOpt('db_query_time', default=60,
               help=_("The period of a db query can run before it is timed "
                      "out. This is to ensure master election time is extended"
                      " accordingly")),
    cfg.BoolOpt('enable_vpp_restart', default=False,
                help=_("Agent restarts VPP during startup")),
    cfg.StrOpt('vhost_user_dir', default='/tmp',
               help=_("vhostuser socket directory")),
    cfg.IntOpt('mac_age', default=180,
               help=_("bridge domain MAC aging TTL (in seconds)")),
    cfg.IntOpt('vpp_cmd_queue_len', default=None,
               help=_("Size of the VPP command queue (in messages)")),
    cfg.StrOpt('l3_hosts', default="127.0.0.1",
               help=_("A comma separated list of Hostnames "
                      "to render L3 services on.")),
    cfg.BoolOpt('enable_l3_ha', default=False,
                help=_("Enable L3 HA feature. Disabled by default.")),
    cfg.BoolOpt('jwt_signing', default=False,
                help=_("Activate JWT token in etcd messages")),

    cfg.StrOpt('jwt_ca_cert',
               default=None,
               help=_("Root CA certificate for the JWT verification")),
    cfg.StrOpt('jwt_node_cert',
               default=None,
               help=_("Local Node certificate for the JWT verification")),
    cfg.StrOpt('jwt_node_private_key',
               default=None,
               help=_("Local Node private key for the JWT computation")),

    cfg.IntOpt('jwt_max_duration', default=0,
               help=_("JWT token max duration in seconds to prevent"
                      " replay attack")),

    cfg.StrOpt('jwt_controller_name_pattern', default="Controller.*",
               help=_("Openstack Controller Host name for JWT verification")),
    cfg.StrOpt('vpp_agent_extensions', default='',
               help=_("Enabled extensions for the VPP agent")),
    cfg.StrOpt('driver_extensions', default='',
               help=_("Enabled extensions for the mechanism driver")),
    cfg.StrOpt('esp_src_cidr', default=None,
               help=_("The source_IP/prefix_len used for ERSPAN")),
    cfg.StrOpt('esp_physnet', default=None,
               help=_("The physical network used for ERSPAN")),
    cfg.StrOpt('network_types', default='vlan,gpe,flat',
               help=_("Enabled network types (driver will be loaded)"))
]

cfg_group = cfg.OptGroup(name='ml2_vpp',
                         title='VPP mechanism driver options',
                         help='Configures the VPP ML2 driver and its agents.')


def register_vpp_opts(cfg=cfg.CONF):
    global _vpp_opts
    cfg.register_opts(_vpp_opts, cfg_group)
    etcdutils.register_etcd_conn_opts(cfg, cfg_group)


def list_opts():
    """Oslo config generator entry point"""
    return [(cfg_group, _vpp_opts + etcdutils.list_opts())]
