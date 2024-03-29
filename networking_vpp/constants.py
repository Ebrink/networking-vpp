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

# Common constants used by mech_vpp, server and plugins

LEADIN = '/networking-vpp'
ROUTERS_DIR = 'routers/'
ROUTER_FIP_DIR = 'routers/floatingip/'
GPE_LSET_NAME = 'net-vpp-gpe-lset-1'
TYPE_GPE = 'gpe'
GPE_UDP_PORT = 4790
GPE_ENCAP_OVERHEAD = 30
MIN_GPE_VNI = 1
MAX_GPE_VNI = 2 ** 24 - 1
API_MANIFEST_FILE = 'vpp-api-files/vpp_api_manifest.json'
API_WHITELIST_FILE = 'vpp-api-files/vpp_api_whitelist.json'
