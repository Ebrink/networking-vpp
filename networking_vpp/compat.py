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


# Staying abreast of neutron.db changes in Stein
try:
    # Rocky and before
    from neutron.db import _resource_extend as resource_extend
    from neutron.db import api as neutron_db_api
    db_context_writer = neutron_db_api.context_manager.writer
    db_context_reader = neutron_db_api.context_manager.reader
except ImportError:
    # Stein onwards
    from neutron_lib.db import api as neutron_db_api
    from neutron_lib.db import resource_extend  # noqa: F401
    db_context_writer = neutron_db_api.CONTEXT_WRITER
    db_context_reader = neutron_db_api.CONTEXT_READER

# Neutron changes in Train
try:
    # Stein and before
    from neutron.services.trunk import constants
    trunk_const = constants
except ImportError:
    # Map changed trunk constants in Train
    from neutron_lib.services.trunk import constants

    class new_trunk_const(object):
        VLAN = constants.SEGMENTATION_TYPE_VLAN
        TRUNK = 'trunk'
        TRUNK_PLUGIN = 'trunk_plugin'
        DOWN_STATUS = constants.TRUNK_DOWN_STATUS
        ACTIVE_STATUS = constants.TRUNK_ACTIVE_STATUS
        ERROR_STATUS = constants.TRUNK_ERROR_STATUS
        SUBPORTS = 'subports'
    trunk_const = new_trunk_const
