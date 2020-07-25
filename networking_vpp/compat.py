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


# Compat used to make a lot of decisions about where a file should be
# loaded from, and the remainder of the code simply uses compat.XXX to
# save making the decisions everywhere.

# Most of this is now very old, and we intend to remove pre-Queens support.

# Phase 1 of this is to remove the decision making logic and still use
# compat imports, which is what you're looking at here.  Lots of noqa,
# because PEP8 quite reasonably assumes we're loading these for use in
# this file, not for other files to import from this module.

# Ocata+
import neutron_lib.api.definitions.portbindings as portbindings  # noqa: F401

# Newton+
from neutron_lib import context  # noqa: F401

# Ocata+
import neutron_lib.api.definitions.provider_net as n_provider  # noqa: F401

# Mitaka+
import neutron_lib.constants as n_const  # noqa: F401
import neutron_lib.exceptions as n_exc  # noqa: F401

# Plugin (service extension) types
import neutron_lib.plugins.constants as plugin_constants  # noqa: F401

# Queens+
from neutron_lib.callbacks import events  # noqa: F401
from neutron_lib.callbacks import registry  # noqa: F401
from neutron_lib.callbacks import resources  # noqa: F401

# Newton+
import neutron_lib.db.model_base as model_base  # noqa: F401
import neutron_lib.plugins.directory as directory  # noqa: F401

# (for, specifically, get_random_mac)
# Newton+:
from neutron_lib.utils import net as net_utils  # noqa: F401

# Between Pike and Queens
from neutron_lib.plugins.ml2 import api as driver_api  # noqa: F401


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
