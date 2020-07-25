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

# Some constants and verifier functions have been deprecated but are still
# used by earlier releases of neutron. In order to maintain
# backwards-compatibility with stable/mitaka this will act as a translator
# that passes constants and functions according to version number.

# neutron_lib has a bunch of hacking checks explicitly to ensure that
# newer versions of mech drivers don't go loading Neutron files.
# Obviously, since we're trying to achieve backward compatibility, we
# do precisely that - but that should only happen in this file.  The
# no-qa comments are to allow that to work.

try:
    # Ocata+
    import neutron_lib.api.definitions.portbindings
    portbindings = neutron_lib.api.definitions.portbindings

except ImportError:
    import neutron.extensions.portbindings  # flake8: noqa: N530
    portbindings = neutron.extensions.portbindings

try:
    # Newton+
    import neutron_lib.context
    context = neutron_lib.context
except ImportError:
    import neutron.context
    context = neutron.context


try:
    from neutron_lib.api.definitions import provider_net as n_provider
except ImportError:
    # Newton, at least, has this:
    from neutron.extensions import providernet as n_provider  # noqa: F401

try:
    # Mitaka+
    import neutron_lib.constants
    import neutron_lib.exceptions

    n_const = neutron_lib.constants
    n_exc = neutron_lib.exceptions

except ImportError:
    import neutron.common.constants  # noqa: N530
    import neutron.common.exceptions  # noqa: N530

    n_const = neutron.common.constants
    n_exec = neutron.common.exceptions

# Some of the TYPE_XXX objects also moved in Pike/Queens
if hasattr(n_const, 'TYPE_FLAT'):
    plugin_constants = n_const
else:
    import neutron.plugins.common.constants
    plugin_constants = neutron.plugins.common.constants

try:
    n_const.UUID_PATTERN
except AttributeError:
    HEX_ELEM = '[0-9A-Fa-f]'
    n_const.UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                                     HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                                     HEX_ELEM + '{12}'])

try:
    from neutron.callbacks import events
    from neutron.callbacks import registry
    from neutron.callbacks import resources
except ImportError:
    # Queens+
    from neutron_lib.callbacks import events  # noqa: F401
    from neutron_lib.callbacks import registry  # noqa: F401
    from neutron_lib.callbacks import resources  # noqa: F401

try:
    # Newton+
    import neutron_lib.db.model_base
    import neutron_lib.plugins.directory

    model_base = neutron_lib.db.model_base
    directory = neutron_lib.plugins.directory

except ImportError:
    import neutron.db.model_base  # noqa: N530
    import neutron.manager  # noqa: N530

    directory = neutron.manager.NeutronManager
    model_base = neutron.db.model_base

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

try:
    # Newton
    n_const.L3
except AttributeError:
    try:
        n_const.L3 = plugin_constants.L3_ROUTER_NAT
    except AttributeError:
        # Rocky
        n_const.L3 = neutron_lib.plugins.constants.L3


try:
    # (for, specifically, get_random_mac)
    # Newer:
    from neutron_lib.utils import net as net_utils
    if not hasattr(net_utils, 'get_random_mac'):  # Check for Newton
        raise AttributeError
except (ImportError, AttributeError):
    # Older:
    from neutron.common import utils as net_utils
assert hasattr(net_utils, 'get_random_mac') is True

try:
    from neutron.plugins.ml2 import driver_api
except ImportError:
    # Between Pike and Queens
    from neutron_lib.plugins.ml2 import api as driver_api  # noqa: F401
