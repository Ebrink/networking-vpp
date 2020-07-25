#!/usr/bin/env python
#
# Copyright (c) 2019 Cisco Systems, Inc.
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
#    Usage: Run this script to generate the API manifest CRC file
#           python api_manifest_generator.py

import fnmatch
from networking_vpp import constants as nvpp_const
import os
from oslo_serialization import jsonutils
from vpp_papi import VPPApiClient


def get_vpp_api_files():
    """Return a list of VPP api json files from the apidir. """
    jsonfiles = []
    for root, dirnames, filenames in os.walk('/usr/share/vpp/api/'):
        for filename in fnmatch.filter(filenames, '*.api.json'):
            jsonfiles.append(os.path.join(root, filename))
    return jsonfiles


class VPPApiManifest(VPPApiClient):
    def __init__(self, apifiles=get_vpp_api_files()):
        super(VPPApiManifest, self).__init__(apifiles)

    def get_vpp_api_manifest(self):
        """Generate the VPP API manifest data."""
        data = []
        for name, msg in self.messages.items():
            n = name + '_' + msg.crc[2:]
            data.append(n)
        return data

    def write_vpp_api_manifest(self, filename=nvpp_const.API_MANIFEST_FILE):
        """Write the VPP API manifest file."""
        data = self.get_vpp_api_manifest()
        with open(filename, 'w') as f:
            jsonutils.dump(data, f)


if __name__ == '__main__':
    print("Writing VPP API manifest file:", nvpp_const.API_MANIFEST_FILE)
    VPPApiManifest().write_vpp_api_manifest()
