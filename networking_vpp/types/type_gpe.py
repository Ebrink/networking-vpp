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

from itertools import chain

from networking_vpp.compat import db_context_writer
from networking_vpp import config_opts
from networking_vpp import constants as nvpp_const
from networking_vpp.db.models import GpeAllocation
from networking_vpp import exceptions as nvpp_exc

from neutron_lib import context as n_context
import neutron_lib.exceptions as n_exc
from neutron_lib.plugins.ml2 import api as driver_api

from neutron.plugins.ml2.drivers import helpers

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging

from typing import List, Set, Tuple

LOG = logging.getLogger(__name__)


class GpeVNIAllocator(object):
    """An allocator class for managing GPE VNI allocation.

    This class manages the allocation of GPE VNIs.
    GPE has a large pool of allocatable VNIs i.e. 2 ** 24 - 1. (16+ Million).
    The prior implementation uses an approach in which each unallocated VNI
    is stored in the neutron DB for allocation. This class optimizes the
    GPE VNI allocation by generating valid VNIs from the VNI range
    specified by the user and thereby storing only the allocated GPE VNIs
    in the Neutron DB.
    """

    def __init__(self, model: GpeAllocation, vni_ranges: List[str]):
        """Initialize a sequence of GPE VNI range iterables.

        :param: model: The GpeAllocation model object
        :param: vni_ranges:
        A sequence of GPE VNI strings available for allocation on
        GPE segments. Each string item in the sequence has the
        format: start:end, denoting the starting and ending values of
        VNIs for allocation on GPE networks.
        e.g. '1000:2000', '2500:10000'
        """
        # The GPE Allocation model
        self.model = model
        # VNI range string sequences
        self.vni_ranges = vni_ranges
        LOG.debug("GPE VNI allocator has initialized")

    def _parse_gpe_vni_ranges(self) -> List[Tuple[int, int]]:
        """Parses the input GPE VNI range string.

        :returns: A list of tuples of integer gpe vni ranges.
        """
        vnis = []
        for entry in self.vni_ranges:
            try:
                min_vni, max_vni = entry.strip().split(':')
                vni_range = int(min_vni.strip()), int(max_vni.strip())
                self.verify_gpe_vnis(*vni_range)
                vnis.append(vni_range)
            except nvpp_exc.GpeVNIInvalid:
                raise nvpp_exc.GpeVNIRangeError(vni_range=self.vni_ranges)
        return vnis

    def verify_gpe_vnis(self, *vnis: int) -> None:
        """Verify if the GPE VNI is valid.

        Throws an exception if input is not suitable as a GPE VNI.

        :param: vnis: Integer that should be VNIs
        """

        for vni in vnis:
            if not (nvpp_const.MIN_GPE_VNI <= vni
                    <= nvpp_const.MAX_GPE_VNI):
                raise nvpp_exc.GpeVNIInvalid(vni_id=vni)

    def get_vni_ranges(self):
        """Returns a list of gpe_vni_range iterables.

        :returns: A list of GPE vni range iterables.
        Each iterable is of object type range.
        """
        return [range(vni_range[0], vni_range[1] + 1) for vni_range
                in self._parse_gpe_vni_ranges()]

    def get_allocatable_vni(self):
        """Returns a VNI that's allocatable on a tenant network

        Returns None if no allocatable GPE VNIs are found.
        """
        # Return the first available VNI that is allocatable without
        # expanding the entire GPE VNI range
        allocated_db_vnis = self.allocated_db_vnis()

        # This does steadily get slower as more networks are
        # allocated, but it works and we assume the allocated networks
        # in the DB never gets excessive.
        for vni in chain(*self.get_vni_ranges()):
            if vni not in allocated_db_vnis:
                return vni

    def allocated_db_vnis(self) -> Set[int]:
        """Returns a generator that produces the allocated GPE VNIs.

        Retrieves a DB view of allocated VNIs in the Neutron DB and returns a
        set of it since we're usually trying to work out in/out.
        """
        ctx = n_context.get_admin_context()
        session = ctx.session
        with session.begin(subtransactions=True):
            allocs = (session.query(self.model).filter_by(
                allocated=True).all())

            return set(
                allocated.gpe_vni
                for allocated in allocs)

    def allocate(self, vni=None):
        """Manage the GPE VNI allocation.

        If the vni argument is not None and it's valid, then it is allocated.
        If the vni is None, a valid vni is generated from the user specified
        range and allocated.
        """
        LOG.debug("Allocating a gpe vni..")
        # If a VNI is specified, you're allowed to use it as long as it is
        # ununsed even if it's outside the conventional range.
        if vni and vni not in self.allocated_db_vnis():
            LOG.debug("GPE Type Driver: Allocating a VNI: %s for the "
                      "fully specified segment", vni)
            return vni
        else:
            vni = self.get_allocatable_vni()
            if vni is not None:
                LOG.debug("GPE Type Driver: Allocating a VNI: %s for the "
                          "partially specified segment", vni)
                return vni

        # No valid VNIs to allocate
        LOG.error("GPE Type Driver: Could not find a valid vni to "
                  "allocate")
        raise nvpp_exc.GpeVNIUnavailable()


class GpeTypeDriver(helpers.SegmentTypeDriver):
    """A GPE network type driver.

    This class implements a type driver for tenant networks
    of type GPE. This driver is responsible for managing the
    VNI allocations and deallocations from a pool of VNIs.
    It enables overlay network connectivity between tenant
    instances using the GPE protocol.
    """

    def __init__(self):
        super(GpeTypeDriver, self).__init__(GpeAllocation)
        self.initialize()

    def get_type(self):
        return nvpp_const.TYPE_GPE

    def initialize(self):
        try:
            config_opts.register_vpp_opts(cfg.CONF)
            self.segmentation_key = next(iter(self.primary_keys))
            self.gpe_vni_allocator = GpeVNIAllocator(
                self.model,
                cfg.CONF.ml2_vpp.gpe_vni_ranges)
        except nvpp_exc.GpeVNIRangeError:
            LOG.exception("Failed to parse gpe_vni_range from config. "
                          "Service terminated!")
            raise SystemExit()

    def is_partial_segment(self, segment):
        return segment.get(driver_api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        network_type = segment.get(driver_api.NETWORK_TYPE)
        segmentation_id = segment.get(driver_api.SEGMENTATION_ID)
        # Ensure that segment only had those two settings in it
        for key, value in segment.items():
            if value and key not in [driver_api.NETWORK_TYPE,
                                     driver_api.SEGMENTATION_ID]:
                msg = (("%(key)s prohibited for %(gpe)s network"),
                       {'key': key,
                        'gpe': network_type})
                raise n_exc.InvalidInput(error_message=msg)

        if segmentation_id is not None:
            self.gpe_vni_allocator.verify_gpe_vnis(segmentation_id)
        else:
            raise nvpp_exc.GpeVNIInvalid(vni_id=None)

    def allocate_fully_specified_segment(self, context, **raw_segment):
        """Allocate a segment fully specified by the raw_segment.

        Fetch the fully specified GPE segment (i.e. with a user
        specified GPE VNI_ID) from the allocation pool allocate it
        in the Neutron DB. If successful, return the DB allocation object.
        Else, return None.
        """
        network_type = self.get_type()
        session = context.session
        # Release segment from mem pool prior to allocating it in the DB
        gpe_vni = raw_segment['gpe_vni']
        seg_id = self.gpe_vni_allocator.allocate(gpe_vni)
        if seg_id is None:
            LOG.error('Failed to allocate the specified GPE segment ID %s ',
                      gpe_vni)
            return
        try:
            with db_context_writer.using(context):
                alloc = (
                    session.query(self.model).filter_by(**raw_segment).
                    first())
                if alloc:
                    if alloc.allocated:
                        # Segment already allocated in the DB
                        return
                    else:
                        # Segment not allocated in the DB
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "started ",
                                  {"type": network_type,
                                   "segment": raw_segment})

                        count = (session.query(self.model).
                                 filter_by(allocated=False, **raw_segment).
                                 update({"allocated": True}))
                        if count:
                            LOG.debug("%(type)s segment %(segment)s allocate "
                                      "done ",
                                      {"type": network_type,
                                       "segment": raw_segment})
                            return alloc

                        # Segment allocated or deleted since select
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "failed: segment has been allocated or "
                                  "deleted",
                                  {"type": network_type,
                                   "segment": raw_segment})

                # Segment to create in the DB
                LOG.debug("%(type)s segment %(segment)s create started",
                          {"type": network_type, "segment": raw_segment})
                alloc = self.model(allocated=True, **raw_segment)
                alloc.save(session)
                LOG.debug("%(type)s segment %(segment)s create done",
                          {"type": network_type, "segment": raw_segment})
                return alloc

        except db_exc.DBDuplicateEntry:
            # Segment already allocated (insert failure)
            alloc = None
            LOG.debug("%(type)s segment %(segment)s create failed",
                      {"type": network_type, "segment": raw_segment})

    def allocate_partially_specified_segment(self, context, **filters):
        """Allocate a segment partially specified by the raw_segment.

        Allocate an ML2 GPE segment from the pool and save it in the
        database.
        If successful, return the allocated DB object.
        Return None if a segment cannot be allocated.
        """
        network_type = self.get_type()
        session = context.session
        LOG.debug('Allocating a partially specified GPE segment '
                  'from pool')
        segmentation_id = self.gpe_vni_allocator.allocate()
        if segmentation_id is None:
            LOG.error('Failed to allocate a GPE segment ID')
            return

        with db_context_writer.using(context):
            raw_segment = {self.segmentation_key: segmentation_id}
            alloc = (
                session.query(self.model).filter_by(**raw_segment).
                first())
            # The VNI is present in the DB, update its allocation
            if alloc and not alloc.allocated:
                (session.query(self.model).
                 filter_by(allocated=False, **raw_segment).
                 update({"allocated": True}))
            # Create a new allocation
            elif not alloc:
                alloc = self.model(allocated=True, **raw_segment)
                alloc.save(session)
                LOG.debug("%(type)s segment %(segment)s create done",
                          {"type": network_type, "segment": raw_segment})
            # We should never run into this state
            else:
                LOG.error("Could not allocate segment %s as it is already "
                          "allocated in the DB", segmentation_id)
                alloc = None
            return alloc

    def reserve_provider_segment(self, session, segment, filters=None):
        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(session,
                                                              **filters)
            if not alloc:
                raise n_exc.NoNetworkAvailable()
        else:
            segmentation_id = segment.get(driver_api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                session, **{self.segmentation_key: segmentation_id})
            if not alloc:
                raise nvpp_exc.GpeVNIInUse(vni_id=segmentation_id)

        return {driver_api.NETWORK_TYPE: self.get_type(),
                driver_api.PHYSICAL_NETWORK: None,
                driver_api.SEGMENTATION_ID: getattr(alloc,
                                                    self.segmentation_key),
                driver_api.MTU: self.get_mtu()}

    def allocate_tenant_segment(self, session, filters=None):
        alloc = self.allocate_partially_specified_segment(session,
                                                          **filters)
        if not alloc:
            return
        return {driver_api.NETWORK_TYPE: self.get_type(),
                driver_api.PHYSICAL_NETWORK: None,
                driver_api.SEGMENTATION_ID: getattr(alloc,
                                                    self.segmentation_key),
                driver_api.MTU: self.get_mtu()}

    def release_segment(self, context, segment):
        vni_id = segment[driver_api.SEGMENTATION_ID]
        LOG.debug('Releasing GPE segment %s', vni_id)

        info = {'type': self.get_type(), 'id': vni_id}
        with db_context_writer.using(context):
            query = (context.session.query(self.model).
                     filter_by(**{self.segmentation_key: vni_id}))
            count = query.delete()
        if count:
            LOG.debug("Releasing %(type)s VNI %(id)s", info)
        else:
            LOG.warning("Released %(type)s VNI %(id)s was not allocated", info)

    def get_allocation(self, context, gpe_vni_id):
        return (context.session.query(self.model).
                filter_by(**{self.segmentation_key: gpe_vni_id}).first())

    def get_mtu(self, physical_network=None):
        mtu = super(GpeTypeDriver, self).get_mtu()
        return mtu - nvpp_const.GPE_ENCAP_OVERHEAD if mtu else 0

    def initialize_network_segment_range_support(self):
        """Required from Train onwards."""
        pass   # We compute VNI allocations dynamically

    def update_network_segment_range_allocations(self):
        """Required from Train onwards."""
        pass   # We compute VNI range allocations dynamically
