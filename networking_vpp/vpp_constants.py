# Copyright (c) 2020 Cisco Systems, Inc.
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

###############################################################################
#                               VPP constants                                 #
#                                                                             #
# These are the various constants spread across L2, L3, NAT, ACLs and so on   #
# that are required in the VPP API calls and other places.                    #
###############################################################################

L2_VTR_POP_1 = 3
L2_VTR_DISABLED = 0
NO_BVI_SET = 4294967295

L2_LEARN = (1 << 0)
L2_FWD = (1 << 1)
L2_FLOOD = (1 << 2)
L2_UU_FLOOD = (1 << 3)
L2_ARP_TERM = (1 << 4)

# Port not in bridge
L2_API_PORT_TYPE_NORMAL = 0
# Port in bridge
L2_API_PORT_TYPE_BVI = 1

# 19.08 onwards:
# Here's the complete NAT related enums for reference and for future. We just
# need few for now.
#
# enum nat_config_flags : u8
# {
#   NAT_IS_NONE = 0x00,
#   NAT_IS_TWICE_NAT = 0x01,
#   NAT_IS_SELF_TWICE_NAT = 0x02,
#   NAT_IS_OUT2IN_ONLY = 0x04,
#   NAT_IS_ADDR_ONLY = 0x08,
#   NAT_IS_OUTSIDE = 0x10,
#   NAT_IS_INSIDE = 0x20,
#   NAT_IS_STATIC = 0x40,
#   NAT_IS_EXT_HOST_VALID = 0x80,
# };
ADDR_ONLY = 0x08
IS_OUTSIDE = 0x10
IS_INSIDE = 0x20
IS_STATIC = 0x40

# 19.08 onwards:
# Here's the complete FIB_PATH_TYPE defs for reference and for
# future. We just need IPv4 and IPv6 for now.
#
# class FibPathType:
#     FIB_PATH_TYPE_NORMAL = 0
#     FIB_PATH_TYPE_LOCAL = 1
#     FIB_PATH_TYPE_DROP = 2
#     FIB_PATH_TYPE_UDP_ENCAP = 3
#     FIB_PATH_TYPE_BIER_IMP = 4
#     FIB_PATH_TYPE_ICMP_UNREACH = 5
#     FIB_PATH_TYPE_ICMP_PROHIBIT = 6
#     FIB_PATH_TYPE_SOURCE_LOOKUP = 7
#     FIB_PATH_TYPE_DVR = 8
#     FIB_PATH_TYPE_INTERFACE_RX = 9
#     FIB_PATH_TYPE_CLASSIFY = 10
ROUTE_NORMAL = 0
ROUTE_LOCAL = 1

# 19.08 onwards:
# Here's the complete FIB_PATH_PROTO related defs for
# reference and for future. We just need few for now.
#
# class FibPathProto:
#     FIB_PATH_NH_PROTO_IP4 = 0
#     FIB_PATH_NH_PROTO_IP6 = 1
#     FIB_PATH_NH_PROTO_MPLS = 2
#     FIB_PATH_NH_PROTO_ETHERNET = 3
#     FIB_PATH_NH_PROTO_BIER = 4
#     FIB_PATH_NH_PROTO_NSH = 5
PROTO_IPV4 = 0
PROTO_IPV6 = 1

# 20.01 onwards:
# In 20.01, sw_interface_set_flags has a new field 'flags' of
# type vl_api_if_status_flags_t which takes the following values:
#
# enum if_status_flags
# {
#   IF_STATUS_API_FLAG_ADMIN_UP = 1,
#   IF_STATUS_API_FLAG_LINK_UP = 2,
# };
IF_ADMIN_UP = 1
IF_ADMIN_DOWN = 0

###############################################################################
#                             VxLAN-GPE constants                             #
###############################################################################
# 20.05 onwards:
# In 20.05, 'eid' is a new bona-fide type of its own, namely,
# vl_api_eid_t, defined as follows in ~vpp/src/vnet/lisp-cp/lisp_types.api:
#
# /* endpoint identifier */
# typedef eid
# {
#   vl_api_eid_type_t type;
#   vl_api_eid_address_t address;
# };
# enum eid_type : u8
# {
#   EID_TYPE_API_PREFIX = 0,
#   EID_TYPE_API_MAC = 1,
#   EID_TYPE_API_NSH = 2,
# };
# union eid_address
# {
#   vl_api_prefix_t prefix;
#   vl_api_mac_address_t mac;
#   vl_api_nsh_t nsh;
# };
#
EID_PREFIX = 0
EID_MAC = 1
EID_NSH = 2
#
# In 20.05, LISP filter type is an enum as defined in
# ~vpp/src/vnet/lisp-cp/lisp.api:
#
# enum lisp_locator_set_filter : u8 {
#   LISP_LOCATOR_SET_FILTER_API_ALL = 0,
#   LISP_LOCATOR_SET_FILTER_API_LOCAL = 1,
#   LISP_LOCATOR_SET_FILTER_API_REMOTE = 2,
# };
#
FILTER_ALL = 0
FILTER_LOCAL = 1
FILTER_REMOTE = 2

###############################################################################
#                                  ERSPAN consts                              #
###############################################################################
# 20.05 onwards:
# In 20.05, SPAN state is defined as an enum defined as follows in
# ~vpp/src/vnet/span/span.api:
#
# enum span_state
# {
#   SPAN_STATE_API_DISABLED = 0,
#   SPAN_STATE_API_RX = 1,
#   SPAN_STATE_API_TX = 2,
#   SPAN_STATE_API_RX_TX = 3,
# };
SPAN_DISABLED = 0,
SPAN_RX = 1,
SPAN_TX = 2,
SPAN_RX_TX = 3,

# GRE tunnel type as defined in ~vpp/src/vnet/gre/gre.api:
# enum gre_tunnel_type : u8
# {
#    GRE_API_TUNNEL_TYPE_L3 = 0,
#    /* L2 Transparent Ethernet Bridge */
#    GRE_API_TUNNEL_TYPE_TEB,
#    /* Encapsulated Remote Switched Port ANalyzer */
#    GRE_API_TUNNEL_TYPE_ERSPAN,
# };
TUNNEL_TYPE_L3 = 0
TUNNEL_TYPE_TEB = 1
TUNNEL_TYPE_ERSPAN = 2

# tunnel_mode and tunnel_encap_decap_flags type as defined in
# ./vnet/tunnel/tunnel_types.api:
#
#  /**
#   * Flags controlling tunnel behaviour
#   */
#  enum tunnel_encap_decap_flags : u8
#  {
#    TUNNEL_API_ENCAP_DECAP_FLAG_NONE = 0,
#    /** at encap, copy the DF bit of the payload into the tunnel header */
#    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF = 0x1,
#    /** at encap, set the DF bit in the tunnel header */
#    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF = 0x2,
#    /** at encap, copy the DSCP bits of the payload into the tunnel header */
#    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP = 0x4,
#    /** at encap, copy the ECN bit of the payload into the tunnel header */
#    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN = 0x8,
#    /** at decap, copy the ECN bit of the tunnel header into the payload */
#    TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN = 0x10,
#  };
#
#  /**
#   * tunnel mode
#   */
#  enum tunnel_mode : u8
#  {
#    /** point-to-point */
#    TUNNEL_API_MODE_P2P = 0,
#    /** multi-point */
#    TUNNEL_API_MODE_MP,
#  };
#
# Note(onong): Just defining what we need. Define the others if/when needed
# in future
TUNNEL_ENCAP_DECAP_NONE = 0
TUNNEL_MODE_P2P = 0
