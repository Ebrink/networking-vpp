Port mirroring support
======================

Networking vpp supports remote port mirroring. This functionality
is intended to be used for debugging and troubleshooting.

For this purpose, networking-vpp implements a driver for the extension
neutron/tap-as-a-service
(https://opendev.org/x/tap-as-a-service/).

================================================================================
1. Installation
- Install the neutron extension: openstack/tap-as-a-service
NB: In order to use the ERSPAN mode, you need to use the "customized version" of tap-as-a-service that supports ERSPAN. 
It is available here: https://github.com/jbeuque/tap-as-a-service

- Update the ml2 plugin configuration files
Add the following lines to the ML2 configuration
(likely /etc/neutron/plugins/ml2/ml2_conf.ini) on any hosts running
VPP and its agent (e.g. compute hosts):

    [ml2_vpp]
    driver_extensions = taas_driver
    vpp_agent_extensions = taas_agent

- Update the taas configuration
Add the following lines to the ML2 configuration on the Neutron server:

    [service_providers]
    service_provider = TAAS:TAAS:networking_vpp.taas_vpp.TaasEtcdDriver:default

- ERSPAN mode
In order to use the ERSPAN mode for tap as a service, the parameters esp_physnet and esp_src_cidr have to 
be added in the ml2 plugin configuration file. esp_src_cidr is the source address of the ERSpan tunnels for the
compute node. esp_physnet is the physical interface to be used for the ERSPAN external mode.
	[ml2_vpp]
	physnets = physnet1:TenGigabitEthernet9/0/0,physnet2:TenGigabitEtherneta/0/0
	esp_physnet = physnet2
	esp_src_cidr = 10.1.2.10/24


================================================================================
2. Usage
See the documentation of Tap as a service
(https://opendev.org/x/tap-as-a-service/).  This
implements the standard service API.

----------------------
ERSPAN mode:
* In order to use the ERSPAN mode, you need to use the "customized version" of tap-as-a-service that supports ERSPAN.

usage: neutron tap-service-create [-h] [-f {json,shell,table,value,yaml}]
                                  [-c COLUMN] [--max-width <integer>]
                                  [--fit-width] [--print-empty] [--noindent]
                                  [--prefix PREFIX] [--tenant-id TENANT_ID]
                                  [--name NAME] [--description DESCRIPTION]
                                  [--port PORT]
                                  [--erspan_dst_ip ERSPAN_DST_IP]


tap-service examples:
	a/ ERSPAN external mode
		The destination is outside of Openstack. The tap service doesn't have any port_id but an erspan destination IP address.
	neutron tap-service-create --erspan_dst_ip 10.1.2.3

	b/ ERSPAN internal mode
		The destination is a port of an openstack VM. The tap service has both a port_id and an erspan destination IP address.
	neutron tap-service-create --port 837e40d1-6458-442e-8386-bf6799f1d89f --erspan_dst_ip 10.1.2.3
----------------------
usage: neutron tap-flow-create [-h] [-f {json,shell,table,value,yaml}]
                               [-c COLUMN] [--max-width <integer>]
                               [--fit-width] [--print-empty] [--noindent]
                               [--prefix PREFIX] [--tenant-id TENANT_ID]
                               [--name NAME] [--description DESCRIPTION]
                               --port SOURCE_PORT --tap-service TAP_SERVICE
                               --direction DIRECTION
                               [--erspan_session_id ERSPAN_SESSION_ID]

tap-flow example:
neutron tap-flow-create --port 0f576381-e461-4807-bb11-5d57624b30a0 --tap-service 51d17137-241d-47db-a28b-d62d0e631205 --erspan_session_id 234 --direction BOTH

================================================================================
3. Known Limitations
- Live migration is not supported by this version.
- vxlan support is currently preliminary.

