#!/bin/bash
# Test whether we can bind a port on VLAN, Trunk, Flat & GPE networks
# Tests VPP vpp-agent resync

OS_USERNAME=${OS_USERNAME:-admin}
OS_PROJECT_NAME=${OS_PROJECT_NAME:-admin}
DEVSTACK_DIR=${HOME}/devstack
source $DEVSTACK_DIR/functions
source $DEVSTACK_DIR/stackrc

# Export the cirros image ID value
IMAGE_ID=${IMAGE_ID}
# m1.tiny flavor is the default
FLAVOR_ID=${FLAVOR_ID:-1}

# NETWORK TEST CONTROL VARIABLES
# Vlan Physnet
VLAN_PHYSNET=${VLAN_PHYSNET:-physnet}
FLAT_PHYSNET=${FLAT_PHYSNET:-"physnet-flat"}


source ~/devstack/openrc $OS_USERNAME $OS_PROJECT_NAME

# Returns 0 if the VM is active, else returns 1
# Exists if the vm is in error state
# $1: vm_name
function check-vm-active {
    echo "Checking if VM $1 has become ACTIVE"
    VM_STATE=$(openstack server show $1 | grep status | awk '{print $4}')
    if  [[ "${VM_STATE}" = 'ACTIVE' ]]; then
      echo "VM $1 is ACTIVE"
      return 0
    elif [[ "${VM_STATE}" = 'ERROR' ]]; then
      echo "VM $1 is in *ERROR* state"
      exit
    else
      return 1
    fi
  }

# Returns 0 if the VM is not found, else returns 1
# $1: vm_name
function check-vm-delete {
    echo "Checking if VM $1 exists"
    VM_STATE=$(openstack server show $1)
    if  [[ -z "${VM_STATE}" ]]; then
      echo "VM $1 is DELETED"
      return 0
    else
      return 1
    fi
  }

# Check if the interface is plugged into the bridge domain
# $1          :  interface e.g. VirtualEthernet0/0/1
# $2          :  bridge_domain_id
# $3(optional): segmentation_id of the interface (for trunk ports)
function check-interface-in-bridge {
    # vhostuser interface (untagged) default case
    local INTERFACE="$1"

    # vhostuser trunk port
    if [[ -n "$3" && "$1" =~ "VirtualEthernet" ]]; then
      INTERFACE="${INTERFACE}.${3}"
    # untagged tap1 interface
    elif [[ -z "$3" && "$1" = "tap" ]]; then
      INTERFACE="tap1"
    fi

    PLUGGED_INTERFACE=$(sudo vppctl show bridge-domain $2 detail | grep -i ${INTERFACE} | awk '{print $1}')
    if  [[ "${PLUGGED_INTERFACE}" = ${INTERFACE} ]]; then
      echo "Interface $INTERFACE is *IN* the bridge_domain $2"
      return 0
    else
      echo "Interface $INTERFACE is *NOT* in bridge_domain $2"
      return 1
    fi
  }

# $1: VM name
# Returns true if the VM exists
function exists-server {
   server="$(openstack server list | grep $1 | awk '{print $4}')"
   if [[ $server = $1 ]]; then
     return 0
   else
     return 1
   fi
}

# Boot a VM on a network, ensure it's active and has an IP
# $1: vm_name
# $2: network_name
# $3: port_id (optional)
function boot-vm {
    local addresses
    # Wait time in seconds for the VM to become active
    local WAIT_FOR_VM_ACTIVE=30s
    local USE_PORT_ID="False"

    if exists-server "$1"; then
       echo "VM $1 exists"
       return 1
    fi
    # boot using port_id
    if [[ -n "$3" ]]; then
      USE_PORT_ID="True"
    fi

    if [[ "$USE_PORT_ID" == "False" ]]; then
      echo "Booting VM $1 on network $2"
      openstack server create --flavor $FLAVOR_ID --image $IMAGE_ID --network $2 $1
    else
      echo "Booting VM $1 using PORT_ID $3"
      openstack server create --flavor $FLAVOR_ID --image $IMAGE_ID --nic port-id=$3 $1
    fi

    export -f check-vm-active
    if ! timeout $WAIT_FOR_VM_ACTIVE bash -c "until check-vm-active $1; do sleep 1; done"; then
       echo "Error: VM $1 did not become ACTIVE after $WAIT_FOR_VM_ACTIVE"
       exit 1
    fi


    addresses=$(openstack server show -c addresses -f value $1)
    ip=$(echo $addresses | sed -n "s/^.*$2=\([0-9\.]*\).*$/\1/p")
    if [[ $ip = "" ]]; then
      echo "VM $1 could not get an ip address"
      exit 1
    fi
    echo "VM $1 got IP: $ip"
}

# Delete a VM
# $1: vm_name
function delete-vm {
  # Wait time in seconds for the VM to be deleted
  local WAIT_FOR_VM_DELETE=30s

  if exists-server "$1"; then
    echo "Deleting VM $1"
    openstack server delete $1
    export -f check-vm-delete
    if ! timeout $WAIT_FOR_VM_DELETE bash -c "until check-vm-delete $1; do sleep 1; done"; then
       echo "Error: VM $1 could not be DELETED after $WAIT_FOR_VM_DELETE"
       exit 1
    fi
  fi
}

# $1: network name
# Returns true if the network exists
function exists-network {
   network="$(openstack network list | grep $1 | awk '{print $4}')"
   if [[ $network = $1 ]]; then
     return 0
   else
     return 1
   fi
}

# $1: subnet name
# Returns true if the subnet exists
function exists-subnet {
   subnet="$(openstack subnet list | grep $1 | awk '{print $4}')"
   if [[ $subnet = $1 ]]; then
     return 0
   else
     return 1
   fi
}

# $1 = Network Name
# $2 = Network Type (vlan, flat)
function create-network {
   local network_name="$1"
   local network_type="$2"

   if exists-network "$network_name"; then
      echo "Network $network_name exists"
      return 1
   fi

   if [[ "$network_type" = "vlan" ]]; then
     echo "Creating a vlan network $network_name using physnet $VLAN_PHYSNET"
     openstack network create --provider-physical-network $VLAN_PHYSNET --provider-network-type vlan $network_name
   elif [[ "$network_type" = "flat" ]]; then
     echo "Creating a flat network $network_name using physnet $FLAT_PHYSNET"
     openstack network create --provider-physical-network $FLAT_PHYSNET --provider-network-type flat $network_name
  # default network type is gpe
   elif [[ "$network_type" = "gpe" || -z "$network_type" ]]; then
    echo "Creating a gpe network $network_name"
    openstack network create $network_name
   fi
   openstack network list
}

# $1 = Network Name
function delete-network {
  local network_name="$1"

  if exists-network "$network_name"; then
     echo "Deleting network $network_name"
     openstack network delete $network_name
  fi
}

# $1 = Subnet Name
# $2 = CIDR
# $3 = Network Name
function create-subnet {
  local subnet_name="$1"
  local cidr="$2"
  local network_name="$3"

  if exists-subnet "$subnet_name"; then
     echo "Subnet $subnet_name exists"
     return 1
  fi

  echo "Creating subnet $subnet_name using cidr $cidr for network $network_name"
  openstack subnet create --subnet-range $cidr --network $network_name $subnet_name
  openstack subnet list
}

# $1 = Subnet Name
function delete-subnet {
  local subnet_name="$1"

  if exists-subnet "$subnet_name"; then
    echo "Deleting subnet $subnet_name"
    openstack subnet delete $subnet_name
  fi
}

function ensure_uplink_in_vpp {
    echo "Ensuring uplink:tap0 in VPP"
    uplink="tap0"
    if ! [[ `vppctl show interface` =~ "$uplink" ]] && [[ "$uplink" =~ 'tap0' ]]; then
        echo "tap0 not found in vppctl show interface"
        # by default, vpp will internally name the first tap device 'tap0'
        vppctl create tap host-if-name test
        vppctl set interface state tap0 up
    fi
}

# Ensures 3 vlan networks and subnets are present
function ensure-vlan-nets {
  create-network vnet1 vlan
  create-subnet subnet-vnet1 "11.1.1.0/24" vnet1
  create-network vnet2 vlan
  create-subnet subnet-vnet2 "11.2.2.0/24" vnet2
  create-network vnet3 vlan
  create-subnet subnet-vnet3 "11.3.3.0/24" vnet3
}

function delete-vlan-nets {
  delete-subnet subnet-vnet1
  delete-network vnet1
  delete-subnet subnet-vnet2
  delete-network vnet2
  delete-subnet subnet-vnet3
  delete-network vnet3
}

function test-vlan {
  # Ensures 3 Vlan networks
  # Boots a VM in each of these networks
  ensure-vlan-nets
  boot-vm vm-vnet1 vnet1
  boot-vm vm-vnet2 vnet2
  boot-vm vm-vnet3 vnet3
  openstack server list
}

function cleanup-vlan {
  # Cleans up all resources created by test-vlan
  delete-vm vm-vnet1
  delete-vm vm-vnet2
  delete-vm vm-vnet3
  delete-vlan-nets
}

function test-flat {
  # Creates a flat network/subnets
  # Boot a VM
  # Ensures that the VM is active
  create-network fnet flat
  create-subnet subnet-fnet "11.4.4.0/24" fnet
  boot-vm vm-fnet fnet
  openstack server list
}

function cleanup-flat {
  # Cleans up all resources created by test-flat
  delete-vm vm-fnet
  openstack server list
  delete-subnet subnet-fnet
  delete-network fnet
}

function test-gpe {
  # Creates two gpe networks/subnets
  # Boot a VM in each
  # Checks if the VMs are active
  create-network gpe-net1 gpe
  create-subnet subnet-gpe1 "11.5.5.0/24" gpe-net1
  boot-vm vm-gpe-net1 gpe-net1
  openstack server list

  create-network gpe-net2 gpe
  create-subnet subnet-gpe2 "11.6.6.0/24" gpe-net2
  boot-vm vm-gpe-net2 gpe-net2
  openstack server list
}

function cleanup-gpe {
  # Cleans up all resources created by test-flat
  delete-vm vm-gpe-net1
  openstack server list
  delete-subnet subnet-gpe1
  delete-network gpe-net1

  delete-vm vm-gpe-net2
  openstack server list
  delete-subnet subnet-gpe2
  delete-network gpe-net2
}


function show-status-after-cleanup {
  echo "Status after cleaning up.."
  openstack subnet list
  openstack network list
  sudo vppctl show int
  sudo vppctl show bridge
}


function check-running-vpp {
    VPP_PIDS=$(pgrep -d, -x vpp_main)
    if  [[ "${VPP_PIDS}" != "" ]]; then
      echo "VPP is currently running with PIDs:$VPP_PIDS"
      return 0
    else
      return 1
    fi
  }

function stop-vpp-agent {
   if is_service_enabled vpp-agent; then
     echo "Stopping Networking VPP Agent"
     stop_process vpp-agent
   fi
}

function start-vpp-agent {
   if is_service_enabled vpp-agent; then
     echo "Starting Networking VPP Agent"
     local NEUTRON_CONF="/etc/neutron/neutron.conf"
     run_process vpp-agent "/usr/local/bin/vpp-agent --config-file $Q_PLUGIN_CONF_FILE --config-file $NEUTRON_CONF"
   fi
}

function stop-vpp {
   if $SYSTEMCTL is-enabled vpp.service; then
     if check-running-vpp; then
       echo "Stopping VPP Service"
       $SYSTEMCTL stop vpp.service
     else
       echo "stop-vpp: VPP is not running"
     fi
   else
     echo "VPP is not enabled"
     exit 1
   fi
}

function start-vpp {
   if ! check-running-vpp; then
     echo "Starting VPP Service"
     $SYSTEMCTL start vpp.service
   else
     echo "start-vpp: VPP is already running"
   fi
}

function test-vpp-agent {
  # Tests whether the VPP agent is active
  VPP_AGENT_ACTIVE=$(sudo systemctl --state=active list-units devstack@vpp-agent.service | grep devstack@vpp-agent.service)
  if [[ -n $VPP_AGENT_ACTIVE ]]; then
    echo "VPP agent restarted successfully"
    return 0
  else
    echo "Networking-vpp agent failed to start"
    exit 1
  fi
}

function test-resync {
  # Tests if the VPP agent can successfully restart without errors
  # Case1: Restart VPP -> Ensure uplink -> Restart VPP-agent
  echo "Testing Resync..restarting VPP"
  stop-vpp
  start-vpp
  until check-running-vpp; do
    echo "Waiting for VPP to start"
    sleep 1
  done
  ensure_uplink_in_vpp
  stop-vpp-agent
  start-vpp-agent
  test-vpp-agent
  # Case2: Restart-agent -> Check Status
  echo "Test Resyncing..restarting VPP-agent"
  stop-vpp-agent
  start-vpp-agent
  test-vpp-agent
}

# Return 0 if the port exists, else return 1
# $1 = port_name
function exists-port {
  local port_name=$1
  exists=$(openstack port show $port_name -c name -f value)
  if [[ -n $exists ]]; then
    return 0
  else
    return 1
  fi
}

# Return 0 if the trunk exists, else return 1
# $1 = trunk_name
function exists-trunk {
  local trunk_name=$1
  exists=$(openstack network trunk show $trunk_name -c name -f value)
  if [[ -n $exists ]]; then
    return 0
  else
    return 1
  fi
}

# Create a trunk + sub-ports & bind a VM
function test-trunk {
  local trunk_name="trunk1"
  local trunk_port_name="trunk1-port1"
  local subport1_name="trunk1-subport1"
  local subport2_name="trunk1-subport2"
  local trunked_vm_name="trunked-vm1"
  # Ensure VLAN networks(vnet1, vnet2 & vnet3) & corresponding subnets exist
  ensure-vlan-nets
  # Create trunk parent port on vnet1
  if ! exists-port $trunk_port_name; then
      openstack port create --network vnet1 $trunk_port_name
  fi
  trunk_port_id=$(openstack port show $trunk_port_name -c id -f value)
  # Create trunk with the above parent port if it a conflicting name does not exist
  if ! exists-trunk $trunk_name; then
      echo "Creating trunk $trunk_name with parent port $trunk_port_id"
      openstack network trunk create --parent-port $trunk_port_id $trunk_name
      echo "Created trunk $trunk_name"
      openstack network trunk list
      # Create Subports on vnet2 & vnet3
      echo "Creating trunk subports($subport1_name, $subport2_name) for trunk $trunk_name on networks vnet2 and vnet3"
      if ! exists-port $subport1_name; then
        openstack port create --network vnet2 $subport1_name
      fi
      if ! exists-port $subport2_name; then
        openstack port create --network vnet3 $subport2_name
      fi
      # Add subport to existing trunk
      echo "Adding subports to trunk $trunk_name with segmentation ids, 11 & 12"
      openstack network trunk set --subport port=${subport1_name},segmentation-type=vlan,segmentation-id=11 $trunk_name
      openstack network trunk set --subport port=${subport2_name},segmentation-type=vlan,segmentation-id=12 $trunk_name
  else
      echo "Trunk $trunk_name exists"
  fi
  openstack network trunk show $trunk_name
  # Boot an instance on the trunk port
  boot-vm $trunked_vm_name vnet1 $trunk_port_id
}

function cleanup-trunk {
  local trunk_name="trunk1"
  local trunk_port_name="trunk1-port1"
  local subport1_name="trunk1-subport1"
  local subport2_name="trunk1-subport2"
  local trunked_vm_name="trunked-vm1"

  echo "Deleting trunked instance $trunked_vm_name"
  delete-vm $trunked_vm_name

  echo "Unsetting subports from trunk $trunk_name"
  openstack network trunk unset --subport $subport1_name $trunk_name
  openstack network trunk unset --subport $subport2_name $trunk_name
  echo "Deleting trunk $trunk_name"
  openstack network trunk delete $trunk_name
  echo "Deleting trunk ports and subports"
  openstack port delete $trunk_port_name
  openstack port delete $subport1_name
  openstack port delete $subport2_name
  delete-vlan-nets
}

ensure_uplink_in_vpp
### Enable the tests you'd like to run below ###
# test-vlan
# test-flat
# test-gpe
# test-trunk
test-resync

## Cleanup Test runs
# cleanup-vlan
# cleanup-gpe
# cleanup-flat
# cleanup-trunk
# show-status-after-cleanup
