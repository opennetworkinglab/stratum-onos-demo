#!/bin/bash
set -x

function check_and_add_netns {
  ip netns list | grep $1
  if [ $? == 0 ]; then
    ip netns del $1
  fi

  ip netns add $1
}

function exec_cmd_in_netns {
    ns=$1
    shift
    ip netns exec $ns $@
}

function bind_iface_to_netns {
    ip link set $1 netns $2
    exec_cmd_in_netns $2 ip a add $3 dev $1
    exec_cmd_in_netns $2 ip r add default via $4
    exec_cmd_in_netns $2 ip link set dev $1 up
}

check_and_add_netns h1
check_and_add_netns h2
check_and_add_netns h3
check_and_add_netns h4

# To leaf1 FP 49 (Inventec)
bind_iface_to_netns ens6f0 h1 10.0.1.1/24 10.0.1.100
bind_iface_to_netns ens1f0 h2 10.0.2.1/24 10.0.2.100
bind_iface_to_netns ens1f1 h3 10.0.2.2/24 10.0.2.100
bind_iface_to_netns ens6f1 h4 10.0.3.1/24 10.0.3.100