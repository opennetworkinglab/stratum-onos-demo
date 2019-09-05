#!/bin/bash
set -x

function exec_cmd_in_netns {
    ns=$1
    shift
    sudo ip netns exec $ns $@
}

function bind_iface_to_netns {
    sudo ip link set $1 netns $2
    exec_cmd_in_netns $2 ip a add $3 dev $1
    exec_cmd_in_netns $2 ip link set dev $1 up
    exec_cmd_in_netns $2 ip r add default via $4
    exec_cmd_in_netns $2 arp -s $4 $5
}

function check_and_remove_netns {
  sudo ip netns list | grep $1
  if [ $? == 0 ]; then
    sudo ip netns del $1
  fi
}

function start {
  sudo ip -all netns delete
  set -e
  sudo ip netns add h1
  sudo ip netns add h2
  sudo ip netns add h3
  sudo ip netns add h4

  bind_iface_to_netns ens1f0 h1 10.0.1.1/24 10.0.1.100 00:aa:00:00:00:01
  bind_iface_to_netns ens1f1 h2 10.0.2.1/24 10.0.2.100 00:aa:00:00:00:02
  bind_iface_to_netns ens6f0 h3 10.0.3.1/24 10.0.3.100 00:aa:00:00:00:03
  bind_iface_to_netns ens6f1 h4 10.0.4.1/24 10.0.4.100 00:aa:00:00:00:04
}

function stop {
  sudo ip -all netns delete
}

case $1 in
  start)
    start
  ;;
  stop)
    stop
  ;;
  *)
    echo "Usage $0 [start|stop]"
  ;;
esac
