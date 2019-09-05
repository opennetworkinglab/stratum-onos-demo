#!/bin/bash
export DPDK_ROOT=${DPDK_ROOT:-$HOME/dpdk}

function bind {
    sudo modprobe uio
    sudo insmod $DPDK_ROOT/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
    sudo dpdk-devbind --bind=igb_uio 0000:83:00.0
    sudo dpdk-devbind --bind=igb_uio 0000:83:00.1
    sudo dpdk-devbind --bind=igb_uio 0000:03:00.0
    sudo dpdk-devbind --bind=igb_uio 0000:03:00.1
}

function unbind {
    sudo dpdk-devbind -b i40e 0000:83:00.0
    sudo dpdk-devbind -b i40e 0000:83:00.1
    sudo dpdk-devbind -b i40e 0000:03:00.0
    sudo dpdk-devbind -b i40e 0000:03:00.1
}

function status {
    dpdk-devbind --status
}

case $1 in
  bind)
    bind
  ;;
  unbind)
    unbind
  ;;
  status)
    status
  ;;
  *)
    echo "Usage $0 [bind|unbind|status]"
  ;;
esac