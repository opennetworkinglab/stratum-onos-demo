# Scripts and instructions to run the demo

Before starting:

* Run Stratum on all switches using the chassis config files in
  [./chassis-config](./chassis-config)
* Build P4 program for all targets ([p4src/README.md](../p4src/README.md))
* Build ONOS app ([app/README.md](../app/README.md))

## 1. Start ONOS and connect to switches

Start ONOS

    make onos-start

Install app (and pipeconf):

    make app-install

If the app is already installed and you would like to install a new version, use
`make app-uninstall` first.

Push netcfg file:

    make netcfg

At this point ONOS should have a gRPC connection to all switches, and the demo
app should have installed the necessary flow rules and groups to get
connectivity between all hosts.

## 2. Emulate hosts

To create network namespace and bind interfaces to it, modify the `netns.sh`
script to use interface names on your system.

To create network namespaces, use:

    ./netns.sh start

To execute any command inside the network namespace, use:

    sudo ip netns exec <ns-name> <command>

To discover hosts in ONOS you can send gratuitous ARPs with the following
command, to be executed inside a network namespace:

    arping -c 1 -P -U [Host IP]

To remove all network namespaces, use:

    ./nents.sh stop

## 3. Generate traffic with DPDK pktgen

Download and build:

 - [DPDK 19.05.0](http://core.dpdk.org/download/)
 - [pktgen 3.6.5](https://git.dpdk.org/apps/pktgen-dpdk/)

Set the following environment variables to the directories where DPDK and pktgen
have been extracted: 

    export DPDK_ROOT=[DPDK dir]
    export PKTGEN_ROOT=[pktgen dir]

### Bind NIC interfaces to DPDK

Run this command to get the PCIe device IDs and check the status of attached
NICs:
    
    ./dpdk-dev.sh status

Modify `pktgen.sh` and `dpdk-dev.sh` with the PCIe device IDs you would like to
use for the demo. The current configuration expects 4x 40G interfaces.

Use the following command to bind the devices to the DPDK driver:

    ./dpdk-dev.sh bind

### Start traffic generator

Use `pktgen.sh` to start the pktgen shell with default settings.

You can also customize the generator by modifying the `pktgen.pkt` file.

On the pktgen shell, to start traffic on all ports:

    pktgen> start 0-3

If hosts are not discovered in ONOS, you can run the following command to
generate gratuitous ARPs:

    pktgen> start 0-3 arp gratuitous

Type `quit` in the pktgen shell to stop traffic and bring down interfaces.

To unbind the NIC interfaces from the DPDK driver, use `./dpdk-dev.sh unbind`.
