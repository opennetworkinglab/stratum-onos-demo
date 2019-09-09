# Instructions to run the demo

## 1. Start Stratum on switches

Manually start the docker container for stratum_bf and stratum_bcm

## 2. Build P4 program and app

#### Clone and build ONOS

```
git clone https://github.com/opennetworkinglab/onos.git
export ONOS_ROOT=<path-to-onos-dir>
source $ONOS_ROOT/tools/dev/bash_profile
cd $ONOS_ROOT
bazel build onos
```

#### Build P4 program

For all backends

```
cd p4src
make build
```

#### Build app

check app/README.md for detailed instructions

```
cd app
mvn clean package
```

## 3. Run ONOS

You have to options to run ONOS: in single-instance local mode (good for
development) or in cluster mode.

###  Demo with local ONOS (for development)

#### Start ONOS in local mode

```
ONOS_APPS=gui,drivers,drivers.stratum,drivers.barefoot,generaldeviceprovider,netcfghostprovider,lldpprovider,proxyarp,route-service ok clean debug
```

#### Set packet I/O log level to trace
```
log:set TRACE org.onosproject.provider.p4runtime.packet.impl
log:set TRACE org.onosproject.drivers.p4runtime.P4RuntimePacketProgrammable
```

#### Load app and netcfg

On a second terminal window:

```
cd app/
onos-app localhost reinstall! target/fabric-demo-1.0-SNAPSHOT.oar
cd ../demo
onos-netcfg localhost netcfg.json
```

#### Send gratuitous ARP reply from hosts

To send gratuitous ARP to the switch, use follow command from hosts:
```
arping -c 1 -P -U [Host IP]
```

### Demo with ONOS cluster

Execute steps 2 in the demo server (bazel-cache).

#### Verify cell configuration

We use 3 LXC containers to deploy ONOS. The IP address of each container is
configured in cell_profile.sh (`OC1`, `OC2`, `OC3`).

The containers use DHCP, so after rebooting the server you shoulod make sure
cell_profile.sh has the right addresses.

To verify the address:
```
lxc info onos1
lxc info onos2
lxc info onos3
```

#### Deploy ONOS

```bash
source cell_profile.sh
stc setup
stc demo-setup.xml
```

### Use network namespace to emulate hosts of the topology

To create network namespace and bind interface to it, modify the `netns.sh` script to use
correct network interfaces, we are using these ports for this demo:

```
ens1f0
ens1f1
ens6f0
ens6f1
```

To start network namespaces, use `./netns.sh start` to start them.

To attach a network namespace, you can use `sudo ip netns exec [ns name] bash` to run bash shell in
specific network namespace.

To remove all network namespaces, use `./nents.sh stop` command.

### Use Pktgen with DPDK to generate the traffic

### Requirements

 - DPDK: [19.05.0](http://core.dpdk.org/download/)
 - Pktgen: [3.6.5](https://git.dpdk.org/apps/pktgen-dpdk/)

After DPDK and Pktgen build and installed, setup path of DPDK and Pktgen before use `dpdk-dev.sh` and `pktgen.sh` script

```bash
export DPDK_ROOT=[DPDK dir]
export PKTGEN_ROOT=[Pktgen dir]
```

Use `./dpdk-dev.sh status` to check NICs, modify `pktgen.sh` and `dpdk-dev.sh` to use correct PCIe device, here we are using these 4 devices which represent 4 40G QSFP ports:

```
0000:03:00.0
0000:03:00.1
0000:83:00.0
0000:83:00.1
```

And use `./dpdk-dev.sh bind` command to bind network interfaces to DPDK driver.

### Start packet generator

Use `pktgen.sh` to start the pktgen shell with default settings.

You can also cutomize packets to generate by modifying the `pktgen.pkt` file.

To start the traffic on all ports:

```
pktgen> start 0-3
```

If hosts did not detect by the ONOS, run the following command to generate ARPs:

```
pktgen> start 0-3 arp gratuitous
```

### Stop DPDK and packet generator

Type `quit` in pktgen shell to stop all traffic and bring down interfaces.

To unbind the DPDK, use `./dpdk-dev.sh unbind` command, which resets the driver for all ports.
