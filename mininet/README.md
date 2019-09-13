# Mininet-based test network

This directory contains scripts to run a local test network using a Docker-based
environment with Mininet, the `stratum_bmv2` software switch, and ONOS. This is
a convenient way to test the P4 program and ONOS app used in this demo.

## Prerequisites

* Docker v17+ (with `docker-compose`)
* `make`

## Network topology

The file [topo.py](topo/topo.py) defines a 2x2 fabric topology using the
`StratumBMv2Switch` custom Mininet switch class provided by the official
[Stratum Mininet Docker image][mn-stratum] (see [stratum.py][stratum.py]).

The file [netcfg.json](topo/netcfg.json) defines the corresponding configuration
needed by ONOS to discover and control all 4 switch instances.

## Make commands

We provide a set of make-based commands to control the different aspects of the
test network.

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make pull`         | Pull all Docker images                                 |
| `make start`        | Start test network containers (`mininet` and `onos`)   |
| `make stop`         | Stops and remove all containers                        |
| `make onos-cli`     | Access the ONOS CLI (password: `rocks`, Ctrl+D to exit)|
| `make onos-ui`      | Shows the ONOS UI (user: `onos` pw: `rocks`)           |
| `make mn-cli`       | Access the Mininet CLI (Ctrl+A + Ctrl+D to exit)       |
| `make onos-log`     | Shows the ONOS log                                     |
| `make mn-log`       | Shows the Mininet log (i.e., the CLI output)           |
| `make app-reload`   | Load the app in ONOS (TODO unimplemented)              |
| `make netcfg`       | Pushes netcfg.json file (network config) to ONOS       |
| `make app-reload`   | Builds and load the fabric app in ONOS                 |
| `make reset`        | Resets the tutorial environment                        |

## Walktrough

To get started, use the following commands to start the test network and show
the ONOS log (make sure to pull the latest images):

```bash
make pull
make start
make onos-log
```

Wait for ONOS to complete boot, i.e. until the ONOS log stops showing new
messages.

On a second terminal window, load the ONOS apps:

```bash
make app-reload
```

This command will first build the ONOS app under `/app`, then load the artifacts
in ONOS. You should see the log updating with messages regarding the loading of
the app and pipeconf registration.

Push the netcfg file:

```bash
make netcfg
```

You should see the ONOS log updating with messages showing discovery of the 4
`stratum_bmv2` switches and links. To verify that all switches have been
discovered, use the ONOS CLI:

```bash
make onos-cli
```

Make sure that all 4 switches have been discovered and ONOS is connected to
them:

```
onos> devices -s
id=device:leaf1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.stratumproject.fabric-demo
id=device:leaf2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.stratumproject.fabric-demo
id=device:spine1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.stratumproject.fabric-demo
id=device:spine2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.stratumproject.fabric-demo
```

Show links, there should be 8 (unidirectional), automatically discovered by
means of LLDP-based packet-in/out performed by the `lldpprovider` app:

```
onos> links
src=device:leaf1/1, dst=device:spine1/1, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf1/2, dst=device:spine2/1, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf2/1, dst=device:spine1/2, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf2/2, dst=device:spine2/2, type=DIRECT, state=ACTIVE, expected=false
src=device:spine1/1, dst=device:leaf1/1, type=DIRECT, state=ACTIVE, expected=false
src=device:spine1/2, dst=device:leaf2/1, type=DIRECT, state=ACTIVE, expected=false
src=device:spine2/1, dst=device:leaf1/2, type=DIRECT, state=ACTIVE, expected=false
src=device:spine2/2, dst=device:leaf2/2, type=DIRECT, state=ACTIVE, expected=false
```

Show port information, obtained by ONOS by querying the OpenConfig Interfaces
model of each switch using gNMI:

```
onos> ports -s
```

Show port counters, also obtained by querying the OpenConfig Interfaces model
via gNMI:

```
onos> portstats
```

Check the flow rules inserted by the ONOS apps. To check just the count for
each switch:

```
onos> flows -c
```

You can also dump all flows for a given switch:

```
onos> flows -s any device:leaf1
```

Similarly, you can check the groups installed for a given switch:

```
onos> groups any device:leaf1
```

ONOS groups are used to abstract P4Runtime action profile groups, multicast
groups, and clone session groups.

It is finally time to test connectivity between the hosts of our Mininet
network. To access the Mininet CLI (Ctrl-A Ctrl-D to exit):

```bash
make mn-cli
```

On the Mininet prompt, start a ping between `h1a` and `h1b`:

```
mininet> h1a ping h1b
PING 10.0.1.2 (10.0.1.2) 56(84) bytes of data.
64 bytes from 10.0.1.2: icmp_seq=1 ttl=64 time=1010 ms
64 bytes from 10.0.1.2: icmp_seq=2 ttl=64 time=6.82 ms
64 bytes from 10.0.1.2: icmp_seq=3 ttl=64 time=2.84 ms
...
```

Ping should work! If you examine the ONOS log you should notice messages about
the discovery of these two hosts. This is achieved by cloning ARP requests to
the control plane by means of P4Runtime packet-in.

Execute the following ONOS command to verify that hosts are discovered:

```
onos> hosts -s
```

`h1a` and `h1b` are connnected to the same leaf and they belong to the same
subnet. For this reason their packets are bridged

Let's now try to ping hosts on different leaves/subnets.

```
mininet> h1a ping h4
```

The **ping should NOT work**, and the reason is that ONOS doesn't know the
location of `h4`, and as such it has not installed the necessary rules to
forward packets. In our configuration, ONOS only learns host information from
ARP requests intercepted in the network. Indeed, while ONOS just learned the
location of `h1a` and `h1b` because of the ARP packets exchanged between these
two, `h4` is on a different subnet, hence no ARP exchange happens between `h1a`
and `h4`. Moreover, since we do not support replying to ARP requests for the
fabric interface IP address, we have configured hosts in mininet with static ARP
entries. As such, `h4` will not even try to resolve the MAC address of its
gateway.

The only option is to have `h4` generate an ARP packet. Use `gratuitousArp` command
to make all hosts generate ARP packets so ONOS can learn the location from them.

```
mininet> gratuitousArp
```

In the ONOS log, you should see messages showing that the location of every hosts has
been discovered. Let's try again pinging from `h1a`:

```
mininet> h1a ping h4
```

It should work now.

### ONOS web UI

You can access the ONOS web UI at the following address:

<http://localhost:8181/onos/ui/login.html>

Use `onos`/`rocks` to log in.

### stratum_bmv2 logs

The log of each `stratum_bmv2` instance can be found under `./tmp` in this
directory. For example, the log of switch instance `leaf1` will be at
`./tmp/leaf1/stratum_bmv2.log`

For more information on all files found under `./tmp` refers to [mn-stratum
documentation][mn-stratum-tmp].


[mn-stratum]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet
[stratum.py]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet/stratum.py
[mn-stratum-tmp]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet#logs-and-other-temporary-files
