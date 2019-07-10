# Mininet-based test network

This directory contains scripts to run a local test network using a
Docker-based environment with Mininet, the `stratum_bmv2` software switch, and
ONOS.

## Prerequisites

* Docker v17+ (with `docker-compose`)
* `make`

## Network topology

The file [topo.py](topo.py) defines a 2x2 fabric topology using the
`StratumBMv2Switch` custom Mininet switch class provided by the official
[Stratum Mininet Docker image][mn-stratum] (see [stratum.py][stratum.py]).

The file [netcfg.json](netcfg.json) defines the corresponding configuration
needed by ONOS to discover and control all 4 switch instances.

## Make commands

We provide a set of make-based commands to control the different aspects of the
test network.

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make build`        | Build/pull all Docker images                           |
| `make start`        | Start test network containers (`mininet` and `onos`)   |
| `make stop`         | Stops and remove all containers                        |
| `make onos-cli`     | Access the ONOS CLI (password: `rocks`, Ctrl+D to exit)|
| `make mn-cli`       | Access the Mininet CLI (Ctrl+A + Ctrl+D to exit)       |
| `make onos-log`     | Shows the ONOS log                                     |
| `make mn-log`       | Shows the Mininet log (i.e., the CLI output)           |
| `make app-reload`   | Load the app in ONOS (TODO unimplemented)              |
| `make netcfg`       | Pushes netcfg.json file (network config) to ONOS       |
| `make reset`        | Resets the tutorial environment                        |

## Walktrough

To get started, use the following commands to start the test network and show
the ONOS log:

```bash
make start
make onos-log
```

Wait for ONOS to complete boot, i.e. until the ONOS log stops showing new
messages.

On a second terminal window, push the netcfg file:

```bash
make netcfg
```

You should see the ONOS log updating with messages showing discovery of the 4
`stratum_bmv2` switches and links. To verify that all switches have been
discovered, use the ONOS CLI:

```bash
make onos-cli
```

```
onos@root > devices -s                                                                                                                                                                                                                                           00:16:51
id=device:leaf1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.onosproject.pipelines.basic
id=device:leaf2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.onosproject.pipelines.basic
id=device:spine1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.onosproject.pipelines.basic
id=device:spine2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.onosproject.pipelines.basic
```

### ONOS web UI

You can access the ONOS web UI at the following address:

<http://localhost:8181/onos/ui/login.html>

Use `onos`/`rocks` to log in.

### stratum_bmv2 logs

The log of eachstratum_bmv2 instance can be found under `./tmp` in this
directory. For example, the log of switch instance `leaf1` will be at
`./tmp/leaf1/stratum_bmv2.log`

For more information on all files found under `./tmp` refers to [mn-stratum
documentation][mn-stratum-tmp].


[mn-stratum]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet
[stratum.py]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet/stratum.py
[mn-stratum-tmp]: https://github.com/opennetworkinglab/stratum/tree/master/tools/mininet#logs-and-other-temporary-files