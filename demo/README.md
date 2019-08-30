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

#### Load app and netcfg

On a second terminal window:

```
cd app/
onos-app localhost reinstall! target/fabric-demo-1.0-SNAPSHOT.oar
cd ../demo
onos-netcfg localhost netcfg.json
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
