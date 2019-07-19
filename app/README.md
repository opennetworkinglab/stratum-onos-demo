# Fabric demo ONOS app

This directory contain the implementation of the ONOS app used in the Stratum
fabric demo.

## Steps to build the app

### Prerequisites

* Bazel 0.27.0
* Apache Maven (`brew install maven` if on macOS)
* [JDK 11](https://www.azul.com/downloads/zulu-community/)

### Publish ONOS artifacts locally

Since we build the app against an unreleased version fo ONOS (master), we first
need to seed our Maven environment with ONOS artifacts. You will need to do this
only once, before building the app. Once ONOS 2.2 will be released, there will
be no need of doing that, since artifacts will be downloaded by Maven.

Execute the following steps:

```
git clone https://github.com/opennetworkinglab/onos.git
cd onos
bazel build onos
source tools/dev/bash_profile
onos-publish
cd tools/package/maven-plugin/
mvn clean install
```

### Build P4 program

The compiled app will include the P4 compiler output for the different targets.
For this reason, we first need to build the P4 program:

```
cd p4src
make build
```

The P4 build artifacts are symlinked under `app/src/main/resources/p4c-out`.

### Build app

```
cd app
mvn clean package
```