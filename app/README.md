# Fabric demo ONOS app

This directory contain the implementation of the ONOS app used in the demo.

## Steps to build the app

### Prerequisites

* Docker
* make

### Build P4 program

The compiled app will include the P4 compiler output for the different targets.
For this reason, we first need to build the P4 program:

```
cd p4src
make build
```

The P4 build artifacts are copied under `app/src/main/resources/p4c-out` when
building the app.

### Build app

```
cd app
make build
```