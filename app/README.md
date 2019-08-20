# Fabric demo ONOS app

This directory contain the implementation of the ONOS app used in the Stratum
fabric demo.

## Steps to build the app

### Prerequisites

* Apache Maven (`brew install maven` if on macOS)
* [JDK 11](https://www.azul.com/downloads/zulu-community/)

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