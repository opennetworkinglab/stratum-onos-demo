# P4 source code

This directory contains the P4 program used in the demo. The main file is
`max.p4`, named after its creator, Max.

## Steps to build max.p4

We provide a set of make-based commands to conveniently build `max.p4` for the
different targets used by this project, such as Tofino, FPM (Broadcom Tomahawk),
and BMv2. To build for all targets:

    make build

Compiled artifacts can be found under `./build`

### Prerequisites

The Makefile uses a containerized version of the different p4c backends for each
target, so the only prerequisites are:

* Docker
* `make`

### Make commands

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make build`        | Build max.p4 for all targets (under `./build`)         |
| `make clean`        | Removes any previously compiled artifact               |
| `make bmv2`         | Build for BMv2 (under `./build/bmv`)                   |
| `make tofino`       | Build for Tofino (under `/build/tofino`)               |
| `make p4i-start`    | Starts the Tofino p4i visualization tool               |
| `make p4i-stop`     | Stops the p4i container                                |