# Fabric demo P4 program

This directory contains the P4 program used in the demo. 

## Steps to build main.p4

We provide a set of make-based commands to conveniently build `main.p4` for the
different targets used in the demo, such as Tofino, FPM (Broadcom Tomahawk),
and BMv2. To build for all targets:

    make build

Compiled artifacts can be found under `./build`

### Prerequisites

The Makefile uses a containerized version of the different p4c backends for each
target, so the only prerequisites are.

* Docker
* `make`

**Note on the Tofino backend**: The Docker image with the p4c backend for Tofino
is not public. If you want to re-use the same Makefile, you should update that
variable `bf_sde_img` with a Docker image that contains a full installation of
the Barefoot SDE, or just the `p4c-compilers` package.

### Make commands

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make build`        | Build main.p4 for all targets (under `./build`)        |
| `make clean`        | Removes any previously compiled artifact               |
| `make bmv2`         | Build for BMv2 (under `./build/bmv`)                   |
| `make tofino`       | Build for Tofino (under `/build/tofino`)               |
| `make fpm`          | Build for Tofino (under `/build/fpm`)                  |