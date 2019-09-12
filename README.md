# Stratum Interoperability Demo

This repo contains code and scripts to reproduce the demo presented at ONF
Connect 2019.

The demo shows Stratum running on whitebox switches from different vendors,
using silicon such as Barefoot Tofino and Broadcom Tomahawk. Switches are
interconnected in a leaf-spine fabric topology, while ONOS is used as the
control plane.

The repo is organized as follows:

* `demo/`: demo script and instructions
* `p4src/`: P4 program and build scripts for bmv2, Tofino and FPM (Broadcom)
* `app/`: ONOS app implementation providing the control plane of the fabric
