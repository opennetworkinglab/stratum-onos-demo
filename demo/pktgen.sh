#!/bin/bash
set -x
export PKTGEN_ROOT=${PKTGEN_ROOT:-$HOME/pktgen-3.6.5}

# -l: Core list
# -n: number of channels
# --proc-type: type of process
# -w: Add PCI devie in white list
# --
# -P: Enable PROMISCUOUS mode on all ports
# -T: Enable the color output
# --crc-strip: strip CRC on all ports
# -m: [rx core:tx core].port
# -f: Command file
# -l: Log file
sudo -E $PKTGEN_ROOT/app/x86_64-native-linuxapp-gcc/app/pktgen \
        -l 0,1-4,11-14 \
        -n 4 \
        --proc-type auto \
        -w 0000:83:00.0 \
        -w 0000:83:00.1 \
        -w 0000:03:00.0 \
        -w 0000:03:00.1 \
        -- \
        -P -T --crc-strip \
        -m [1:2].0 \
        -m [3:4].1 \
        -m [11:12].2 \
        -m [13:14].3 \
        -f pktgen.pkt \
        -l /tmp/pktgen.log
