#!/usr/bin/env bash

set -xe

CPU_PORT=253
GRPC_PORT=28000

./veth_setup.sh

INTFS=
for idx in 0 1 2 3 4 5 6 7; do
    ptfPort=${idx}
    vethIdx=$(( 2*${idx} + 1 ))
    INTFS="${INTFS} -i${ptfPort}@veth${vethIdx}"
done

#stratum_bmv2 \
#    --device_id=1 \
#    --forwarding_pipeline_configs_file=/dev/null \
#    --persistent_config_dir=/dev/null \
#    --initial_pipeline=/root/dummy.json \
#    --cpu_port=${CPU_PORT} \
#    --external-hercules-urls=0.0.0.0:${GRPC_PORT} \
#    --logtosyslog=false \
#    --logtostderr=true \
#    ${INTFS} > stratum_bmv2.log 2>&1

simple_switch_grpc \
    --device-id 1 \
    ${INTFS} \
    --log-console \
    -Ltrace \
    --no-p4 \
    -- \
    --cpu-port ${CPU_PORT} \
    --grpc-server-addr 0.0.0.0:${GRPC_PORT} \
    > bmv2.log 2>&1
