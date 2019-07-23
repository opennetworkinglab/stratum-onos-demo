#!/usr/bin/env bash

set -e

PTF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
P4SRC_DIR=${PTF_DIR}/../p4src
P4C_OUT=${P4SRC_DIR}/build/bmv2

imageName=ptf-bmv2-`echo ${PTF_DIR} | shasum | cut -c1-7`
runName=${imageName}-${RANDOM}

function stop() {
        echo " Stopping ${runName}..."
        docker stop -t0 ${runName}
}
trap stop INT

# Run and show log (also stored in run.log)
docker build -t ${imageName} -f Dockerfile.bmv2 .

# Start container. Entrypoint starts stratum_bmv2. We put that in the background
# and execute the PTF scripts separately.
docker run --name ${runName} -d --privileged --rm \
    -v ${PTF_DIR}:/ptf -w /ptf \
    -v ${P4C_OUT}:/p4c-out \
    ${imageName} \
    ./entrypoint.sh

sleep 2

set +e

docker exec ${runName} ./ptf_runner.py \
    --device-config /p4c-out/bmv2.json \
    --p4info /p4c-out/p4info.txt \
    --grpc-addr localhost:28000 \
    --device-id 1 \
    --testdir ./ \
    --port-map /ptf/port_map.veth.json $@

stop
