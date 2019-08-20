export ONOS_APPS=gui,drivers,drivers.stratum,drivers.barefoot,generaldeviceprovider,netcfghostprovider,lldpprovider,proxyarp

export ONOS_USER=ubuntu
export ONOS_GROUP=ubuntu
export ONOS_INSTALL_DIR=/opt/onos
export ONOS_WEB_PASS=rocks
export ONOS_WEB_USER=onos
export ONOS_NIC="10.128.100.*"
export OC1=10.128.100.58
export OC2=10.128.100.59
export OC3=10.128.100.60
export OCN=""

export OCI=$OC1
export OCC1=$OC1
export OCC2=$OC2
export OCC3=$OC3
export ONOS_INSTANCES="$OC1 $OC2 $OC3"

export stcDumpLogs=true