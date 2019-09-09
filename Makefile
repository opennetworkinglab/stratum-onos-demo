
onos:
	ONOS_APPS=gui,drivers,drivers.stratum,drivers.barefoot,generaldeviceprovider,netcfghostprovider,lldpprovider,proxyarp,route-service ok clean debug

onos-app:
	onos-app localhost reinstall! app/target/fabric-demo-1.0-SNAPSHOT.oar

onos-netcfg:
	onos-netcfg localhost netcfg/5x3.json

router-setup:
	sudo arp -s 10.0.5.100 00:aa:00:00:00:05
	sudo ip r add 10.0.1.0/24 via 10.0.5.100
	sudo ip r add 10.0.2.0/24 via 10.0.5.100
	sudo ip r add 10.0.3.0/24 via 10.0.5.100
	sudo ip r add 10.0.4.0/24 via 10.0.5.100
	sudo arping -c 3 -P -U 10.0.5.1

iptables-nat:
	sudo iptables -t nat -I POSTROUTING -j MASQUERADE

