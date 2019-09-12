ONOS_VERSION := 2.2.0
ONOS_APPS := gui,drivers,drivers.stratum,drivers.barefoot,generaldeviceprovider,netcfghostprovider,lldpprovider,proxyarp,route-service

onos_url := http://localhost:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost
app_name := org.stratumproject.fabric-demo

onos-start:
	$(info *** Starting ONOS container...)
	docker run --rm -d -e ONOS_APPS=${ONOS_APPS} -p 8181:8181 -p 8101:8101 \
		--name onos onosproject/onos:${ONOS_VERSION}

onos-kill:
	$(info *** Stopping ONOS container...)
	docker stop -t0 onos

onos-log:
	docker logs -f onos

onos-cli:
	$(info *** Password: "rocks". Ctrl-D to exit...)
	@ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o LogLevel=ERROR -p 8101 onos@localhost

app-install:
	$(info *** Installing and activating app in ONOS...)
	${onos_curl} -X POST -HContent-Type:application/octet-stream \
		'${onos_url}/v1/applications?activate=true' \
		--data-binary @../app/target/fabric-demo-1.0-SNAPSHOT.oar
	@echo

app-uninstall:
	$(info *** Uninstalling app from ONOS (if present)...)
	-${onos_curl} -X DELETE ${onos_url}/v1/applications/${app_name}
	@echo

netcfg:
	$(info *** Pushing netcfg.json to ONOS...)
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/v1/network/configuration -d@./netcfg.json
	@echo

router-setup:
	sudo arp -s 10.0.5.100 00:aa:00:00:00:05
	sudo ip r add 10.0.1.0/24 via 10.0.5.100
	sudo ip r add 10.0.2.0/24 via 10.0.5.100
	sudo ip r add 10.0.3.0/24 via 10.0.5.100
	sudo ip r add 10.0.4.0/24 via 10.0.5.100
	sudo arping -c 3 -P -U 10.0.5.1

iptables-nat:
	sudo iptables -t nat -I POSTROUTING -j MASQUERADE

