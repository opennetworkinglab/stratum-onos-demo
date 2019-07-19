app_name := org.stratumproject.fabric-demo
onos_url := http://localhost:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost

build:
	docker-compose build mininet
	docker-compose pull onos

start:
	docker-compose up -d

stop:
	docker-compose down -t0

restart: stop start

onos-cli:
	ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -p 8101 onos@localhost

onos-log:
	docker-compose logs -f onos

onos-ui:
	open ${onos_url}/ui

mn-cli:
	docker-compose exec mininet screen -Urx -S cli

mn-log:
	docker-compose logs -f mininet

netcfg:
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/v1/network/configuration -d@./topo/netcfg.json

app-reload: app-build app-uninstall app-install

app-build:
	cd ../app && mvn clean package

app-install:
	${onos_curl} -X POST -HContent-Type:application/octet-stream \
		'${onos_url}/v1/applications?activate=true' \
		--data-binary @../app/target/fabric-demo-1.0-SNAPSHOT.oar

app-uninstall:
	${onos_curl} -X DELETE ${onos_url}/v1/applications/${app_name}

reset: stop
	-rm -rf ./tmp