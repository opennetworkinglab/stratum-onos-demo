netcfg_url := http://localhost:8181/onos/v1/network/configuration/
onos_curl := curl -sSL --user onos:rocks --noproxy localhost

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

mn-cli:
	docker-compose exec mininet screen -Urx -S cli

mn-log:
	docker-compose logs -f mininet

netcfg:
	${onos_curl} -X POST -H 'Content-Type:application/json' ${netcfg_url} -d@netcfg.json

reset: stop
	-rm -rf ./tmp