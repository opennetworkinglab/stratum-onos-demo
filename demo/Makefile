
netns-start: pktgen-stop
	./netns.sh start

netns-stop:
	./netns.sh stop

bind-dpdk:
	./dpdk-dev.sh bind

unbind-dpdk:
	./dpdk-dev.sh unbind

pktgen: netns-stop bind-dpdk
	./pktgen.sh
