#!/usr/bin/python

#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Host

from stratum import StratumBmv2Switch

CPU_PORT = 253


class RoutedHost(Host):
    """Host that can be configured with multiple IP addresses."""

    def __init__(self, name, ips, gw, gw_mac, *args, **kwargs):
        super(RoutedHost, self).__init__(name, *args, **kwargs)
        self.ips = ips
        self.gateway = gw
        self.gateway_mac = gw_mac

    def config(self, **kwargs):
        Host.config(self, **kwargs)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        for ip in self.ips:
            self.cmd('ip addr add %s dev %s' % (ip, self.defaultIntf()))
        self.cmd('ip route add default via %s' % self.gateway)
        self.cmd('ip neigh add %s dev %s lladdr %s'
                 % (self.gateway, self.defaultIntf(), self.gateway_mac))


class CustomTopo(Topo):
    """2x2 topology"""

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # gRPC ports assigned from 50001
        # Leaves
        # 50001
        leaf1 = self.addSwitch('leaf1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # 50002
        leaf2 = self.addSwitch('leaf2', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # Spines
        # 50003
        spine1 = self.addSwitch('spine1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # 50004
        spine2 = self.addSwitch('spine2', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # Switch Links
        self.addLink(spine1, leaf1)
        self.addLink(spine1, leaf2)
        self.addLink(spine2, leaf1)
        self.addLink(spine2, leaf2)

        # IPv6 hosts attached to leaf 1
        h1a = self.addHost('h1a', mac="00:00:00:00:00:1A", cls=RoutedHost,
                           ips=["10.0.1.1/24"],
                           gw="10.0.1.100", gw_mac="00:aa:00:00:00:01")
        h1b = self.addHost('h1b', mac="00:00:00:00:00:1B", cls=RoutedHost,
                           ips=["10.0.1.2/24"],
                           gw="10.0.1.100", gw_mac="00:aa:00:00:00:01")
        h1c = self.addHost('h1c', mac="00:00:00:00:00:1C", cls=RoutedHost,
                           ips=["10.0.1.3/24"],
                           gw="10.0.1.100", gw_mac="00:aa:00:00:00:01")

        h2 = self.addHost('h2', mac="00:00:00:00:00:20", cls=RoutedHost,
                          ips=["10.0.2.1/24"],
                          gw="10.0.2.100", gw_mac="00:aa:00:00:00:01")
        self.addLink(h1a, leaf1)  # port 3
        self.addLink(h1b, leaf1)  # port 4
        self.addLink(h1c, leaf1)  # port 5
        self.addLink(h2, leaf1)  # port 6

        # IPv6 hosts attached to leaf 2
        h3 = self.addHost('h3', mac="00:00:00:00:00:30", cls=RoutedHost,
                          ips=["10.0.3.1/24"],
                          gw="10.0.3.100", gw_mac="00:aa:00:00:00:02")
        h4 = self.addHost('h4', mac="00:00:00:00:00:40", cls=RoutedHost,
                          ips=["10.0.4.1/24"],
                          gw="10.0.4.100", gw_mac="00:aa:00:00:00:02")
        self.addLink(h3, leaf2)  # port 3
        self.addLink(h4, leaf2)  # port 4

def do_gratuitousArp(self, line):
    for host in self.mn.hosts:
        for ip_prefix in host.ips:
            ip = ip_prefix.split("/")[0]
            print "Gratuitous %s IP %s" % (host, ip)
            host.cmd("arping -c 1 -P -U %s" % (ip, ))

CLI.do_gratuitousArp = do_gratuitousArp
def main():
    net = Mininet(topo=CustomTopo(), controller=None)
    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel('info')
    main()
