#!/usr/bin/env python2

# Copyright 2019 Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Maximilian Pudelko (max@opennetworking.org)

import ptf
import os
import time
from ptf import config, packet
import ptf.testutils as testutils
from ptf.mask import Mask
from p4.v1 import p4runtime_pb2

from google.rpc import code_pb2

from base_test import P4RuntimeTest, autocleanup, stringify, ipv4_to_binary, mac_to_binary


IPV4_ETHERTYPE = "\x08\x00"
ARP_ETHERTYPE = 0x0806
CPU_PORT_ = "\x00\xfd"
CPU_PORT = 0xfd
CPU_MIRROR_SESSION_ID = 511

DEFAULT_PRIORITY = 10
LOOPBACK_PORT = 13

# Base class with configuration parameters
class ConfiguredTest(P4RuntimeTest):
    def __init__(self):
        super(ConfiguredTest, self).__init__()

    def setUp(self):
        super(ConfiguredTest, self).setUp()
        self.ip_host_a = "10.1.0.1"
        self.ip_host_b = "10.2.0.1"
        self.ip_host_a_str = ipv4_to_binary(self.ip_host_a)
        self.ip_host_b_str = ipv4_to_binary(self.ip_host_b)
        # FIXME make target independent
        self.host_port_a = self.swports(1) # 35 on BCM
        self.host_port_b = self.swports(2) # 34 on BCM
        self.switch_port_a = stringify(1, 2) # 34 on BCM
        self.switch_port_b = stringify(2, 2) # 35 on BCM
        self.switch_port_loopback = stringify(LOOPBACK_PORT, 2)
        self.host_port_a_mac = mac_to_binary("3c:fd:fe:a8:ea:30")
        self.host_port_b_mac = mac_to_binary("3c:fd:fe:a8:ea:31")
        self.switch_port_a_mac = mac_to_binary("00:00:00:aa:aa:aa")
        self.switch_port_b_mac = mac_to_binary("00:00:00:bb:bb:bb")


@testutils.group("bmv2")
class PktIoOutDirectToDataPlaneTest(ConfiguredTest):
    """
    Sent packets directly out of a physical port.
    Skips the ingress pipeline and any processing.
    """
    def testPacket(self, pkt):
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1

        egress_physical_port.value = self.switch_port_a
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, pkt, [self.host_port_a])

        egress_physical_port.value = self.switch_port_b
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, pkt, [self.host_port_b])

    @autocleanup
    def runTest(self):
        pkts = [
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=1500,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=0),
        ]
        for p in pkts:
            self.testPacket(p)

@testutils.group("bmv2")
class PktIoOutToIngressPipelineAclRedirectToPortTest(ConfiguredTest):
    """
    Sent packets out through the ingress pipeline and redirect it to
    a port via an ACL rule.
    """
    def testPacket(self, pkt):
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(0, 1)
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, pkt, [self.host_port_b])

    @autocleanup
    def runTest(self):
        pkts = [
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=1500,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=0),
        ]
        # Redirect ipv4 to port B
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", "\x08\x00", "\xFF\xFF")],
            "set_egress_port",
            [("port", self.switch_port_b)],
            DEFAULT_PRIORITY
        )
        for p in pkts:
            self.testPacket(p)

@testutils.group("bmv2")
class PktIoOutToIngressPipelineAclPuntToCpuTest(ConfiguredTest):
    """
    Sent packets out through the ingress pipeline and punt it back
    to CPU via an ACL rule.
    """
    def testPacket(self, pkt):
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(0, 2)
        self.send_packet_out(pkt_out)
        testutils.verify_no_other_packets(self)
        recv_pkt = self.get_packet_in()

    @autocleanup
    def runTest(self):
        pkts = [
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=1500,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=0),
        ]
        # Redirect ipv4 to CPU
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", "\x08\x00", "\xFF\xFF")],
            "set_queue_and_send_to_cpu",
            [("queue_id", stringify(4, 1))],
            DEFAULT_PRIORITY
        )
        for p in pkts:
            self.testPacket(p)


class PktIoOutToIngressPipelineL3ForwardingTest(ConfiguredTest):
    """
    Sent packets out through the ingress pipeline and forward
    to port with L3 rules.

    Currently broken
    """
    @autocleanup
    def runTestTempDISABLED(self):
        # Admit L2 packets with router MACs
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_b_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create nexthop entries
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_a), ("smac", self.switch_port_a_mac), ("dmac", self.host_port_a_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            2,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        # Create L3 forwarding rules
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            2)
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_a_str, 16)],
            1)

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(0, 2)
        # Check if L3 setup is sound with dataplane packet
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b]) # Breaks here

@testutils.group("bmv2")
class PacketIoOutDirectLoopbackPortAclTest(ConfiguredTest):
    """
    Send a packet directly to loopback port and punt back via ACL.
    """
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)

        # Direct Tx to loopback port
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(LOOPBACK_PORT, 2)

        # Redirect IPv4 to CPU with CoS 4
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", IPV4_ETHERTYPE, "\xff\xff")],
            "set_queue_and_send_to_cpu",
            [("queue_id", stringify(4, 1))],
            DEFAULT_PRIORITY
        )
        self.send_packet_out(pkt_out)
        testutils.verify_no_other_packets(self)
        self.verify_packet_in(pkt, CPU_PORT)

@testutils.group("bmv2")
class PacketIoOutDirectLoopbackL3ForwardingTest(ConfiguredTest):
    """
    Send a packet directly to loopback port and L3 forward it to
    a dataplane port.
    """
    @autocleanup
    def runTest(self):
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create rules to forward to port B
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            1)

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)

        # Direct Tx to loopback port
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(LOOPBACK_PORT, 2)
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])

@testutils.group("bmv2")
class PacketIoOutDirectLoopbackCloneToCpuTest(ConfiguredTest):
    """
    Send a packet directly to loopback port, L3 forward it to
    a dataplane port and clone a copy to CPU.
    """
    @autocleanup
    def runTest(self):
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create rules to forward to port B
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            1)
        # Clone IPv4 to CPU with CoS 4
        self.add_clone_session(CPU_MIRROR_SESSION_ID, [CPU_PORT])
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", IPV4_ETHERTYPE, "\xff\xff")],
            "set_queue_and_clone_to_cpu",
            [("queue_id", stringify(4, 1))],
            DEFAULT_PRIORITY
        )

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)

        # Direct Tx to loopback port
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = stringify(LOOPBACK_PORT, 2)
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])
        self.verify_packet_in(exp_pkt, CPU_PORT)


class PktIoOutDirectToCPUTest(ConfiguredTest):
    """
    Send packets out over CPU and punt them pack to CPU.
    Note: not possible
    """
    def testPacket(self, pkt):
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = self.switch_port_b
        self.send_packet_out(pkt_out)
        recv_pkt = self.get_packet_in()
        testutils.verify_no_other_packets(self, timeout=0.5)

    @autocleanup
    def runTestDISABLED(self):
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", IPV4_ETHERTYPE, "\xff\xff")],
            "set_queue_and_send_to_cpu",
            [("queue_id", stringify(4, 1))]
        )
        # Trap nexthop to CPU
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", CPU_PORT_), ("smac", "\x00\x00\x00\x00\x00\x00"), ("dmac", "\x00\x00\x00\x00\x00\x00"), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", ipv4_to_binary("10.0.0.0"), 8)],
            1)
        testutils.verify_no_other_packets(self, timeout=0.5)

        pkts = [
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=1500,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64),
            testutils.simple_ip_packet(
                pktlen=60,
                eth_src= mac_to_binary("00:00:00:c0:1a:10"), eth_dst=self.host_port_b_mac,
                ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=0),
        ]
        for p in pkts:
            self.testPacket(p)


class RedirectDataplaneToCpuNextHopTest(ConfiguredTest):
    """
    Send packets over dataplane and punt them to CPU via a CPU next hop.
    See: RedirectDataplaneToCpuACLTest
    """
    @autocleanup
    def runTest(self):
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create rules to forward to port B
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        # Trap nexthop to CPU
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            2,
            "ingress.l3_fwd.set_nexthop",
            [("port", CPU_PORT_), ("smac", "\x00\x00\x00\x00\x00\x00"), ("dmac", "\x00\x00\x00\x00\x00\x00"), ("dst_vlan", stringify(1, 2))]
        )
        # UC /8 route to port B
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 8)],
            1)
        # UC /16 route to CPU
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            2)

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_no_other_packets(self)
        recv_pkt = self.get_packet_in(timeout=1)
        print(recv_pkt)


class RedirectDataplaneToDataplaneTest(ConfiguredTest):
    """
    Sent a packet over the dataplane and redirect to another dataplane port.
    """
    @autocleanup
    def runTest(self):
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create rules to forward to port B
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            1)

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])
        testutils.verify_no_other_packets(self)

        # Redirect ipv4 to port A
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", "\x08\x00", "\x08\x00")],
            "set_egress_port",
            [("port", self.switch_port_a)]
        )
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_a])
        testutils.verify_no_other_packets(self)


class RedirectDataplaneToCpuACLTest(ConfiguredTest):
    """
    Sent a packet over the dataplane and punt to CPU via an ACL rule.
    See: RedirectDataplaneToCpuNextHopTest
    """
    @autocleanup
    def runTest(self):
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create rules to forward to port B
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            1)

        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])
        testutils.verify_no_other_packets(self)

        # Redirect IPv4 to CPU with CoS 4
        self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", IPV4_ETHERTYPE, "\xff\xff")],
            "set_queue_and_send_to_cpu",
            [("queue_id", stringify(4, 1))]
        )
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_no_other_packets(self)
        recv_pkt = self.get_packet_in(timeout=1)
        print(recv_pkt)


class L3ForwardTest(ConfiguredTest):
    """
    Bi-directional L3 forwarding between two hosts
    """
    @autocleanup
    def runTest(self):
        # Admit L2 packets with router MACs
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_b_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create nexthop entries
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_a), ("smac", self.switch_port_a_mac), ("dmac", self.host_port_a_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            2,
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )
        # Create L3 forwarding rules
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            2)
        self.send_request_add_entry_to_member(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_a_str, 16)],
            1)
        # Test host A to B
        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_b])
        testutils.verify_no_other_packets(self)
        # Test host B to A
        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_b_mac, eth_dst=self.switch_port_b_mac, ip_src=self.ip_host_b, ip_dst=self.ip_host_a, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_a_mac, eth_dst=self.host_port_a_mac, ip_src=self.ip_host_b, ip_dst=self.ip_host_a, ip_ttl=63)
        testutils.send_packet(self, self.host_port_b, pkt)
        testutils.verify_packets(self, exp_pkt, [self.host_port_a])
        testutils.verify_no_other_packets(self)


class PacketIoOutSpamTest(ConfiguredTest):
    """
    TODO
    Send many packets directly out of a dataplane port.
    """
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)

        # Direct Tx to loopback port
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = self.switch_port_loopback

        # Redirect IPv4 to CPU with CoS 4
        req, resp = self.send_request_add_entry_to_action(
            "ingress.punt.punt_table",
            [self.Ternary("hdr.ethernet.ether_type", IPV4_ETHERTYPE, "\xff\xff")],
            "set_queue_and_send_to_cpu",
            [("queue_id", stringify(4, 1))]
        )

        del_req = self._get_new_write_request()
        del_req.CopyFrom(req)
        for update in del_req.updates:
            if update.type == p4runtime_pb2.Update.INSERT:
                update.type = p4runtime_pb2.Update.DELETE

        for i in range(100):
            self.write_request(del_req, False)
            self.write_request(req, False)

        for i in range(50):
            self.send_packet_out(pkt_out)
            testutils.verify_no_other_packets(self)
            recv_pkt = self.get_packet_in()


class CloneSessionTest(ConfiguredTest):
    """
    TODO
    Canonical way to create a clone session.
    """
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_a_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=64)
        exp_pkt = testutils.simple_ip_packet(
            pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac, ip_src=self.ip_host_a, ip_dst=self.ip_host_b, ip_ttl=63)

        self.add_clone_session(CPU_MIRROR_SESSION_ID, [CPU_PORT])


class L2MulticastTest(ConfiguredTest):
    """
    TODO
    """
    @autocleanup
    def runTest(self):
        mcast_group_id = 100
        # Use different MAC here to prevent collisions with NIC MACs
        mac_src = mac_to_binary("00:00:00:55:55:55")

        self.add_mcast_group(mcast_group_id, [34, 35])

        self.send_request_add_entry_to_action(
            "ingress.mcast.mcast_table",
            # [self.Exact("hdr.ethernet.ether_type", stringify(ARP_ETHERTYPE, 2))],
            [self.Exact("hdr.ethernet.ether_type", stringify(ARP_ETHERTYPE, 2)),
             self.Ternary("hdr.ethernet.src_addr", mac_src, "\xff\xff\xff\xff\xff\xff")],
            "set_mcast_group_id",
            [("group_id", stringify(mcast_group_id, 2))]
        )

        pkt = testutils.simple_eth_packet(
            pktlen=60, eth_type=ARP_ETHERTYPE,
            eth_src=mac_src, eth_dst=self.switch_port_b_mac)

        # Direct Tx to loopback port
        pkt_out = p4runtime_pb2.PacketOut()
        pkt_out.payload = str(pkt)
        egress_physical_port = pkt_out.metadata.add()
        egress_physical_port.metadata_id = 1
        egress_physical_port.value = self.switch_port_loopback
        self.send_packet_out(pkt_out)
        testutils.verify_packets(self, pkt, [self.host_port_a, self.host_port_b])

        # Check ingress port pruning
        testutils.send_packet(self, self.host_port_a, pkt)
        testutils.verify_packets(self, pkt, [self.host_port_b])
        testutils.verify_no_other_packets(self)

        testutils.send_packet(self, self.host_port_b, pkt)
        testutils.verify_packets(self, pkt, [self.host_port_a])
        testutils.verify_no_other_packets(self)


class EcmpTest(ConfiguredTest):
    """
    TODO
    Create ECMP routes & nexthops and send packets over them.
    """
    @autocleanup
    def runTest(self):
        # Admit L2 packets with router MACs
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_a_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        self.send_request_add_entry_to_action(
            "ingress.l3_fwd.l3_routing_classifier_table",
            [self.Ternary("hdr.ethernet.dst_addr", self.switch_port_b_mac, "\xff\xff\xff\xff\xff\xff")],
            "ingress.l3_fwd.set_l3_admit",
            [],
            DEFAULT_PRIORITY
        )
        # Create non-multipath nhops
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            1,  # nhop id
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_a), ("smac", self.switch_port_a_mac), ("dmac", self.host_port_a_mac), ("dst_vlan", stringify(1, 2))]
        )
        self.send_request_add_member(
            "ingress.l3_fwd.wcmp_action_profile",
            2,  # nhop id
            "ingress.l3_fwd.set_nexthop",
            [("port", self.switch_port_b), ("smac", self.switch_port_b_mac), ("dmac", self.host_port_b_mac), ("dst_vlan", stringify(1, 2))]
        )

        # Create ECMP group
        self.send_request_add_group(
            "ingress.l3_fwd.wcmp_action_profile",
            1,   # group id
            128, # max members
            [1, 2]  # nhop members
        )

        # Create L3 forwarding rule to ECMP group
        self.send_request_add_entry_to_group(
            "ingress.l3_fwd.l3_fwd_table",
            [self.Exact("local_metadata.vrf_id", stringify(0, 2)), self.Lpm("hdr.ipv4_base.dst_addr", self.ip_host_b_str, 16)],
            1  # group id
        )

        hits = {}

        for i in range(50):
            ip_src = self.ip_host_a[:-1] + str(i*2)
            pkt = testutils.simple_ip_packet(
                pktlen=60, eth_src=self.host_port_a_mac, eth_dst=self.switch_port_b_mac,
                ip_src=ip_src, ip_dst=self.ip_host_b, ip_ttl=64)
            exp_pkt_on_a = testutils.simple_ip_packet(
                pktlen=60, eth_src=self.switch_port_a_mac, eth_dst=self.host_port_a_mac,
                ip_src=ip_src, ip_dst=self.ip_host_b, ip_ttl=63)
            exp_pkt_on_b = testutils.simple_ip_packet(
                pktlen=60, eth_src=self.switch_port_b_mac, eth_dst=self.host_port_b_mac,
                ip_src=ip_src, ip_dst=self.ip_host_b, ip_ttl=63)

            # Direct Tx to loopback port
            pkt_out = p4runtime_pb2.PacketOut()
            pkt_out.payload = str(pkt)
            egress_physical_port = pkt_out.metadata.add()
            egress_physical_port.metadata_id = 1
            egress_physical_port.value = self.switch_port_loopback
            self.send_packet_out(pkt_out)

            hit_port = testutils.verify_any_packet_any_port(self, [exp_pkt_on_a, exp_pkt_on_b], [self.host_port_a, self.host_port_b])
            hits[hit_port] = True

        if not hits[self.host_port_a]:
            self.fail("Port A never hit")
        if not hits[self.host_port_b]:
            self.fail("Port B never hit")
