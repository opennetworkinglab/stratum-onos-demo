// Copyright (c) 2019, Open Networking Foundation
//
// P4_16 specification for a packet parser.

#ifndef P4_SPEC_PARSER_P4_
#define P4_SPEC_PARSER_P4_

#include <v1model.p4>
#include "headers.p4"

//------------------------------------------------------------------------------
// Global defines
//------------------------------------------------------------------------------

#define ETHERTYPE_VLAN1 0x8100
#define ETHERTYPE_VLAN2 0x9100
#define ETHERTYPE_VLAN3 0x9200
#define ETHERTYPE_VLAN4 0x9300

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_ND 0x6007
#define ETHERTYPE_LLDP 0x88CC

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_ICMPv6 58

#ifndef CPU_PORT
// enforced by FPM / BCM
#define CPU_PORT 0xFD
#endif
#define VLAN_DEPTH 2

//------------------------------------------------------------------------------
// List of all recognized headers
//------------------------------------------------------------------------------

struct parsed_packet_t {
  ethernet_t ethernet;
  ipv4_base_t ipv4_base;
  ipv6_base_t ipv6_base;
  icmp_header_t icmp_header;
  tcp_t tcp;
  udp_t udp;
  vlan_tag_t[VLAN_DEPTH] vlan_tag; // header stack
  arp_t arp;
  packet_in_header_t packet_in;
  packet_out_header_t packet_out;
}

//------------------------------------------------------------------------------
// Parser
//------------------------------------------------------------------------------

parser pkt_parser(packet_in pk, out parsed_packet_t hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
  state start {
    transition select(standard_metadata.ingress_port) {
      CPU_PORT : parse_cpu_header;
      _ :        parse_ethernet;
    }
  }

  state parse_ethernet {
    pk.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
      ETHERTYPE_VLAN1: parse_vlan;
      ETHERTYPE_VLAN2: parse_vlan;
      ETHERTYPE_VLAN3: parse_vlan;
      ETHERTYPE_VLAN4: parse_vlan;
      ETHERTYPE_IPV4:  parse_ipv4;
      ETHERTYPE_IPV6:  parse_ipv6;
      ETHERTYPE_ARP:   parse_arp;
      _ :              accept;
    }
  }

  state parse_vlan {
    // reference the next element in header stack
    pk.extract(hdr.vlan_tag.next);
    transition select(hdr.vlan_tag.last.ether_type) {
      ETHERTYPE_VLAN1: parse_vlan;
      ETHERTYPE_VLAN2: parse_vlan;
      ETHERTYPE_VLAN3: parse_vlan;
      ETHERTYPE_VLAN4: parse_vlan;
      ETHERTYPE_IPV4 : parse_ipv4;
      ETHERTYPE_IPV6 : parse_ipv6;
      _ :              accept;
    }
  }

  state parse_ipv4 {
    pk.extract(hdr.ipv4_base);
    // TODO: confirm if below concats the two fields
    transition select(hdr.ipv4_base.frag_offset ++ hdr.ipv4_base.protocol) {
      IP_PROTOCOLS_ICMP : parse_icmp;
      IP_PROTOCOLS_TCP  : parse_tcp;
      IP_PROTOCOLS_UDP  : parse_udp;
      _ :                 accept;
    }
  }

  state parse_ipv6 {
    pk.extract(hdr.ipv6_base);
    transition select(hdr.ipv6_base.next_header) {
      IP_PROTOCOLS_ICMPv6: parse_icmp;
      IP_PROTOCOLS_TCP   : parse_tcp;
      IP_PROTOCOLS_UDP   : parse_udp;
      _ :                  accept;
    }
  }

  state parse_tcp {
    pk.extract(hdr.tcp);
    // Normalize TCP port metadata to common port metadata
    local_metadata.l4_src_port = hdr.tcp.src_port;
    local_metadata.l4_dst_port = hdr.tcp.dst_port;
    transition accept;
  }

  state parse_udp {
    pk.extract(hdr.udp);
    // Normalize UDP port metadata to common port metadata
    local_metadata.l4_src_port = hdr.udp.src_port;
    local_metadata.l4_dst_port = hdr.udp.dst_port;
    transition accept;
  }

  state parse_icmp {
    pk.extract(hdr.icmp_header);
    transition accept;
  }

  state parse_arp {
    pk.extract(hdr.arp);
    transition accept;
  }

  state parse_cpu_header {
    pk.extract(hdr.packet_out);
    transition parse_ethernet;
  }
} // end pkt_parser

control pkt_deparser(packet_out b, in parsed_packet_t hdr) {
  apply {
    // packet_out is not a valid header in a packet destined to CPU_PORT
    b.emit(hdr.packet_in);
    b.emit(hdr.ethernet);
    b.emit(hdr.vlan_tag);
    b.emit(hdr.ipv4_base);
    b.emit(hdr.ipv6_base);
    b.emit(hdr.arp);
    b.emit(hdr.icmp_header);
    b.emit(hdr.tcp);
    b.emit(hdr.udp);
  }
}

#endif // P4_SPEC_PARSER_P4_
