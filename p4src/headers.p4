// Copyright (c) 2019, Open Networking Foundation
//
// Common header definitions.

#ifndef P4_SPEC_HEADERS_P4_
#define P4_SPEC_HEADERS_P4_

//------------------------------------------------------------------------------
// Field type definitions
//------------------------------------------------------------------------------

typedef bit<48>   EthernetAddress;
typedef bit<32>   IPv4Address;
typedef bit<128>  IPv6Address;
typedef bit<9>    PortNum;

//------------------------------------------------------------------------------
// Protocol header definitions
//------------------------------------------------------------------------------

header ethernet_t {
  EthernetAddress dst_addr;
  EthernetAddress src_addr;
  bit<16> ether_type;
}

header ipv4_base_t {
  bit<4> version;
  bit<4> ihl;
  bit<8> diffserv;
  bit<16> total_len;
  bit<16> identification;
  bit<3> flags;
  bit<13> frag_offset;
  bit<8> ttl;
  bit<8> protocol;
  bit<16> hdr_checksum;
  IPv4Address src_addr;
  IPv4Address dst_addr;
}

// Fixed ipv6 header
header ipv6_base_t {
  bit<4> version;
  bit<8> traffic_class;
  bit<20> flow_label;
  bit<16> payload_length;
  bit<8> next_header;
  bit<8> hop_limit;
  IPv6Address src_addr;
  IPv6Address dst_addr;
}

header udp_t {
  bit<16> src_port;
  bit<16> dst_port;
  bit<16> hdr_length;
  bit<16> checksum;
}

header tcp_t {
  bit<16> src_port;
  bit<16> dst_port;
  bit<32> seq_no;
  bit<32> ack_no;
  bit<4> data_offset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgent_ptr;
}

// Same for both ip v4 and v6
header icmp_header_t {
  bit<8> icmp_type;
  bit<8> code;
  bit<16> checksum;
}

header vlan_tag_t {
  bit<3> pcp;
  bit cfi;
  bit<12> vid;
  bit<16> ether_type;
}

header arp_t {
  bit<16> hw_type;
  bit<16> proto_type;
  bit<8> hw_addr_len;
  bit<8> proto_addr_len;
  bit<16> opcode;
  bit<48> sender_hw_addr;
  bit<32> sender_proto_addr;
  bit<48> target_hw_addr;
  bit<32> target_proto_addr;
}

//------------------------------------------------------------------------------
// Controller header definitions
//------------------------------------------------------------------------------

@controller_header("packet_in")
header packet_in_header_t {
  @switchstack("field_type: P4_FIELD_TYPE_INGRESS_PORT")
  @proto_tag(1) bit<9> ingress_physical_port;
  @proto_tag(2) bit<7> padding1;
  @proto_tag(3) bit<32> ingress_logical_port;
  // The initial intended egress port decided for the packet by the pipeline.
  // This is standard metadata.egress_spec at the time the punt-rule was hit.
  @switchstack("field_type: P4_FIELD_TYPE_EGRESS_PORT")
  @proto_tag(4) bit<9> target_egress_port;
  @proto_tag(5) bit<7> padding2;
}

@not_extracted_in_egress // Tofino has a deparser and parser around the TM
@controller_header("packet_out")
header packet_out_header_t {
  @switchstack("field_type: P4_FIELD_TYPE_EGRESS_PORT")
  @proto_tag(1) bit<9> egress_physical_port;
  @proto_tag(2) bit<1> submit_to_ingress;
  @proto_tag(3) bit<6> padding;
}

//------------------------------------------------------------------------------
// Metadata definition
//------------------------------------------------------------------------------

// Local meta-data for each packet being processed.
struct local_metadata_t {
    @switchstack("field_type: P4_FIELD_TYPE_VRF")
    bit<10> vrf_id;
    bit<8> class_id;              // Dst traffic class ID (IPSP)
    bit<5> cpu_cos_queue_id;
    bit<1> skip_egress;
    bit<9> egress_spec_at_punt_match;
    @switchstack("field_type: P4_FIELD_TYPE_COLOR")
    bit<2> color;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<8> icmp_code;
    @switchstack("field_type: P4_FIELD_TYPE_L3_ADMIT")
    bit<1> l3_admit;
    @switchstack("field_type: P4_FIELD_TYPE_VLAN_VID")
    bit<12> dst_vlan;
    bit<1> is_mcast;
}
#endif // P4_SPEC_HEADERS_P4_
