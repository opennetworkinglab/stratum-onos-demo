#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "ipv4_checksum.p4"

#define CPU_MIRROR_SESSION_ID 1023
#define METER_GREEN 0


control punt(inout parsed_packet_t hdr,
             inout local_metadata_t local_metadata,
             inout standard_metadata_t standard_metadata) {

  @proto_package("punt")
  direct_meter<bit<2>>(MeterType.bytes) ingress_port_meter;

  @proto_package("punt")
  direct_counter(CounterType.packets) punt_packet_counter;

  @proto_package("punt")
  action set_queue_and_clone_to_cpu(@proto_tag(1) bit<5> queue_id) {
    local_metadata.cpu_cos_queue_id = queue_id;
    local_metadata.egress_spec_at_punt_match = standard_metadata.egress_spec;
    clone3<tuple<bit<9>>>(CloneType.I2E, CPU_MIRROR_SESSION_ID,
                          {standard_metadata.ingress_port});
    ingress_port_meter.read(local_metadata.color);
    punt_packet_counter.count();
  }

  @proto_package("punt")
  action set_queue_and_send_to_cpu(@proto_tag(1) bit<5> queue_id) {
    local_metadata.cpu_cos_queue_id = queue_id;
    local_metadata.egress_spec_at_punt_match = standard_metadata.egress_spec;
    standard_metadata.egress_spec = CPU_PORT;
    ingress_port_meter.read(local_metadata.color);
    punt_packet_counter.count();
  }

  action set_egress_port(PortNum port) {
    local_metadata.egress_spec_at_punt_match = standard_metadata.egress_spec;
    standard_metadata.egress_spec = port;
    ingress_port_meter.read(local_metadata.color);
    punt_packet_counter.count();
  }

  // Combined punt table.
  @proto_package("punt")
  @switchstack("pipeline_stage: INGRESS_ACL")
  table punt_table {
    key = {
      standard_metadata.ingress_port: ternary @proto_tag(1);
      standard_metadata.egress_spec: ternary @proto_tag(2);

      hdr.ethernet.ether_type: ternary @proto_tag(3);

      hdr.ipv4_base.diffserv: ternary @proto_tag(4);
    //   hdr.ipv6_base.traffic_class: ternary @proto_tag(5);
      hdr.ipv4_base.ttl: ternary @proto_tag(6);
    //   hdr.ipv6_base.hop_limit: ternary @proto_tag(7);
      hdr.ipv4_base.src_addr: ternary @proto_tag(8);
      hdr.ipv4_base.dst_addr: ternary @proto_tag(9);
    //   hdr.ipv6_base.src_addr: ternary @proto_tag(10);
    //   hdr.ipv6_base.dst_addr: ternary @proto_tag(11);
      hdr.ipv4_base.protocol: ternary @proto_tag(12);
    //   hdr.ipv6_base.next_header: ternary @proto_tag(13);

    //   hdr.arp.target_proto_addr: ternary @proto_tag(14);
      local_metadata.icmp_code: ternary @proto_tag(15);

      hdr.vlan_tag[0].vid: ternary @proto_tag(16);
      hdr.vlan_tag[0].pcp: ternary @proto_tag(17);

      local_metadata.class_id: ternary @proto_tag(18);
      local_metadata.vrf_id: ternary @proto_tag(19);
    }
    actions = {
      @proto_tag(1) set_queue_and_clone_to_cpu;
      @proto_tag(2) set_queue_and_send_to_cpu;
      set_egress_port;
    }
    meters = ingress_port_meter;
    counters = punt_packet_counter;
    size = 25;
  }

  apply {
    punt_table.apply();
    // if (local_metadata.color != METER_GREEN) {
    //   mark_to_drop();
    // }
  }
} // end punt

control l3_fwd(inout parsed_packet_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
  action nop() { }

  action drop() {
      mark_to_drop(standard_metadata);
  }

  @proto_package("l3_admit")
  action set_l3_admit() {
      local_metadata.l3_admit = 1;
  }

  @proto_package("l3_admit")
  @switchstack("pipeline_stage: L2")
  table l3_routing_classifier_table {
      key = {
          hdr.ethernet.dst_addr : ternary @proto_tag(1);
      }
      actions = {
          @proto_tag(1) set_l3_admit;
          @proto_tag(2) nop;
      }
      default_action = nop();
  }

  @proto_package("l3_fwd")
  action set_nexthop(@proto_tag(1) PortNum port,
                      @proto_tag(2) EthernetAddress smac,
                      @proto_tag(3) EthernetAddress dmac,
                      @proto_tag(4) bit<12> dst_vlan) {
      standard_metadata.egress_spec = port;
      local_metadata.dst_vlan = dst_vlan;
      hdr.ethernet.src_addr = smac;
      hdr.ethernet.dst_addr = dmac;
      hdr.ipv4_base.ttl = hdr.ipv4_base.ttl - 1;
  }

  action_selector(HashAlgorithm.crc16, 32w1024, 32w14) wcmp_action_profile;

  @proto_package("l3_fwd")
  @switchstack("pipeline_stage: L3_LPM")
  table l3_fwd_table {
      key = {
          local_metadata.vrf_id: exact @proto_tag(1);
          hdr.ipv4_base.dst_addr : lpm @proto_tag(2);
          hdr.ipv4_base.dst_addr : ternary @proto_tag(3);
          // hdr.ipv4_base.src_addr : selector @proto_tag(3);
          // hdr.ipv4_base.protocol : selector @proto_tag(4);
          // local_metadata.l4_src_port : selector @proto_tag(5);
          // local_metadata.l4_dst_port : selector @proto_tag(6);
      }
      actions = {
          @proto_tag(1) set_nexthop;
          @proto_tag(2) nop;
          drop;
      }
      const default_action = nop();
      implementation = wcmp_action_profile;
  }

  apply {
      l3_routing_classifier_table.apply();
      l3_fwd_table.apply();
  }
} // end l3_fwd

control ingress(inout parsed_packet_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
  apply {
    punt.apply(hdr, local_metadata, standard_metadata);
    l3_fwd.apply(hdr, local_metadata, standard_metadata);
  }
} // end ingress

control egress(inout parsed_packet_t hdr,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {
    apply { }
} // end egress

V1Switch(
    pkt_parser(),
    verify_ipv4_checksum(),
    ingress(),
    egress(),
    compute_ipv4_checksum(),
    pkt_deparser()
) main;
