#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "ipv4_checksum.p4"

// enforced by FPM / BCM
#define CPU_MIRROR_SESSION_ID 511

#define METER_GREEN 0
#define LOOPBACK_PORT 13


control punt(inout parsed_packet_t hdr,
             inout local_metadata_t local_metadata,
             inout standard_metadata_t standard_metadata) {

  direct_meter<bit<2>>(MeterType.bytes) ingress_port_meter;

  direct_counter(CounterType.packets) punt_packet_counter;

  action set_queue_and_clone_to_cpu(bit<5> queue_id) {
    local_metadata.cpu_cos_queue_id = queue_id;
    local_metadata.egress_spec_at_punt_match = standard_metadata.egress_spec;
    clone3(CloneType.I2E, CPU_MIRROR_SESSION_ID,
                        {standard_metadata.ingress_port});
    ingress_port_meter.read(local_metadata.color);
    punt_packet_counter.count();
  }

  action set_queue_and_send_to_cpu(bit<5> queue_id) {
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
  @switchstack("pipeline_stage: INGRESS_ACL")
  table punt_table {
    key = {
      standard_metadata.ingress_port: ternary;
      standard_metadata.egress_spec: ternary;

      hdr.ethernet.ether_type: ternary;

      hdr.ipv4_base.diffserv: ternary;
      // hdr.ipv6_base.traffic_class: ternary;
      hdr.ipv4_base.ttl: ternary;
      // hdr.ipv6_base.hop_limit: ternary;
      hdr.ipv4_base.src_addr: ternary;
      hdr.ipv4_base.dst_addr: ternary;
      // hdr.ipv6_base.src_addr: ternary;
      // hdr.ipv6_base.dst_addr: ternary;
      hdr.ipv4_base.protocol: ternary;
      // hdr.ipv6_base.next_header: ternary;\
      // hdr.arp.target_proto_addr: ternary;
      local_metadata.icmp_code: ternary;

      hdr.vlan_tag[0].vid: ternary;
      hdr.vlan_tag[0].pcp: ternary;

      local_metadata.class_id: ternary;
      local_metadata.vrf_id: ternary;
    }
    actions = {
      set_queue_and_clone_to_cpu;
      set_queue_and_send_to_cpu;
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

  action drop() { mark_to_drop(standard_metadata); }

  action set_l3_admit() {
      local_metadata.l3_admit = 1;
  }

  @switchstack("pipeline_stage: L2")
  table l3_routing_classifier_table {
      key = {
          hdr.ethernet.dst_addr : ternary;
      }
      actions = {
          set_l3_admit;
          nop;
      }
      default_action = nop();
  }

  action set_nexthop(PortNum port,
                     EthernetAddress smac,
                     EthernetAddress dmac,
                     bit<12> dst_vlan) {
      standard_metadata.egress_spec = port;
      local_metadata.dst_vlan = dst_vlan;
      hdr.ethernet.src_addr = smac;
      hdr.ethernet.dst_addr = dmac;
      hdr.ipv4_base.ttl = hdr.ipv4_base.ttl - 1;
  }

  action_selector(HashAlgorithm.crc16, 32w1024, 32w14) wcmp_action_profile;

  @switchstack("pipeline_stage: L3_LPM")
  table l3_fwd_table {
      key = {
          local_metadata.vrf_id      : exact;
          hdr.ipv4_base.dst_addr     : lpm;
          // hdr.ipv4_base.dst_addr  : ternary;
          hdr.ipv4_base.src_addr     : selector;
          hdr.ipv4_base.protocol     : selector;
          local_metadata.l4_src_port : selector;
          local_metadata.l4_dst_port : selector;
      }
      actions = {
          set_nexthop;
          nop;
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

control mcast(inout parsed_packet_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {

  action set_mcast_group_id(bit<16> group_id) {
    standard_metadata.mcast_grp = group_id;
  }

  @switchstack("pipeline_stage: INGRESS_ACL")
  table mcast_table {
    key = {
      hdr.ethernet.src_addr : ternary;
      hdr.ethernet.dst_addr : ternary;
      hdr.ethernet.ether_type : exact;
    }
    actions = {
      set_mcast_group_id;
    }
  }

  apply {
    mcast_table.apply();
  }
} // end mcast

control ingress(inout parsed_packet_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
  apply {
    if (hdr.packet_out.isValid()) {
        standard_metadata.egress_spec = hdr.packet_out.egress_physical_port;
        hdr.packet_out.setInvalid();
    }
    if (standard_metadata.egress_spec == 0 ||
            standard_metadata.egress_spec == LOOPBACK_PORT) {
        punt.apply(hdr, local_metadata, standard_metadata);
        mcast.apply(hdr, local_metadata, standard_metadata);
        l3_fwd.apply(hdr, local_metadata, standard_metadata);
    }
  }
} // end ingress

control egress(inout parsed_packet_t hdr,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_physical_port = standard_metadata.ingress_port;
            hdr.packet_in.target_egress_port = local_metadata.egress_spec_at_punt_match;
            // No need to process through the rest of the pipeline.
            exit;
        }
    }
} // end egress

V1Switch(
    pkt_parser(),
    verify_ipv4_checksum(),
    ingress(),
    egress(),
    compute_ipv4_checksum(),
    pkt_deparser()
) main;
