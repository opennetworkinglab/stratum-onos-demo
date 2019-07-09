// Copyright (c) 2019, Open Networking Foundation
//
// P4_16 specification for IPv4 checksum verify and update.

#include "headers.p4"


control verify_ipv4_checksum(inout parsed_packet_t hdr,
                        inout local_metadata_t local_metadata) {
  apply {
    verify_checksum(hdr.ipv4_base.isValid(),
      {
        hdr.ipv4_base.version, hdr.ipv4_base.ihl,
        hdr.ipv4_base.diffserv, hdr.ipv4_base.total_len,
        hdr.ipv4_base.identification, hdr.ipv4_base.flags,
        hdr.ipv4_base.frag_offset, hdr.ipv4_base.ttl,
        hdr.ipv4_base.protocol, hdr.ipv4_base.src_addr,
        hdr.ipv4_base.dst_addr
      },
      hdr.ipv4_base.hdr_checksum,
      HashAlgorithm.csum16
    );
  }
}

control compute_ipv4_checksum(inout parsed_packet_t hdr,
                         inout local_metadata_t local_metadata) {
  apply {
    update_checksum(hdr.ipv4_base.isValid(),
      {
        hdr.ipv4_base.version, hdr.ipv4_base.ihl,
        hdr.ipv4_base.diffserv, hdr.ipv4_base.total_len,
        hdr.ipv4_base.identification, hdr.ipv4_base.flags,
        hdr.ipv4_base.frag_offset, hdr.ipv4_base.ttl,
        hdr.ipv4_base.protocol, hdr.ipv4_base.src_addr,
        hdr.ipv4_base.dst_addr
      },
      hdr.ipv4_base.hdr_checksum,
      HashAlgorithm.csum16
    );
  }
}
