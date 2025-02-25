/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<32> CPU_PORT = 255;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    macAddr_t sha;
    ip4Addr_t spa;
    macAddr_t tha;
    ip4Addr_t tpa;
}

struct metadata {
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<32> timestamp;
    bit<16> pkt_size; 
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    arp_t arp;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.src_ip = hdr.ipv4.srcAddr;
        meta.dst_ip = hdr.ipv4.dstAddr;
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egress_port(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action send_arp_response(macAddr_t src_mac, macAddr_t dst_mac, ip4Addr_t src_ip, ip4Addr_t dst_ip) {
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.etherType = TYPE_ARP;

        hdr.arp.htype = 1;
        hdr.arp.ptype = TYPE_IPV4;
        hdr.arp.hlen = 6;
        hdr.arp.plen = 4;
        hdr.arp.oper = 2; // ARP reply
        hdr.arp.sha = src_mac;
        hdr.arp.spa = src_ip;
        hdr.arp.tha = dst_mac;
        hdr.arp.tpa = dst_ip;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action NoOp() {
        // This action does nothing
    }


    table arp_cache {
        key = {
            hdr.arp.tpa: exact;
        }
        actions = {
            send_arp_response;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egress_port;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_ARP) {
            arp_cache.apply();
        } else if (hdr.ipv4.isValid()) {
            forward.apply();
        } else {
            drop();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
