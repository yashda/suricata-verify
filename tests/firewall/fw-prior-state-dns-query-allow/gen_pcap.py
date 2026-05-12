#!/usr/bin/env python3
# Generate a multi-transport synthetic DNS capture covering both:
#   1) A UDP DNS query for "www.amazon.com" followed by a minimal
#      NOERROR A response (2 UDP packets).
#   2) A DNS-over-TCP query/response flow on port 53: TCP 3-way
#      handshake, DNS query (preceded by the 2-byte big-endian length
#      prefix per RFC 1035 §4.2.2), server ACK, DNS response (also with
#      2-byte length prefix), client ACK, and a FIN/FIN-ACK teardown.
#      The TCP flow uses a distinct client port (55001) so its flow is
#      cleanly separated from the UDP flow.
#
# This is the packet input for the `fw-prior-state-dns-query-allow` POC
# fixture per task 8.2. The fixture's single Prior_State_Rule expands
# into a 10-rule set (4 TCP handshake + 2 UDP + 3 DNS + 1 Decision_Hook);
# both the UDP path (subs 5..6) and the TCP path (subs 1..4) are
# exercised by this capture.
#
# Regenerate by running `python3 gen_pcap.py`.

import struct
import sys

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def dns_query(tx_id: int, qname: str) -> bytes:
    # Header: id, flags=0x0100 (RD), qdcount=1, ancount=0, nscount=0, arcount=0
    hdr = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)  # A, IN
    return hdr + q


def dns_response(tx_id: int, qname: str, answer_ip: str) -> bytes:
    # Header with QR=1, RA=1 + one answer RR
    hdr = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)
    # Answer: name (use pointer 0xc00c to qname at offset 12), type A,
    # class IN, ttl=300, rdlen=4, rdata=IPv4
    octets = [int(x) for x in answer_ip.split(".")]
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(octets)
    return hdr + q + ans


def tcp_length_prefix(payload: bytes) -> bytes:
    # RFC 1035 §4.2.2: DNS over TCP is prefixed with a 16-bit big-endian
    # length field giving the length of the following DNS message.
    return struct.pack(">H", len(payload)) + payload


def build():
    client_ip = "192.0.2.10"
    server_ip = "198.51.100.5"
    udp_client_port = 55000
    tcp_client_port = 55001
    server_port = 53

    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    pkts = []

    # -------- UDP DNS flow --------
    q = dns_query(0x1234, "www.amazon.com")
    qpkt = (
        eth
        / IP(src=client_ip, dst=server_ip)
        / UDP(sport=udp_client_port, dport=server_port)
        / Raw(load=q)
    )
    pkts.append(qpkt)

    r = dns_response(0x1234, "www.amazon.com", "203.0.113.20")
    rpkt = (
        eth
        / IP(src=server_ip, dst=client_ip)
        / UDP(sport=server_port, dport=udp_client_port)
        / Raw(load=r)
    )
    pkts.append(rpkt)

    # -------- TCP DNS flow --------
    c_seq = 1000
    s_seq = 5000

    # SYN
    syn = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=tcp_client_port, dport=server_port, flags="S", seq=c_seq
    )
    pkts.append(syn)

    # SYN-ACK
    syn_ack = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=tcp_client_port, flags="SA",
        seq=s_seq, ack=c_seq + 1,
    )
    pkts.append(syn_ack)

    # ACK (handshake completes)
    c_seq += 1
    s_seq += 1
    ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=tcp_client_port, dport=server_port, flags="A",
        seq=c_seq, ack=s_seq,
    )
    pkts.append(ack)

    # DNS query over TCP (with 2-byte length prefix)
    tcp_q_payload = tcp_length_prefix(dns_query(0x5678, "www.amazon.com"))
    q_tcp = (
        eth
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=tcp_client_port,
            dport=server_port,
            flags="PA",
            seq=c_seq,
            ack=s_seq,
        )
        / Raw(load=tcp_q_payload)
    )
    pkts.append(q_tcp)

    # server ACK of the query
    c_seq += len(tcp_q_payload)
    s_ack = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=tcp_client_port, flags="A",
        seq=s_seq, ack=c_seq,
    )
    pkts.append(s_ack)

    # DNS response over TCP (with 2-byte length prefix)
    tcp_r_payload = tcp_length_prefix(
        dns_response(0x5678, "www.amazon.com", "203.0.113.20")
    )
    r_tcp = (
        eth
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=tcp_client_port,
            flags="PA",
            seq=s_seq,
            ack=c_seq,
        )
        / Raw(load=tcp_r_payload)
    )
    pkts.append(r_tcp)

    # client ACK of the response
    s_seq += len(tcp_r_payload)
    c_ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=tcp_client_port, dport=server_port, flags="A",
        seq=c_seq, ack=s_seq,
    )
    pkts.append(c_ack)

    # FIN from client
    fin_c = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=tcp_client_port, dport=server_port, flags="FA",
        seq=c_seq, ack=s_seq,
    )
    pkts.append(fin_c)

    # FIN-ACK from server
    c_seq += 1
    fin_s = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=tcp_client_port, flags="FA",
        seq=s_seq, ack=c_seq,
    )
    pkts.append(fin_s)

    # final ACK
    s_seq += 1
    last_ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=tcp_client_port, dport=server_port, flags="A",
        seq=c_seq, ack=s_seq,
    )
    pkts.append(last_ack)

    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    wrpcap(out, pkts)
    print(f"wrote {out} with {len(pkts)} packets")


if __name__ == "__main__":
    build()
