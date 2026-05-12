#!/usr/bin/env python3
# Generate a minimal synthetic TLS flow whose ClientHello SNI matches
# ".amazon.com". The flow contains a full TCP 3-way handshake, then a
# TLS 1.2 ClientHello with SNI="www.amazon.com", then a TLS 1.2 server
# response (ServerHello + Certificate + ServerHelloDone + empty cert in
# one record stream) so that Suricata drives the TLS state machine
# through client_hello_done and at least one server state. This is not a
# real TLS handshake — it is the minimum byte pattern Suricata's TLS
# parser needs to recognise the named states exercised by the POC rule.
#
# Scapy's TLS layer is not used; we lay the raw bytes down explicitly so
# the pcap is stable across Scapy versions.

import struct
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def tls_record(content_type, fragment):
    # TLS 1.2 record: ContentType(1) Version(2)=0x0303 Length(2) fragment
    return bytes([content_type]) + b"\x03\x03" + struct.pack(">H", len(fragment)) + fragment


def client_hello(sni_host: bytes) -> bytes:
    # Handshake: ClientHello
    # https://datatracker.ietf.org/doc/html/rfc5246 section 7.4.1.2
    legacy_version = b"\x03\x03"
    random = b"\xaa" * 32
    session_id = b"\x00"  # length 0
    # 1 cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
    cipher_suites = struct.pack(">H", 2) + b"\x00\x9c"
    compression_methods = b"\x01\x00"  # length 1, null

    # Extension: server_name
    sn_entry = b"\x00" + struct.pack(">H", len(sni_host)) + sni_host  # name_type=host_name
    sn_list = struct.pack(">H", len(sn_entry)) + sn_entry
    ext_server_name = b"\x00\x00" + struct.pack(">H", len(sn_list)) + sn_list

    # Extensions block
    extensions = ext_server_name
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    body = (
        legacy_version
        + random
        + session_id
        + cipher_suites
        + compression_methods
        + extensions_block
    )
    # Handshake header: HandshakeType(1)=ClientHello, Length(3), body
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return hs


def server_hello() -> bytes:
    # Handshake: ServerHello with the same cipher suite
    legacy_version = b"\x03\x03"
    random = b"\xbb" * 32
    session_id = b"\x00"
    cipher_suite = b"\x00\x9c"
    compression = b"\x00"
    body = legacy_version + random + session_id + cipher_suite + compression
    return b"\x02" + struct.pack(">I", len(body))[1:] + body


def server_certificate() -> bytes:
    # Handshake: Certificate with 1 minimal cert payload (just bytes — not
    # valid X.509, but Suricata's TLS parser only needs the length fields
    # to advance through the server_cert_done state).
    cert = b"\x30\x82\x00\x10" + b"\x00" * 16
    cert_entry = struct.pack(">I", len(cert))[1:] + cert
    chain = struct.pack(">I", len(cert_entry))[1:] + cert_entry
    return b"\x0b" + struct.pack(">I", len(chain))[1:] + chain


def server_hello_done() -> bytes:
    return b"\x0e\x00\x00\x00"  # ServerHelloDone with 0-length body


def build():
    client_ip = "192.0.2.10"
    server_ip = "198.51.100.5"
    client_port = 43210
    server_port = 443

    # TCP seq/ack trackers
    c_seq = 1000
    s_seq = 5000

    pkts = []

    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    # SYN
    syn = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=c_seq
    )
    pkts.append(syn)

    # SYN-ACK
    syn_ack = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=s_seq, ack=c_seq + 1
    )
    pkts.append(syn_ack)

    # ACK
    c_seq += 1
    s_seq += 1
    ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq
    )
    pkts.append(ack)

    # ClientHello: single TLS record carrying the ClientHello handshake
    ch = client_hello(b"www.amazon.com")
    ch_record = tls_record(0x16, ch)
    cpkt = (
        eth
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="PA",
            seq=c_seq,
            ack=s_seq,
        )
        / Raw(load=ch_record)
    )
    pkts.append(cpkt)

    # server ack of ClientHello
    c_seq += len(ch_record)
    s_ack_ch = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="A", seq=s_seq, ack=c_seq
    )
    pkts.append(s_ack_ch)

    # Server response: ServerHello + Certificate + ServerHelloDone, all in
    # one TLS record to keep the PCAP small.
    sh = server_hello()
    sc = server_certificate()
    shd = server_hello_done()
    s_record = tls_record(0x16, sh + sc + shd)
    spkt = (
        eth
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="PA",
            seq=s_seq,
            ack=c_seq,
        )
        / Raw(load=s_record)
    )
    pkts.append(spkt)

    # client ack
    s_seq += len(s_record)
    c_ack_s = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq
    )
    pkts.append(c_ack_s)

    # FIN from client
    fin_c = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="FA", seq=c_seq, ack=s_seq
    )
    pkts.append(fin_c)

    # FIN-ACK from server
    c_seq += 1
    fin_s = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="FA", seq=s_seq, ack=c_seq
    )
    pkts.append(fin_s)

    # final ACK
    s_seq += 1
    last_ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq
    )
    pkts.append(last_ack)

    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    wrpcap(out, pkts)
    print(f"wrote {out} with {len(pkts)} packets")


if __name__ == "__main__":
    build()
