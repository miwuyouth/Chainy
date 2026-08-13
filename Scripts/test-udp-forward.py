#!/usr/bin/env python3
"""Test UDP forwarding through Chainy's local SOCKS5 proxy.

Usage: python3 scripts/test-udp-forward.py [port]  (default port 1080)

Does a real SOCKS5 UDP ASSOCIATE handshake against Chainy's local proxy,
then sends a DNS query for www.google.com to 8.8.8.8:53 through it and
times the round trip -- exercises the exact path a real SOCKS5 client
takes, unlike Chainy's own internal "Test Connection" probe which dials
ChainCore directly and skips the local proxy listener.
"""
import socket
import struct
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080


def dns_query(name: str, qid: int = 0x2A2A) -> bytes:
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


tcp = socket.create_connection(("127.0.0.1", port), timeout=5)
tcp.sendall(b"\x05\x01\x00")  # SOCKS5, 1 method, no-auth
if tcp.recv(2) != b"\x05\x00":
    sys.exit("proxy rejected no-auth handshake")

tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # CMD=UDP ASSOCIATE
reply = tcp.recv(10)
if len(reply) < 10 or reply[1] != 0x00:
    sys.exit(f"UDP ASSOCIATE refused (reply={reply.hex()}) -- this chain's protocols likely don't support UDP")

bound_port = struct.unpack("!H", reply[8:10])[0]
print(f"UDP relay bound at 127.0.0.1:{bound_port}")

header = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
packet = header + dns_query("www.google.com")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(8)
start = time.time()
udp.sendto(packet, ("127.0.0.1", bound_port))
try:
    data, _ = udp.recvfrom(2048)
    print(f"UDP forwarding OK -- {(time.time() - start) * 1000:.0f}ms round trip, {len(data)} bytes back")
except socket.timeout:
    print("UDP forwarding FAILED -- no reply within 8s (blocked path, or upstream ignored it)")
finally:
    tcp.close()
