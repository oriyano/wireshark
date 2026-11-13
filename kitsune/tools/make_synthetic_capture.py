#!/usr/bin/env python3
#
# make_synthetic_capture.py - write a synthetic office-network capture
#
# Kitsune - test data generator.
#
# The traffic is generated, not captured, so it holds no private data.
# It models a small office: several /24 subnets behind one gateway,
# Windows and Linux hosts (with typical TTLs and TCP window sizes),
# servers offering SSH, HTTP, SMB and DNS, and clients that look up
# names, browse and ping. That makes it useful both for benchmarking
# the packet list and for testing host and OS discovery.
#
# Usage: make_synthetic_capture.py OUTPUT.pcap [PACKETS] [SEED]
#
# SPDX-License-Identifier: GPL-2.0-or-later

import random
import struct
import sys

LINKTYPE_ETHERNET = 1


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def ip_bytes(ip):
    return bytes(int(part) for part in ip.split("."))


class Host:
    def __init__(self, name, ip, mac, os_kind, services=()):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.os_kind = os_kind      # "windows", "linux", "embedded"
        self.services = list(services)

    @property
    def ttl(self):
        return {"windows": 128, "linux": 64, "embedded": 255}[self.os_kind]

    @property
    def window(self):
        return {"windows": 64240, "linux": 29200, "embedded": 5840}[self.os_kind]


class Writer:
    def __init__(self, path, rng):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        self.t = 1767225600.0  # 2026-01-01 00:00:00 UTC
        self.count = 0
        self.rng = rng
        self.ip_id = 1

    def advance(self, mean_gap):
        self.t += self.rng.expovariate(1.0 / mean_gap)

    def frame(self, payload):
        secs = int(self.t)
        usecs = int((self.t - secs) * 1_000_000)
        self.f.write(struct.pack("<IIII", secs, usecs, len(payload), len(payload)))
        self.f.write(payload)
        self.count += 1

    def ether(self, src, dst, ethertype, body):
        return mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", ethertype) + body

    def ipv4(self, src, dst, proto, body, ttl):
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), self.ip_id, 0x4000,
                             ttl, proto, 0, ip_bytes(src.ip if isinstance(src, Host) else src),
                             ip_bytes(dst.ip if isinstance(dst, Host) else dst))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return header + body

    def tcp(self, sip, dip, sport, dport, seq, ack, flags, window, payload=b"", options=b""):
        offset = (20 + len(options)) // 4
        header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, window, 0, 0) + options
        pseudo = ip_bytes(sip) + ip_bytes(dip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
        csum = checksum(pseudo + header + payload)
        return header[:16] + struct.pack("!H", csum) + header[18:] + payload

    def udp(self, sip, dip, sport, dport, payload):
        header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        pseudo = ip_bytes(sip) + ip_bytes(dip) + struct.pack("!BBH", 0, 17, len(header) + len(payload))
        csum = checksum(pseudo + header + payload) or 0xFFFF
        return header[:6] + struct.pack("!H", csum) + payload

    def send_tcp(self, src, dst, smac, dmac, sport, dport, seq, ack, flags, payload=b"", syn=False):
        options = b""
        if syn:
            # MSS, SACK permitted, timestamps / window scale differ by OS.
            if src.os_kind == "windows":
                options = b"\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02"
            elif src.os_kind == "embedded":
                options = b"\x02\x04\x05\xb4"          # small stacks: MSS only
            else:
                options = b"\x02\x04\x05\xb4\x04\x02\x08\x0a" + struct.pack("!II", seq & 0xFFFFFFFF, 0) + b"\x01\x03\x03\x07"
        # Window scaling applies after the handshake: 2^8 on Windows, 2^7 on Linux.
        window = src.window if syn else src.window >> {"windows": 8, "linux": 7, "embedded": 0}[src.os_kind]
        seg = self.tcp(src.ip, dst.ip, sport, dport, seq, ack, flags, window, payload, options)
        self.frame(self.ether(smac, dmac, 0x0800, self.ipv4(src, dst, 6, seg, src.ttl)))

    def close(self):
        self.f.close()


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def build_network(rng):
    gateway = Host("GATEWAY", "192.168.1.1", "00:1a:2b:00:00:01", "embedded")
    subnets = {
        "192.168.10": [("MGMT-%02d" % i, "windows") for i in range(1, 13)],
        "192.168.20": [("NAS-SERVER", "linux"), ("FILE-SRV", "windows"), ("DB-SERVER", "linux"),
                       ("APP-SERVER", "windows"), ("WEB-SERVER", "linux"), ("MONITOR", "windows"),
                       ("BACKUP", "linux"), ("VM-HOST", "windows")],
        "192.168.30": [("CAM-%02d" % i, "embedded") for i in range(1, 18)],
        "192.168.40": [("GUEST-%02d" % i, rng.choice(["windows", "linux"])) for i in range(1, 7)],
        "192.168.50": [("LAPTOP-%02d" % i, rng.choice(["windows", "windows", "linux"])) for i in range(1, 6)],
    }
    service_ports = {
        "NAS-SERVER": [22, 80, 443, 445, 2049], "FILE-SRV": [445, 3389], "DB-SERVER": [22, 3306],
        "APP-SERVER": [80, 443, 8080], "WEB-SERVER": [22, 80, 443], "MONITOR": [443, 9090],
        "BACKUP": [22, 873], "VM-HOST": [443, 902],
    }
    hosts = []
    for prefix, members in subnets.items():
        for index, (name, os_kind) in enumerate(members, start=10):
            mac = "00:1a:2b:%02x:%02x:%02x" % (int(prefix.split(".")[2]), index, rng.randrange(256))
            hosts.append(Host(name, "%s.%d" % (prefix, index), mac, os_kind, service_ports.get(name, [])))
    dns_server = Host("DNS", "192.168.1.53", "00:1a:2b:00:00:35", "linux", [53])
    return gateway, dns_server, hosts


def http_conversation(w, client, server, gw_mac, rng):
    sport = rng.randrange(49152, 65535)
    dport = 80 if 80 in server.services else 8080
    cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)
    cmac, smac = client.mac, server.mac
    w.send_tcp(client, server, cmac, smac, sport, dport, cseq, 0, 0x02, syn=True); w.advance(0.0004)
    w.send_tcp(server, client, smac, cmac, dport, sport, sseq, cseq + 1, 0x12, syn=True); w.advance(0.0003)
    w.send_tcp(client, server, cmac, smac, sport, dport, cseq + 1, sseq + 1, 0x10); w.advance(0.0002)
    agent = {"windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0",
             "linux": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/133.0",
             "embedded": "CamFirmware/2.1 (embedded)"}[client.os_kind]
    request = ("GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"
               % (server.name.lower(), agent)).encode()
    w.send_tcp(client, server, cmac, smac, sport, dport, cseq + 1, sseq + 1, 0x18, request); w.advance(0.002)
    body = b'{"status":"ok"}'
    software = "nginx/1.24.0 (Ubuntu)" if server.os_kind == "linux" else "Microsoft-IIS/10.0"
    response = ("HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                % (software, len(body))).encode() + body
    w.send_tcp(server, client, smac, cmac, dport, sport, sseq + 1, cseq + 1 + len(request), 0x18, response); w.advance(0.0003)
    w.send_tcp(client, server, cmac, smac, sport, dport, cseq + 1 + len(request), sseq + 1 + len(response), 0x11); w.advance(0.0003)
    w.send_tcp(server, client, smac, cmac, dport, sport, sseq + 1 + len(response), cseq + 2 + len(request), 0x11); w.advance(0.0002)
    w.send_tcp(client, server, cmac, smac, sport, dport, cseq + 2 + len(request), sseq + 2 + len(response), 0x10)


def ssh_banner(w, client, server, rng):
    sport = rng.randrange(49152, 65535)
    cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)
    w.send_tcp(client, server, client.mac, server.mac, sport, 22, cseq, 0, 0x02, syn=True); w.advance(0.0004)
    w.send_tcp(server, client, server.mac, client.mac, 22, sport, sseq, cseq + 1, 0x12, syn=True); w.advance(0.0003)
    w.send_tcp(client, server, client.mac, server.mac, sport, 22, cseq + 1, sseq + 1, 0x10); w.advance(0.001)
    banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
    w.send_tcp(server, client, server.mac, client.mac, 22, sport, sseq + 1, cseq + 1, 0x18, banner); w.advance(0.0005)
    w.send_tcp(client, server, client.mac, server.mac, sport, 22, cseq + 1, sseq + 1 + len(banner), 0x14)


def dns_lookup(w, client, dns_server, name, answer_ip, rng):
    txid = rng.getrandbits(16)
    sport = rng.randrange(49152, 65535)
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    w.frame(w.ether(client.mac, dns_server.mac, 0x0800,
                    w.ipv4(client, dns_server, 17, w.udp(client.ip, dns_server.ip, sport, 53, query), client.ttl)))
    w.advance(0.003)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes(answer_ip)
    reply = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
    w.frame(w.ether(dns_server.mac, client.mac, 0x0800,
                    w.ipv4(dns_server, client, 17, w.udp(dns_server.ip, client.ip, 53, sport, reply), dns_server.ttl)))


def arp_exchange(w, asker, target):
    request = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac_bytes(asker.mac), ip_bytes(asker.ip),
                          b"\0" * 6, ip_bytes(target.ip))
    w.frame(w.ether(asker.mac, "ff:ff:ff:ff:ff:ff", 0x0806, request + b"\0" * 18))
    w.advance(0.0005)
    reply = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, mac_bytes(target.mac), ip_bytes(target.ip),
                        mac_bytes(asker.mac), ip_bytes(asker.ip))
    w.frame(w.ether(target.mac, asker.mac, 0x0806, reply + b"\0" * 18))


def dhcp_exchange(w, client, server, rng):
    """DHCP request and ack: the client's name and vendor class, and the router option."""
    xid = rng.getrandbits(32)
    vendor = {"windows": b"MSFT 5.0", "linux": b"dhcpcd-10.0.6:Linux", "embedded": b"udhcp 1.36.1"}[client.os_kind]
    name = client.name.encode()

    def bootp(op, ciaddr, yiaddr, options):
        body = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000, ip_bytes(ciaddr),
                           ip_bytes(yiaddr), b"\0" * 4, b"\0" * 4, mac_bytes(client.mac) + b"\0" * 10, b"\0" * 64,
                           b"\0" * 128)
        return body + b"\x63\x82\x53\x63" + options + b"\xff"

    req_opts = (b"\x35\x01\x03" + b"\x32\x04" + ip_bytes(client.ip) + b"\x0c" + bytes([len(name)]) + name +
                b"\x3c" + bytes([len(vendor)]) + vendor + b"\x37\x04\x01\x03\x06\x0f")
    request = bootp(1, "0.0.0.0", "0.0.0.0", req_opts)
    w.frame(w.ether(client.mac, "ff:ff:ff:ff:ff:ff", 0x0800,
                    w.ipv4("0.0.0.0", "255.255.255.255", 17, w.udp("0.0.0.0", "255.255.255.255", 68, 67, request), client.ttl)))
    w.advance(0.004)
    ack_opts = (b"\x35\x01\x05" + b"\x36\x04" + ip_bytes(server.ip) + b"\x33\x04\x00\x01\x51\x80" +
                b"\x01\x04\xff\xff\xff\x00" + b"\x03\x04" + ip_bytes(server.ip) + b"\x06\x04" + ip_bytes("192.168.1.53"))
    ack = bootp(2, "0.0.0.0", client.ip, ack_opts)
    w.frame(w.ether(server.mac, client.mac, 0x0800,
                    w.ipv4(server, client, 17, w.udp(server.ip, client.ip, 67, 68, ack), server.ttl)))


def ping(w, src, dst, seq):
    payload = bytes(range(32))
    for kind, a, b in ((8, src, dst), (0, dst, src)):
        icmp = struct.pack("!BBHHH", kind, 0, 0, 0x4b49, seq) + payload
        icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
        w.frame(w.ether(a.mac, b.mac, 0x0800, w.ipv4(a, b, 1, icmp, a.ttl)))
        w.advance(0.0008)


def main():
    if len(sys.argv) < 2:
        print(__doc__ or "usage: make_synthetic_capture.py OUTPUT.pcap [PACKETS] [SEED]")
        sys.exit(1)
    path = sys.argv[1]
    target = int(sys.argv[2]) if len(sys.argv) > 2 else 100_000
    rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)

    gateway, dns_server, hosts = build_network(rng)
    servers = [h for h in hosts if h.services]
    web_servers = [h for h in servers if 80 in h.services or 8080 in h.services]
    ssh_servers = [h for h in servers if 22 in h.services]
    clients = [h for h in hosts if not h.services]

    w = Writer(path, rng)
    seq = 0
    while w.count < target:
        client = rng.choice(clients)
        roll = rng.random()
        if roll < 0.45:
            server = rng.choice(web_servers)
            dns_lookup(w, client, dns_server, server.name.lower() + ".office.example", server.ip, rng)
            w.advance(0.002)
            http_conversation(w, client, server, gateway.mac, rng)
        elif roll < 0.65:
            ssh_banner(w, client, rng.choice(ssh_servers), rng)
        elif roll < 0.85:
            server = rng.choice(servers)
            dns_lookup(w, client, dns_server, server.name.lower() + ".office.example", server.ip, rng)
        elif roll < 0.95:
            seq += 1
            ping(w, client, rng.choice(hosts + [gateway]), seq & 0xFFFF)
        elif roll < 0.97:
            arp_exchange(w, client, gateway)
        else:
            dhcp_exchange(w, client, gateway, rng)
        w.advance(0.004)
    w.close()
    print("wrote %d packets to %s" % (w.count, path))


if __name__ == "__main__":
    main()
