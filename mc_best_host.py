#!/usr/bin/env python3
"""
mc_best_host.py - find the fastest address to reach a Minecraft server from where you are.

Give it a server address. It asks several public DNS resolvers where the name points (large networks
and DDoS-protection proxies often hand out different addresses depending on who asks), then times
every address it finds with real connections and Minecraft status pings, and ranks them.

Standard library only. Python 3.8+.

    python mc_best_host.py mc.example.net
    python mc_best_host.py play.example.net:25570 --samples 12 --trace --geo
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import platform
import random
import socket
import statistics
import struct
import subprocess
import sys
import time
import urllib.request

DEFAULT_PORT = 25565
# Protocol number sent in the status handshake. Servers answer a status request for any value.
PROTOCOL = 772  # Minecraft 1.21.8

# Public resolvers. They sit in different places, so geo-aware DNS often answers differently for each.
PUBLIC_RESOLVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("AdGuard", "94.140.14.14"),
    ("Yandex", "77.88.8.8"),
    ("Level3", "4.2.2.2"),
    ("CleanBrowsing", "185.228.168.9"),
]

# Words in a CNAME chain that mean "this name is fronted by a proxy / DDoS protection".
PROXY_HINTS = ("tcpshield", "cloudflare", "spectrum", "ddos-guard", "ddosguard", "path.net", "voxility",
               "stormwall", "gcore", "nexusguard", "mcprotect", "mcshield")

TYPE_A, TYPE_CNAME, TYPE_SRV = 1, 5, 33


# --------------------------------------------------------------------------- minimal DNS client

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, off: int):
    labels, end, hops = [], None, 0
    while True:
        if off >= len(data) or hops > 30:
            raise ValueError("bad DNS name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            continue
        labels.append(data[off + 1: off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def dns_query(resolver: str, name: str, qtype: int, timeout: float = 2.0):
    """One UDP DNS query. Returns a list of ('A', ip) / ('CNAME', name) / ('SRV', (prio, weight, port, target))."""
    tid = random.randrange(0, 65536)
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (resolver, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x000F:  # non-zero RCODE
        return []
    off = 12
    for _ in range(qdcount):
        _, off = _read_name(data, off)
        off += 4
    answers = []
    for _ in range(ancount):
        _, off = _read_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off: off + 10])
        off += 10
        rdata = off
        off += rdlen
        if rtype == TYPE_A and rdlen == 4:
            answers.append(("A", socket.inet_ntoa(data[rdata: rdata + 4])))
        elif rtype == TYPE_CNAME:
            target, _ = _read_name(data, rdata)
            answers.append(("CNAME", target))
        elif rtype == TYPE_SRV:
            prio, weight, port = struct.unpack(">HHH", data[rdata: rdata + 6])
            target, _ = _read_name(data, rdata + 6)
            answers.append(("SRV", (prio, weight, port, target)))
    return answers


def _safe_query(resolver: str, name: str, qtype: int, timeout: float):
    try:
        return dns_query(resolver, name, qtype, timeout)
    except (OSError, ValueError, struct.error):
        return []


def collect_addresses(host: str, resolvers, timeout: float):
    """Ask every resolver for the A records of `host`. Returns (ip -> sorted resolver names, cname chain)."""
    seen: dict[str, set[str]] = {}
    cnames: list[str] = []

    def ask(item):
        label, ip = item
        return label, _safe_query(ip, host, TYPE_A, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(resolvers))) as pool:
        for label, answers in pool.map(ask, resolvers):
            for kind, value in answers:
                if kind == "A":
                    seen.setdefault(value, set()).add(label)
                elif kind == "CNAME" and value not in cnames:
                    cnames.append(value)

    # The computer's own resolver too: it is the one the game would really use.
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            seen.setdefault(info[4][0], set()).add("this computer")
    except OSError:
        pass
    return {ip: sorted(names) for ip, names in seen.items()}, cnames


def find_srv(host: str, resolvers, timeout: float):
    """Minecraft clients look up _minecraft._tcp.<host> first. Returns (target, port) or None."""
    for _, ip in resolvers:
        answers = _safe_query(ip, "_minecraft._tcp." + host, TYPE_SRV, timeout)
        records = [v for kind, v in answers if kind == "SRV"]
        if records:
            records.sort(key=lambda r: (r[0], -r[1]))
            _, _, port, target = records[0]
            return target, port
    return None


# --------------------------------------------------------------------------- probes

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def _read_varint(sock: socket.socket) -> int:
    result = shift = 0
    while True:
        b = _recv_exact(sock, 1)[0]
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result
        shift += 7
        if shift > 35:
            raise ValueError("varint too long")


def _packet(payload: bytes) -> bytes:
    return _varint(len(payload)) + payload


def tcp_connect_ms(ip: str, port: int, timeout: float) -> float:
    start = time.perf_counter()
    sock = socket.create_connection((ip, port), timeout=timeout)
    elapsed = (time.perf_counter() - start) * 1000.0
    sock.close()
    return elapsed


def status_ping(ip: str, port: int, handshake_host: str, timeout: float):
    """Minecraft server-list ping. Returns (first_byte_ms, pong_ms) or raises."""
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        host_bytes = handshake_host.encode("utf-8")
        handshake = _packet(_varint(0) + _varint(PROTOCOL) + _varint(len(host_bytes)) + host_bytes
                            + struct.pack(">H", port) + _varint(1))
        request = _packet(_varint(0))
        start = time.perf_counter()
        sock.sendall(handshake + request)
        _read_varint(sock)                      # packet length
        _read_varint(sock)                      # packet id (0 = status response)
        json_len = _read_varint(sock)
        _recv_exact(sock, json_len)
        status_ms = (time.perf_counter() - start) * 1000.0
        start = time.perf_counter()
        sock.sendall(_packet(_varint(1) + struct.pack(">q", int(time.time() * 1000))))
        _read_varint(sock)
        _read_varint(sock)
        _recv_exact(sock, 8)
        pong_ms = (time.perf_counter() - start) * 1000.0
        return status_ms, pong_ms
    finally:
        sock.close()


def probe(ip: str, port: int, handshake_host: str, samples: int, timeout: float) -> dict:
    tcp, status, pong, failures = [], [], [], 0
    for _ in range(samples):
        try:
            tcp.append(tcp_connect_ms(ip, port, timeout))
        except OSError:
            failures += 1
        try:
            s, p = status_ping(ip, port, handshake_host, timeout)
            status.append(s)
            pong.append(p)
        except (OSError, ValueError):
            pass
        time.sleep(0.12)

    def med(values):
        return statistics.median(values) if values else None

    return {
        "ip": ip,
        "tcp_ms": med(tcp),
        "status_ms": med(status),
        "pong_ms": med(pong),
        "pong_min_ms": min(pong) if pong else None,
        "jitter_ms": statistics.pstdev(pong) if len(pong) > 1 else 0.0,
        "answered": len(pong),
        "samples": samples,
        "tcp_failures": failures,
    }


# --------------------------------------------------------------------------- optional extras

def geolocate(ip: str):
    """Opt-in (--geo): asks ip-api.com where a PUBLIC server address is. Sends only that address."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as"
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            return f"{data.get('city', '?')}, {data.get('country', '?')} ({data.get('as', data.get('isp', '?'))})"
    except (OSError, ValueError):
        pass
    return None


def traceroute(ip: str) -> str:
    if platform.system() == "Windows":
        cmd = ["tracert", "-d", "-h", "20", "-w", "800", ip]
    else:
        cmd = ["traceroute", "-n", "-m", "20", "-w", "1", ip]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"(could not run {cmd[0]}: {exc})"


# --------------------------------------------------------------------------- main

def parse_target(text: str):
    text = text.strip()
    for prefix in ("minecraft://", "mc://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
    text = text.rstrip("/")
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, int(port)
    return text, DEFAULT_PORT


def fmt(value, width=7):
    return f"{value:{width}.1f}" if value is not None else " " * (width - 1) + "-"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Find the fastest address to reach a Minecraft server from here.")
    ap.add_argument("server", nargs="?", help="server address, e.g. mc.example.net or play.example.net:25570")
    ap.add_argument("--samples", type=int, default=8, help="measurements per address (default 8)")
    ap.add_argument("--timeout", type=float, default=3.0, help="seconds to wait per connection (default 3)")
    ap.add_argument("--resolver", action="append", default=[], metavar="IP",
                    help="extra DNS resolver to ask (repeatable)")
    ap.add_argument("--geo", action="store_true", help="look up where each address is (sends addresses to ip-api.com)")
    ap.add_argument("--trace", action="store_true", help="run traceroute to the best address")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON only")
    args = ap.parse_args(argv)

    target = args.server or input("Minecraft server address: ").strip()
    if not target:
        ap.error("no server address given")
    host, port = parse_target(target)
    resolvers = list(PUBLIC_RESOLVERS) + [(f"custom {ip}", ip) for ip in args.resolver]
    log = (lambda *a, **k: None) if args.json else print

    log(f"Server: {host}:{port}")
    srv = find_srv(host, resolvers, args.timeout)
    handshake_host, lookup_host = host, host
    if srv:
        lookup_host, port = srv[0], srv[1]
        log(f"SRV record: the game really connects to {lookup_host}:{port}")

    log(f"Asking {len(resolvers)} public DNS resolvers (plus this computer) where {lookup_host} points...")
    addresses, cnames = collect_addresses(lookup_host, resolvers, args.timeout)
    if not addresses:
        print("No addresses found. Check the name, or try --resolver with a resolver you trust.", file=sys.stderr)
        return 2
    proxies = sorted({h for c in cnames for h in PROXY_HINTS if h in c.lower()})
    if cnames:
        log("CNAME chain: " + " -> ".join(cnames))
    log(f"Found {len(addresses)} address(es). Measuring each ({args.samples} samples)...\n")

    results = []
    for ip in addresses:
        r = probe(ip, port, handshake_host, args.samples, args.timeout)
        r["seen_via"] = addresses[ip]
        results.append(r)

    def rank_key(r):
        value = r["pong_ms"] if r["pong_ms"] is not None else r["tcp_ms"]
        return (value is None, value if value is not None else 0.0)

    results.sort(key=rank_key)
    best = next((r for r in results if rank_key(r)[0] is False), None)

    if args.geo:
        for r in results:
            r["location"] = geolocate(r["ip"])

    if args.json:
        print(json.dumps({"server": host, "port": port, "handshake_host": handshake_host,
                          "proxy_hints": proxies, "results": results,
                          "best": best["ip"] if best else None}, indent=2))
        return 0

    header = f"{'address':<16} {'tcp ms':>7} {'status':>7} {'pong ms':>8} {'jitter':>7} {'ok':>5}  seen via"
    print(header)
    print("-" * len(header))
    for r in results:
        mark = "  <== best" if best and r["ip"] == best["ip"] else ""
        names = r["seen_via"]
        via = ", ".join(names) if len(names) <= 3 else f"{len(names)} resolvers" + (
            " (incl. this computer)" if "this computer" in names else "")
        print(f"{r['ip']:<16} {fmt(r['tcp_ms'])} {fmt(r['status_ms'])} {fmt(r['pong_ms'], 8)} {fmt(r['jitter_ms'])} "
              f"{r['answered']:>2}/{r['samples']:<2}  {via}{mark}")
        if args.geo and r.get("location"):
            print(f"{'':<16} {r['location']}")

    if not best:
        print("\nNo address answered. The server may be offline or blocking status pings.")
        return 1

    best_ms = best["pong_ms"] if best["pong_ms"] is not None else best["tcp_ms"]
    print(f"\nFastest address for you: {best['ip']}  (~{best_ms:.1f} ms)")
    close = [r["ip"] for r in results
             if r is not best and r["pong_ms"] is not None and best["pong_ms"] is not None
             and r["pong_ms"] - best["pong_ms"] < max(1.5, best["jitter_ms"] * 2)]
    if close:
        print(f"Within measurement noise of it (equally good): {', '.join(close)}")
    system_choice = [r for r in results if "this computer" in r["seen_via"]]
    if system_choice and system_choice[0]["ip"] == best["ip"]:
        print("Your own DNS already gives you this address, so you are already on the best one.")
    else:
        print("\nTo use it, point the server name at that address in your hosts file:")
        print(f"    {best['ip']} {lookup_host}")
        if platform.system() == "Windows":
            print(r"  (edit C:\Windows\System32\drivers\etc\hosts as Administrator; remove the line to undo)")
        else:
            print("  (edit /etc/hosts as root; remove the line to undo)")
        print("  This only works if you join by that name, not by typing the raw IP.")

    # Who answered the status ping? A plain TCP connect only reaches the first machine on the path.
    # If the pong takes about as long as that, the first machine (a proxy, or the server itself)
    # answered it. If it takes clearly longer, the ping was passed on to the real server.
    if best["tcp_ms"] is not None and best["pong_ms"] is not None:
        extra = best["pong_ms"] - best["tcp_ms"]
        if extra > max(3.0, 0.25 * best["tcp_ms"]):
            print(f"\nThe status ping took {extra:.0f} ms longer than a plain connection, so it was passed on to the")
            print("real server: the pong time above is a good estimate of your in-game ping.")
        elif proxies:
            print(f"\nNote: this name is fronted by a proxy ({', '.join(proxies)}) and the proxy answered the ping.")
            print("These numbers measure you -> proxy only. Your in-game ping also includes the proxy -> real")
            print("server leg, which this tool cannot see and no address choice can change.")
        else:
            print("\nThe nearest machine answered the ping. If the server sits behind a proxy, your in-game")
            print("ping also includes the proxy -> real server leg, which this tool cannot see.")

    if args.trace:
        print(f"\nTraceroute to {best['ip']}:\n")
        print(traceroute(best["ip"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
