#!/usr/bin/env python3
"""
Advanced Internet Audit

Run a network-engineer style internet health check and produce:
  - JSON raw data report
  - Markdown executive report
  - Separate capabilities report
  - Interactive HTML world route map from traceroute geolocation

Notes:
  - Only test networks and targets you are allowed to test.
  - Router geolocation is approximate. ISPs often register router IPs far from
    the physical device, so the map is a useful clue, not a legal-grade trace.
  - Richer speed tests are enabled when `speedtest-cli` is installed.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import html
import http.client
import ipaddress
import json
import math
import os
import platform
import random
import re
import shutil
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


CAPABILITIES = [
    "Public IP discovery and local machine/network identity",
    "Operating system, Python runtime, hostname, local IP, and default gateway detection",
    "Interface counters and interface status when psutil is installed",
    "ICMP latency, packet loss, minimum/average/maximum RTT, and jitter estimation",
    "TCP connection latency to common service ports",
    "DNS timing using the operating system resolver",
    "Direct UDP DNS resolver checks against 1.1.1.1, 8.8.8.8, and 9.9.9.9",
    "Low-level DNS record type checks for A, AAAA, CNAME, MX, TXT, NS, and PTR",
    "Custom ICMP ping payload size for packet-size and path sensitivity checks",
    "HTTP and HTTPS timing split into DNS, TCP connect, TLS handshake, TTFB, and total time",
    "Optional Ookla-style speed test when speedtest-cli is installed",
    "Fallback HTTP download throughput test when speedtest-cli is unavailable",
    "Traceroute or tracert hop discovery",
    "Traceroute probe mode selection where supported: UDP, ICMP, or TCP",
    "Public-hop geolocation for route visualization",
    "Interactive HTML world map with hop markers and route polyline",
    "Watch mode for repeated traceroute snapshots and auto-refreshing route map",
    "IPv4 path MTU probing where the local ping command supports do-not-fragment flags",
    "Automated findings with network-engineer style thresholds",
    "JSON report for machines and Markdown report for humans",
]


DEFAULT_PING_TARGETS = ["1.1.1.1", "8.8.8.8", "cloudflare.com", "google.com"]
DEFAULT_DOMAINS = ["cloudflare.com", "google.com", "github.com", "openai.com"]
DEFAULT_URLS = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/generate_204",
    "https://github.com/",
]
DEFAULT_TCP_TARGETS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("cloudflare.com", 443),
    ("google.com", 443),
    ("github.com", 443),
]
DEFAULT_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DNS_QTYPE_BY_NAME = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
DNS_QTYPE_NAMES = {value: key for key, value in DNS_QTYPE_BY_NAME.items()}
DEFAULT_DNS_QTYPES = ["A", "AAAA"]
TRACEROUTE_MODES = {"udp", "icmp", "tcp"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def monotonic_ms() -> float:
    return time.perf_counter() * 1000.0


def safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    sorted_values = sorted(values)
    index = (len(sorted_values) - 1) * pct
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return sorted_values[int(index)]
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (index - lower)


def ms(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1f} ms"


def mbps(bits_per_second: Optional[float]) -> str:
    if bits_per_second is None:
        return "n/a"
    return f"{bits_per_second / 1_000_000:.2f} Mbps"


def run_command(args: List[str], timeout: int = 30) -> Dict[str, Any]:
    started = monotonic_ms()
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration_ms": monotonic_ms() - started,
            "command": args,
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"Command not found: {args[0]}",
            "duration_ms": monotonic_ms() - started,
            "command": args,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"Timed out after {timeout}s",
            "duration_ms": monotonic_ms() - started,
            "command": args,
        }


def url_json(url: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "advanced-internet-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1024 * 1024)
        return json.loads(body.decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def url_text(url: str, timeout: int = 8, max_bytes: int = 1024 * 1024) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "advanced-internet-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(parsed.is_global)


def get_public_ip() -> Dict[str, Any]:
    providers = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.co/json",
    ]
    for url in providers:
        data = url_json(url, timeout=8)
        if data:
            ip = data.get("ip") or data.get("query")
            if ip:
                return {"ip": ip, "provider": url, "raw": data}
    text = url_text("https://ifconfig.me/ip", timeout=8, max_bytes=256)
    if text:
        return {"ip": text.strip(), "provider": "https://ifconfig.me/ip", "raw": text.strip()}
    return {"ip": None, "error": "Unable to discover public IP"}


def get_local_ip() -> Optional[str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        if sock:
            sock.close()


def get_default_gateway() -> Dict[str, Any]:
    system = platform.system().lower()
    if system == "linux":
        result = run_command(["ip", "route", "show", "default"], timeout=5)
        gateway = None
        interface = None
        match = re.search(r"default via (\S+).*?\bdev\s+(\S+)", result["stdout"])
        if match:
            gateway, interface = match.group(1), match.group(2)
        return {"gateway": gateway, "interface": interface, "raw": result}
    if system == "darwin":
        result = run_command(["route", "-n", "get", "default"], timeout=5)
        gateway = None
        interface = None
        gw_match = re.search(r"gateway:\s*(\S+)", result["stdout"])
        if_match = re.search(r"interface:\s*(\S+)", result["stdout"])
        if gw_match:
            gateway = gw_match.group(1)
        if if_match:
            interface = if_match.group(1)
        return {"gateway": gateway, "interface": interface, "raw": result}
    if system == "windows":
        result = run_command(["powershell", "-NoProfile", "-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ConvertTo-Json"], timeout=10)
        return {"gateway": None, "interface": None, "raw": result}
    return {"gateway": None, "interface": None, "raw": {"error": f"Unsupported system: {system}"}}


def get_interface_snapshot() -> Dict[str, Any]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return {"available": False, "reason": "Install psutil for interface counters"}

    stats = {}
    try:
        for name, item in psutil.net_if_stats().items():
            stats[name] = {
                "isup": item.isup,
                "duplex": str(item.duplex),
                "speed_mbps": item.speed,
                "mtu": item.mtu,
            }
        counters = {}
        pernic = psutil.net_io_counters(pernic=True)
        for name, item in pernic.items():
            counters[name] = {
                "bytes_sent": item.bytes_sent,
                "bytes_recv": item.bytes_recv,
                "packets_sent": item.packets_sent,
                "packets_recv": item.packets_recv,
                "errin": item.errin,
                "errout": item.errout,
                "dropin": item.dropin,
                "dropout": item.dropout,
            }
    except OSError as exc:
        return {"available": False, "reason": f"Interface counters unavailable: {exc}"}
    return {"available": True, "stats": stats, "counters": counters}


def collect_identity() -> Dict[str, Any]:
    return {
        "generated_at_utc": utc_now(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "python": sys.version.replace("\n", " "),
        "local_ip": get_local_ip(),
        "public_ip": get_public_ip(),
        "default_gateway": get_default_gateway(),
        "interfaces": get_interface_snapshot(),
    }


def ping_command(target: str, count: int, timeout_s: int, payload_size: int = 56) -> List[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout_s * 1000), "-l", str(payload_size), target]
    if system == "darwin":
        return ["ping", "-c", str(count), "-W", str(timeout_s * 1000), "-s", str(payload_size), target]
    return ["ping", "-c", str(count), "-W", str(timeout_s), "-s", str(payload_size), target]


def parse_ping_output(output: str) -> Dict[str, Any]:
    rtts = [float(x) for x in re.findall(r"time[=<]\s*([0-9.]+)\s*ms", output, flags=re.I)]
    loss = None
    transmitted = None
    received = None

    unix_summary = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received.*?([0-9.]+)%\s+packet loss", output, flags=re.I | re.S)
    if unix_summary:
        transmitted = int(unix_summary.group(1))
        received = int(unix_summary.group(2))
        loss = float(unix_summary.group(3))

    win_summary = re.search(r"Packets:\s+Sent\s+=\s+(\d+),\s+Received\s+=\s+(\d+),\s+Lost\s+=\s+\d+\s+\(([0-9.]+)%\s+loss\)", output, flags=re.I)
    if win_summary:
        transmitted = int(win_summary.group(1))
        received = int(win_summary.group(2))
        loss = float(win_summary.group(3))

    if loss is None and transmitted and received is not None:
        loss = ((transmitted - received) / transmitted) * 100.0

    avg = statistics.mean(rtts) if rtts else None
    jitter = None
    if len(rtts) >= 2:
        diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        jitter = statistics.mean(diffs)

    return {
        "packet_loss_pct": loss,
        "transmitted": transmitted,
        "received": received,
        "rtt_samples_ms": rtts,
        "min_ms": min(rtts) if rtts else None,
        "avg_ms": avg,
        "max_ms": max(rtts) if rtts else None,
        "p95_ms": percentile(rtts, 0.95),
        "jitter_ms": jitter,
    }


def ping_target(target: str, count: int, timeout_s: int, payload_size: int = 56) -> Dict[str, Any]:
    cmd = ping_command(target, count, timeout_s, payload_size)
    raw = run_command(cmd, timeout=max(timeout_s * count + 5, 15))
    parsed = parse_ping_output(raw["stdout"] + "\n" + raw["stderr"])
    return {"target": target, "payload_size_bytes": payload_size, "ok": raw["ok"], **parsed, "raw": raw}


def tcp_connect_test(host: str, port: int, timeout_s: int = 5, attempts: int = 3) -> Dict[str, Any]:
    samples = []
    errors = []
    for _ in range(attempts):
        started = monotonic_ms()
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                samples.append(monotonic_ms() - started)
        except OSError as exc:
            errors.append(str(exc))
    return {
        "host": host,
        "port": port,
        "attempts": attempts,
        "successes": len(samples),
        "connect_samples_ms": samples,
        "avg_connect_ms": statistics.mean(samples) if samples else None,
        "min_connect_ms": min(samples) if samples else None,
        "max_connect_ms": max(samples) if samples else None,
        "errors": errors[:3],
    }


def system_dns_lookup(domain: str) -> Dict[str, Any]:
    started = monotonic_ms()
    try:
        answers = socket.getaddrinfo(domain, None)
        elapsed = monotonic_ms() - started
        ips = sorted({item[4][0] for item in answers})
        return {"domain": domain, "ok": True, "duration_ms": elapsed, "answers": ips}
    except socket.gaierror as exc:
        return {"domain": domain, "ok": False, "duration_ms": monotonic_ms() - started, "error": str(exc), "answers": []}


def encode_dns_name(domain: str) -> bytes:
    parts = domain.rstrip(".").split(".")
    encoded = bytearray()
    for part in parts:
        raw = part.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {part}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def read_dns_name(packet: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    if depth > 10:
        raise ValueError("DNS compression pointer loop")
    labels = []
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            label, _ = read_dns_name(packet, pointer, depth + 1)
            labels.append(label)
            offset += 2
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(label for label in labels if label), offset


def parse_dns_qtypes(items: Optional[List[str]]) -> List[int]:
    if not items:
        return [DNS_QTYPE_BY_NAME[name] for name in DEFAULT_DNS_QTYPES]
    qtypes = []
    for item in items:
        raw = str(item).strip().upper()
        if not raw:
            continue
        if raw.isdigit():
            qtype = int(raw)
        else:
            if raw not in DNS_QTYPE_BY_NAME:
                supported = ", ".join(sorted(DNS_QTYPE_BY_NAME))
                raise ValueError(f"Unsupported DNS type {item}. Supported: {supported}")
            qtype = DNS_QTYPE_BY_NAME[raw]
        if qtype not in qtypes:
            qtypes.append(qtype)
    return qtypes or [DNS_QTYPE_BY_NAME[name] for name in DEFAULT_DNS_QTYPES]


def decode_dns_rdata(packet: bytes, rdata_offset: int, rdata: bytes, atype: int) -> Any:
    if atype == 1 and len(rdata) == 4:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if atype == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if atype in {2, 5, 12}:
        value, _ = read_dns_name(packet, rdata_offset)
        return value
    if atype == 15 and len(rdata) >= 3:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = read_dns_name(packet, rdata_offset + 2)
        return {"preference": preference, "exchange": exchange}
    if atype == 16:
        texts = []
        index = 0
        while index < len(rdata):
            length = rdata[index]
            index += 1
            texts.append(rdata[index : index + length].decode("utf-8", "replace"))
            index += length
        return texts
    if atype == 6:
        mname, offset = read_dns_name(packet, rdata_offset)
        rname, offset = read_dns_name(packet, offset)
        if offset + 20 <= rdata_offset + len(rdata):
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", packet[offset : offset + 20])
            return {
                "mname": mname,
                "rname": rname,
                "serial": serial,
                "refresh": refresh,
                "retry": retry,
                "expire": expire,
                "minimum": minimum,
            }
        return {"mname": mname, "rname": rname}
    return base64.b64encode(rdata).decode("ascii")


def udp_dns_query(server: str, domain: str, qtype: int = 1, timeout_s: int = 3) -> Dict[str, Any]:
    query_id = random.randint(0, 65535)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    packet += encode_dns_name(domain)
    packet += struct.pack("!HH", qtype, 1)

    started = monotonic_ms()
    sock = None
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        elapsed = monotonic_ms() - started
    except OSError as exc:
        return {"server": server, "domain": domain, "qtype": qtype, "qtype_name": DNS_QTYPE_NAMES.get(qtype, str(qtype)), "ok": False, "duration_ms": monotonic_ms() - started, "error": str(exc), "answers": []}
    finally:
        if sock:
            sock.close()

    try:
        rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        rcode = flags & 0x000F
        offset = 12
        for _ in range(qdcount):
            _, offset = read_dns_name(data, offset)
            offset += 4

        answers = []
        for _ in range(ancount):
            name, offset = read_dns_name(data, offset)
            atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            value = decode_dns_rdata(data, rdata_offset, rdata, atype)
            if value:
                answers.append({"name": name, "type": atype, "type_name": DNS_QTYPE_NAMES.get(atype, str(atype)), "class": aclass, "ttl": ttl, "value": value})
        return {
            "server": server,
            "domain": domain,
            "qtype": qtype,
            "qtype_name": DNS_QTYPE_NAMES.get(qtype, str(qtype)),
            "ok": rid == query_id and rcode == 0,
            "duration_ms": elapsed,
            "rcode": rcode,
            "answers": answers,
        }
    except (ValueError, struct.error, IndexError) as exc:
        return {"server": server, "domain": domain, "qtype": qtype, "qtype_name": DNS_QTYPE_NAMES.get(qtype, str(qtype)), "ok": False, "duration_ms": elapsed, "error": f"Parse error: {exc}", "answers": []}


def http_timing(url: str, timeout_s: int = 10, max_bytes: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    if not host:
        return {"url": url, "ok": False, "error": "URL missing host"}
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    result: Dict[str, Any] = {"url": url, "scheme": scheme, "host": host, "port": port}
    total_started = monotonic_ms()
    sock: Optional[socket.socket] = None
    try:
        dns_started = monotonic_ms()
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        result["dns_ms"] = monotonic_ms() - dns_started
        result["resolved_ips"] = sorted({item[4][0] for item in infos})

        family, socktype, proto, _, sockaddr = infos[0]
        raw_sock = socket.socket(family, socktype, proto)
        raw_sock.settimeout(timeout_s)
        connect_started = monotonic_ms()
        raw_sock.connect(sockaddr)
        result["tcp_connect_ms"] = monotonic_ms() - connect_started

        if scheme == "https":
            tls_started = monotonic_ms()
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw_sock, server_hostname=host)
            result["tls_handshake_ms"] = monotonic_ms() - tls_started
            cert = sock.getpeercert()
            if cert:
                result["tls_subject"] = cert.get("subject")
                result["tls_not_after"] = cert.get("notAfter")
        else:
            sock = raw_sock
            result["tls_handshake_ms"] = None

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: advanced-internet-audit/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "replace")

        sent_at = monotonic_ms()
        sock.sendall(request)
        received = bytearray()
        first_byte_at = None
        while len(received) < max_bytes:
            chunk = sock.recv(16384)
            if not chunk:
                break
            if first_byte_at is None:
                first_byte_at = monotonic_ms()
            received.extend(chunk)

        result["ttfb_ms"] = (first_byte_at - sent_at) if first_byte_at is not None else None
        result["total_ms"] = monotonic_ms() - total_started
        result["bytes_read"] = len(received)
        header_end = received.find(b"\r\n\r\n")
        if header_end != -1:
            header = received[:header_end].decode("iso-8859-1", "replace")
            first_line = header.splitlines()[0] if header.splitlines() else ""
            status_match = re.search(r"HTTP/\S+\s+(\d+)", first_line)
            if status_match:
                result["status_code"] = int(status_match.group(1))
        result["ok"] = True
        return result
    except (OSError, ssl.SSLError, socket.gaierror) as exc:
        result["ok"] = False
        result["error"] = str(exc)
        result["total_ms"] = monotonic_ms() - total_started
        return result
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def run_speedtest(skip: bool) -> Dict[str, Any]:
    if skip:
        return {"skipped": True, "reason": "Skipped by user"}
    try:
        import speedtest  # type: ignore
    except ImportError:
        return fallback_download_test()

    try:
        started = monotonic_ms()
        st = speedtest.Speedtest()
        st.get_best_server()
        download_bps = st.download()
        upload_bps = st.upload(pre_allocate=False)
        data = st.results.dict()
        return {
            "engine": "speedtest-cli",
            "ok": True,
            "duration_ms": monotonic_ms() - started,
            "download_bps": download_bps,
            "upload_bps": upload_bps,
            "ping_ms": data.get("ping"),
            "server": data.get("server"),
            "client": data.get("client"),
            "raw": data,
        }
    except Exception as exc:
        fallback = fallback_download_test()
        fallback["speedtest_cli_error"] = str(exc)
        return fallback


def fallback_download_test() -> Dict[str, Any]:
    urls = [
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://proof.ovh.net/files/10Mb.dat",
    ]
    results = []
    for url in urls:
        started = monotonic_ms()
        bytes_read = 0
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "advanced-internet-audit/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                while True:
                    chunk = resp.read(128 * 1024)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
            elapsed_s = (monotonic_ms() - started) / 1000.0
            bps = (bytes_read * 8) / elapsed_s if elapsed_s else None
            results.append({"url": url, "ok": True, "bytes": bytes_read, "seconds": elapsed_s, "download_bps": bps})
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            results.append({"url": url, "ok": False, "bytes": bytes_read, "error": str(exc)})

    good = [item["download_bps"] for item in results if item.get("ok") and item.get("download_bps")]
    return {
        "engine": "fallback-http-download",
        "ok": bool(good),
        "download_bps": max(good) if good else None,
        "upload_bps": None,
        "note": "Install speedtest-cli for a fuller download/upload/ping speed test",
        "raw": results,
    }


def traceroute_command(target: str, max_hops: int, timeout_s: int, probes: int, mode: str = "udp", tcp_port: int = 443) -> Optional[List[str]]:
    system = platform.system().lower()
    mode = mode.lower()
    if system == "windows":
        if shutil.which("tracert"):
            return ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_s * 1000), target]
        return None
    if shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_s), "-q", str(probes)]
        if mode == "icmp":
            cmd.append("-I")
        elif mode == "tcp":
            cmd.extend(["-T", "-p", str(tcp_port)])
        cmd.append(target)
        return cmd
    if shutil.which("tracepath") and system == "linux":
        return ["tracepath", "-n", "-m", str(max_hops), target]
    return None


def parse_traceroute_output(output: str) -> List[Dict[str, Any]]:
    hops: List[Dict[str, Any]] = []
    ip_re = re.compile(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})")
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+):?\s+(.+)$", line)
        if not match:
            continue
        hop_no = int(match.group(1))
        rest = match.group(2)
        ips = []
        for candidate in ip_re.findall(rest):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in ips:
                ips.append(candidate)
        times = [float(x) for x in re.findall(r"([0-9.]+)\s*ms", rest)]
        hops.append(
            {
                "hop": hop_no,
                "ips": ips,
                "primary_ip": ips[0] if ips else None,
                "rtt_ms": statistics.mean(times) if times else None,
                "samples_ms": times,
                "raw_line": line.strip(),
            }
        )
    return hops


def run_traceroute(target: str, max_hops: int, timeout_s: int, probes: int, mode: str = "udp", tcp_port: int = 443) -> Dict[str, Any]:
    if mode not in TRACEROUTE_MODES:
        return {"target": target, "ok": False, "error": f"Unsupported traceroute mode: {mode}", "mode": mode, "hops": []}
    cmd = traceroute_command(target, max_hops=max_hops, timeout_s=timeout_s, probes=probes, mode=mode, tcp_port=tcp_port)
    if not cmd:
        return {"target": target, "ok": False, "error": "No traceroute/tracert/tracepath command found", "mode": mode, "hops": []}
    raw = run_command(cmd, timeout=max(max_hops * timeout_s * probes + 10, 30))
    combined = raw["stdout"] + "\n" + raw["stderr"]
    hops = parse_traceroute_output(combined)
    return {"target": target, "ok": bool(hops), "mode": mode, "tcp_port": tcp_port if mode == "tcp" else None, "hops": hops, "raw": raw}


def geolocate_ip(ip: str) -> Dict[str, Any]:
    if not is_public_ip(ip):
        return {"query": ip, "status": "private_or_reserved"}
    url = (
        "http://ip-api.com/json/"
        + urllib.parse.quote(ip)
        + "?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
    )
    data = url_json(url, timeout=6)
    if not data:
        return {"query": ip, "status": "error", "message": "No geolocation response"}
    return data


def enrich_hops_with_geo(hops: List[Dict[str, Any]], skip_geo: bool = False) -> List[Dict[str, Any]]:
    if skip_geo:
        return [{**hop, "geo": {"status": "skipped"}} for hop in hops]
    cache: Dict[str, Dict[str, Any]] = {}
    enriched = []
    for hop in hops:
        ip = hop.get("primary_ip")
        geo = None
        if ip:
            if ip not in cache:
                cache[ip] = geolocate_ip(ip)
                time.sleep(0.2)
            geo = cache[ip]
        enriched.append({**hop, "geo": geo})
    return enriched


def mtu_ping_command(target: str, payload_size: int, timeout_s: int = 3) -> Optional[List[str]]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-f", "-l", str(payload_size), "-w", str(timeout_s * 1000), target]
    if system == "darwin":
        return ["ping", "-c", "1", "-D", "-s", str(payload_size), "-W", str(timeout_s * 1000), target]
    return ["ping", "-c", "1", "-M", "do", "-s", str(payload_size), "-W", str(timeout_s), target]


def mtu_payload_works(target: str, payload_size: int) -> bool:
    cmd = mtu_ping_command(target, payload_size)
    if not cmd:
        return False
    result = run_command(cmd, timeout=8)
    text = (result["stdout"] + "\n" + result["stderr"]).lower()
    if "100% packet loss" in text or "fragmentation needed" in text or "message too long" in text or "packet needs to be fragmented" in text:
        return False
    return result["ok"] and bool(re.search(r"time[=<]", text))


def probe_mtu(target: str, skip: bool = False) -> Dict[str, Any]:
    if skip:
        return {"skipped": True}
    try:
        ipaddress.ip_address(socket.gethostbyname(target))
    except OSError:
        return {"ok": False, "target": target, "error": "Unable to resolve IPv4 target for MTU probe"}

    low = 0
    high = 1472
    best = None
    while low <= high:
        mid = (low + high) // 2
        if mtu_payload_works(target, mid):
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    if best is None:
        return {"ok": False, "target": target, "error": "No successful do-not-fragment ping response"}
    return {"ok": True, "target": target, "max_payload_bytes": best, "estimated_ipv4_path_mtu": best + 28}


def write_route_map(
    traceroute: Dict[str, Any],
    output_path: Path,
    generated_at: str,
    auto_refresh_seconds: int = 0,
) -> None:
    route_points = []
    for hop in traceroute.get("hops", []):
        geo = hop.get("geo") or {}
        lat = safe_float(geo.get("lat"))
        lon = safe_float(geo.get("lon"))
        if lat is None or lon is None:
            continue
        route_points.append(
            {
                "hop": hop.get("hop"),
                "ip": hop.get("primary_ip"),
                "rtt_ms": hop.get("rtt_ms"),
                "lat": lat,
                "lon": lon,
                "city": geo.get("city"),
                "region": geo.get("regionName"),
                "country": geo.get("country"),
                "isp": geo.get("isp") or geo.get("org"),
                "asn": geo.get("as"),
            }
        )

    refresh = f'<meta http-equiv="refresh" content="{auto_refresh_seconds}">' if auto_refresh_seconds > 0 else ""
    payload = json.dumps(route_points, ensure_ascii=True)
    target = html.escape(str(traceroute.get("target", "unknown")))
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {refresh}
  <title>Internet Route Map - {target}</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <style>
    html, body, #map {{ height: 100%; margin: 0; font-family: Inter, Arial, sans-serif; }}
    .panel {{
      position: absolute; z-index: 1000; top: 16px; left: 16px; width: min(420px, calc(100vw - 32px));
      background: rgba(255,255,255,.94); border: 1px solid #d7dde8; border-radius: 8px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, .16); overflow: hidden;
    }}
    .panel header {{ padding: 12px 14px; border-bottom: 1px solid #e5e9f0; background: #f8fafc; }}
    .panel h1 {{ font-size: 15px; line-height: 1.25; margin: 0 0 3px; }}
    .panel .meta {{ color: #475569; font-size: 12px; }}
    .hop-list {{ max-height: 45vh; overflow: auto; padding: 8px 12px 12px; }}
    .hop {{ display: grid; grid-template-columns: 34px 1fr; gap: 8px; padding: 8px 0; border-bottom: 1px solid #edf1f7; }}
    .hop:last-child {{ border-bottom: 0; }}
    .badge {{ width: 28px; height: 28px; display: grid; place-items: center; border-radius: 999px; background: #0f766e; color: white; font-size: 12px; font-weight: 700; }}
    .main {{ font-size: 13px; color: #0f172a; }}
    .sub {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
    .empty {{ padding: 14px; font-size: 13px; color: #475569; }}
  </style>
</head>
<body>
  <div id="map"></div>
  <section class="panel">
    <header>
      <h1>Route to {target}</h1>
      <div class="meta">Generated {html.escape(generated_at)} UTC. Geolocation is approximate.</div>
    </header>
    <div id="hopList" class="hop-list"></div>
  </section>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    const hops = {payload};
    const map = L.map('map', {{ worldCopyJump: true }}).setView([20, 0], 2);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 18,
      attribution: '&copy; OpenStreetMap contributors'
    }}).addTo(map);

    const list = document.getElementById('hopList');
    if (!hops.length) {{
      list.innerHTML = '<div class="empty">No public hops could be geolocated. Private ISP hops and hidden routers are normal on many paths.</div>';
    }} else {{
      const latlngs = [];
      hops.forEach((hop) => {{
        const point = [hop.lat, hop.lon];
        latlngs.push(point);
        const label = `Hop ${{hop.hop}} - ${{hop.ip || 'unknown'}}`;
        const details = [hop.city, hop.region, hop.country].filter(Boolean).join(', ');
        const popup = `<strong>${{label}}</strong><br>${{details || 'Unknown location'}}<br>${{hop.isp || ''}}<br>${{hop.rtt_ms ? hop.rtt_ms.toFixed(1) + ' ms' : ''}}`;
        L.circleMarker(point, {{
          radius: 7,
          color: '#0f766e',
          fillColor: '#14b8a6',
          fillOpacity: 0.9,
          weight: 2
        }}).addTo(map).bindPopup(popup);

        const row = document.createElement('div');
        row.className = 'hop';
        row.innerHTML = `<div class="badge">${{hop.hop}}</div>
          <div><div class="main">${{hop.ip || 'unknown'}} - ${{details || 'Unknown location'}}</div>
          <div class="sub">${{hop.isp || 'Unknown ISP'}}${{hop.rtt_ms ? ' - ' + hop.rtt_ms.toFixed(1) + ' ms' : ''}}</div></div>`;
        list.appendChild(row);
      }});
      L.polyline(latlngs, {{ color: '#0f766e', weight: 3, opacity: .8 }}).addTo(map);
      map.fitBounds(latlngs, {{ padding: [70, 70] }});
    }}
  </script>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")


def write_capabilities(path: Path) -> None:
    lines = ["# Internet Audit Capabilities", ""]
    lines.extend(f"- {item}" for item in CAPABILITIES)
    lines.append("")
    lines.append("Recommended optional packages: `speedtest-cli` for fuller speed tests and `psutil` for interface counters.")
    path.write_text("\n".join(lines), encoding="utf-8")


def network_findings(report: Dict[str, Any]) -> List[str]:
    findings = []

    for item in report.get("latency", []):
        target = item.get("target")
        loss = item.get("packet_loss_pct")
        avg = item.get("avg_ms")
        jitter = item.get("jitter_ms")
        if loss is not None and loss >= 5:
            findings.append(f"High packet loss to {target}: {loss:.1f}%. This usually indicates congestion, Wi-Fi interference, ISP trouble, or filtering.")
        elif loss is not None and loss > 0:
            findings.append(f"Some packet loss to {target}: {loss:.1f}%. Re-test while idle and while loaded to separate baseline loss from bufferbloat/congestion.")
        if avg is not None and avg > 150:
            findings.append(f"High average latency to {target}: {avg:.1f} ms.")
        if jitter is not None and jitter > 30:
            findings.append(f"High jitter to {target}: {jitter:.1f} ms. Real-time voice/video/gaming may feel unstable.")

    dns_slow = [x for x in report.get("dns", {}).get("system", []) if x.get("duration_ms") and x["duration_ms"] > 150]
    if dns_slow:
        domains = ", ".join(x["domain"] for x in dns_slow[:4])
        findings.append(f"Slow system DNS lookups detected for: {domains}. Try a different resolver or inspect local DNS/proxy behavior.")

    for item in report.get("http", []):
        if not item.get("ok"):
            findings.append(f"HTTP test failed for {item.get('url')}: {item.get('error')}")
            continue
        if item.get("dns_ms") and item["dns_ms"] > 150:
            findings.append(f"Slow DNS phase for {item.get('url')}: {item['dns_ms']:.1f} ms.")
        if item.get("tcp_connect_ms") and item["tcp_connect_ms"] > 250:
            findings.append(f"Slow TCP connect for {item.get('url')}: {item['tcp_connect_ms']:.1f} ms.")
        if item.get("tls_handshake_ms") and item["tls_handshake_ms"] > 350:
            findings.append(f"Slow TLS handshake for {item.get('url')}: {item['tls_handshake_ms']:.1f} ms.")
        if item.get("ttfb_ms") and item["ttfb_ms"] > 800:
            findings.append(f"High time-to-first-byte for {item.get('url')}: {item['ttfb_ms']:.1f} ms.")

    mtu = report.get("mtu", {})
    if mtu.get("ok") and mtu.get("estimated_ipv4_path_mtu") and mtu["estimated_ipv4_path_mtu"] < 1400:
        findings.append(f"Low estimated path MTU: {mtu['estimated_ipv4_path_mtu']} bytes. VPN, PPPoE, or tunnel overhead may be involved.")

    speed = report.get("speed", {})
    if speed.get("ok") and speed.get("download_bps") is not None:
        down = speed["download_bps"] / 1_000_000
        if down < 10:
            findings.append(f"Low measured download throughput: {down:.2f} Mbps. Compare against your ISP plan using a wired test.")

    if not findings:
        findings.append("No obvious critical issue was detected by threshold checks. Compare repeated reports during good and bad periods for stronger evidence.")
    return findings


def markdown_table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        escaped = [html.escape(str(cell)) for cell in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return lines


def format_dns_answer_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value)


def write_markdown_report(report: Dict[str, Any], path: Path, map_path: Path, capabilities_path: Path) -> None:
    findings = report.get("findings", [])
    identity = report.get("identity", {})
    public_ip = identity.get("public_ip", {}).get("ip")
    gateway = identity.get("default_gateway", {})
    speed = report.get("speed", {})
    mtu = report.get("mtu", {})

    lines = [
        "# Advanced Internet Audit Report",
        "",
        f"Generated: `{report.get('generated_at_utc')}`",
        "",
        "## Executive Findings",
        "",
    ]
    lines.extend(f"- {item}" for item in findings)
    lines.extend(
        [
            "",
            "## Identity",
            "",
            f"- Hostname: `{identity.get('hostname')}`",
            f"- Local IP: `{identity.get('local_ip')}`",
            f"- Public IP: `{public_ip}`",
            f"- Default gateway: `{gateway.get('gateway')}` on `{gateway.get('interface')}`",
            f"- Platform: `{identity.get('platform')}`",
            "",
            "## Speed",
            "",
            f"- Engine: `{speed.get('engine', 'n/a')}`",
            f"- Download: `{mbps(speed.get('download_bps'))}`",
            f"- Upload: `{mbps(speed.get('upload_bps'))}`",
            f"- Ping: `{ms(speed.get('ping_ms'))}`",
            "",
            "## Latency And Loss",
            "",
        ]
    )

    rows = []
    for item in report.get("latency", []):
        rows.append(
            [
                item.get("target"),
                item.get("transmitted"),
                item.get("received"),
                f"{item.get('packet_loss_pct'):.1f}%" if item.get("packet_loss_pct") is not None else "n/a",
                ms(item.get("avg_ms")),
                ms(item.get("p95_ms")),
                ms(item.get("jitter_ms")),
            ]
        )
    lines.extend(markdown_table(["Target", "Sent", "Recv", "Loss", "Avg", "P95", "Jitter"], rows))

    lines.extend(["", "## TCP Connect", ""])
    tcp_rows = []
    for item in report.get("tcp_connect", []):
        tcp_rows.append([f"{item.get('host')}:{item.get('port')}", item.get("successes"), item.get("attempts"), ms(item.get("avg_connect_ms"))])
    lines.extend(markdown_table(["Target", "Success", "Attempts", "Avg Connect"], tcp_rows))

    lines.extend(["", "## DNS", ""])
    dns_rows = []
    for item in report.get("dns", {}).get("system", []):
        dns_rows.append([item.get("domain"), "system", "system", "yes" if item.get("ok") else "no", ms(item.get("duration_ms")), ", ".join(item.get("answers", [])[:3])])
    for item in report.get("dns", {}).get("direct", []):
        values = [format_dns_answer_value(answer.get("value")) for answer in item.get("answers", []) if answer.get("value")]
        dns_rows.append([item.get("domain"), item.get("server"), item.get("qtype_name", item.get("qtype")), "yes" if item.get("ok") else "no", ms(item.get("duration_ms")), ", ".join(values[:3])])
    lines.extend(markdown_table(["Domain", "Resolver", "Type", "OK", "Time", "Answers"], dns_rows))

    lines.extend(["", "## HTTP And TLS", ""])
    http_rows = []
    for item in report.get("http", []):
        http_rows.append(
            [
                item.get("url"),
                item.get("status_code", "n/a"),
                ms(item.get("dns_ms")),
                ms(item.get("tcp_connect_ms")),
                ms(item.get("tls_handshake_ms")),
                ms(item.get("ttfb_ms")),
                ms(item.get("total_ms")),
            ]
        )
    lines.extend(markdown_table(["URL", "Status", "DNS", "TCP", "TLS", "TTFB", "Total"], http_rows))

    lines.extend(["", "## Route", ""])
    route_rows = []
    for hop in report.get("traceroute", {}).get("hops", []):
        geo = hop.get("geo") or {}
        place = ", ".join([str(x) for x in [geo.get("city"), geo.get("regionName"), geo.get("country")] if x])
        route_rows.append([hop.get("hop"), hop.get("primary_ip"), ms(hop.get("rtt_ms")), place or geo.get("status", "n/a"), geo.get("isp") or geo.get("org") or "n/a"])
    lines.extend(markdown_table(["Hop", "IP", "RTT", "Approx Location", "ISP/Org"], route_rows))
    lines.extend(
        [
            "",
            f"Interactive route map: `{map_path.name}`",
            "",
            "## MTU",
            "",
            f"- Target: `{mtu.get('target')}`",
            f"- Estimated IPv4 path MTU: `{mtu.get('estimated_ipv4_path_mtu', 'n/a')}`",
            "",
            "## Capabilities",
            "",
            f"See `{capabilities_path.name}` for the separate capabilities list.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_tcp_targets(items: Optional[List[str]]) -> List[Tuple[str, int]]:
    if not items:
        return DEFAULT_TCP_TARGETS
    parsed = []
    for item in items:
        if ":" not in item:
            raise ValueError(f"TCP target must be host:port, got {item}")
        host, raw_port = item.rsplit(":", 1)
        parsed.append((host, int(raw_port)))
    return parsed


def run_full_audit(args: argparse.Namespace) -> Dict[str, Any]:
    generated_at = utc_now()
    report: Dict[str, Any] = {
        "generated_at_utc": generated_at,
        "capabilities": CAPABILITIES,
        "config": {
            "ping_targets": args.targets,
            "domains": args.domains,
            "urls": args.urls,
            "traceroute_target": args.traceroute_target,
            "traceroute_mode": args.traceroute_mode,
            "traceroute_tcp_port": args.traceroute_tcp_port,
            "dns_qtypes": args.dns_qtypes,
            "ping_count": args.ping_count,
            "ping_size": args.ping_size,
            "skip_speedtest": args.skip_speedtest,
            "skip_geo": args.skip_geo,
        },
    }

    report["identity"] = collect_identity()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        latency_futures = [executor.submit(ping_target, target, args.ping_count, args.ping_timeout, args.ping_size) for target in args.targets]
        tcp_futures = [executor.submit(tcp_connect_test, host, port, args.tcp_timeout, args.tcp_attempts) for host, port in parse_tcp_targets(args.tcp_targets)]
        dns_system_futures = [executor.submit(system_dns_lookup, domain) for domain in args.domains]
        http_futures = [executor.submit(http_timing, url, args.http_timeout) for url in args.urls]

        report["latency"] = [future.result() for future in concurrent.futures.as_completed(latency_futures)]
        report["tcp_connect"] = [future.result() for future in concurrent.futures.as_completed(tcp_futures)]
        dns_system = [future.result() for future in concurrent.futures.as_completed(dns_system_futures)]
        report["http"] = [future.result() for future in concurrent.futures.as_completed(http_futures)]

    direct_dns = []
    qtypes = parse_dns_qtypes(args.dns_qtypes)
    for domain in args.domains:
        for server in args.dns_servers:
            for qtype in qtypes:
                direct_dns.append(udp_dns_query(server, domain, qtype=qtype, timeout_s=args.dns_timeout))
    report["dns"] = {"system": dns_system, "direct": direct_dns}

    report["speed"] = run_speedtest(args.skip_speedtest)
    report["traceroute"] = run_traceroute(args.traceroute_target, args.max_hops, args.trace_timeout, args.trace_probes, args.traceroute_mode, args.traceroute_tcp_port)
    report["traceroute"]["hops"] = enrich_hops_with_geo(report["traceroute"].get("hops", []), args.skip_geo)
    report["mtu"] = probe_mtu(args.mtu_target, args.skip_mtu)
    report["findings"] = network_findings(report)
    return report


def write_outputs(report: Dict[str, Any], output_dir: Path, auto_refresh_seconds: int = 0) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "internet_audit_report.json"
    md_path = output_dir / "internet_audit_report.md"
    capabilities_path = output_dir / "internet_audit_capabilities.md"
    map_path = output_dir / "internet_route_map.html"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_capabilities(capabilities_path)
    write_route_map(report.get("traceroute", {}), map_path, report.get("generated_at_utc", utc_now()), auto_refresh_seconds)
    write_markdown_report(report, md_path, map_path, capabilities_path)
    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "capabilities": str(capabilities_path),
        "map": str(map_path),
    }


def append_watch_snapshot(path: Path, traceroute: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"generated_at_utc": utc_now(), "traceroute": traceroute}, sort_keys=True) + "\n")


def watch_route(args: argparse.Namespace, output_dir: Path) -> None:
    watch_path = output_dir / "route_watch.jsonl"
    live_map_path = output_dir / "internet_route_map.html"
    iteration = 0
    while True:
        iteration += 1
        traceroute = run_traceroute(args.traceroute_target, args.max_hops, args.trace_timeout, args.trace_probes)
        traceroute["hops"] = enrich_hops_with_geo(traceroute.get("hops", []), args.skip_geo)
        append_watch_snapshot(watch_path, traceroute)
        write_route_map(traceroute, live_map_path, utc_now(), args.watch_interval)
        print(f"[watch] wrote route snapshot {iteration} to {live_map_path}")
        if args.watch_iterations and iteration >= args.watch_iterations:
            break
        time.sleep(args.watch_interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Advanced internet audit with reports and route map")
    parser.add_argument("--output-dir", default="internet_audit_report", help="Directory for JSON, Markdown, capabilities, and map outputs")
    parser.add_argument("--targets", nargs="+", default=DEFAULT_PING_TARGETS, help="Ping targets")
    parser.add_argument("--domains", nargs="+", default=DEFAULT_DOMAINS, help="Domains for DNS tests")
    parser.add_argument("--urls", nargs="+", default=DEFAULT_URLS, help="URLs for HTTP/TLS timing tests")
    parser.add_argument("--tcp-targets", nargs="*", help="TCP targets as host:port")
    parser.add_argument("--dns-servers", nargs="+", default=DEFAULT_DNS_SERVERS, help="Direct DNS resolver IPs")
    parser.add_argument("--dns-qtypes", nargs="+", default=DEFAULT_DNS_QTYPES, help="DNS record types such as A AAAA MX TXT")
    parser.add_argument("--traceroute-target", default="1.1.1.1", help="Target used for traceroute map")
    parser.add_argument("--traceroute-mode", choices=sorted(TRACEROUTE_MODES), default="udp", help="Traceroute probe mode where supported")
    parser.add_argument("--traceroute-tcp-port", type=int, default=443, help="TCP port used when traceroute mode is tcp")
    parser.add_argument("--mtu-target", default="1.1.1.1", help="IPv4 target used for MTU probing")
    parser.add_argument("--ping-count", type=int, default=8)
    parser.add_argument("--ping-size", type=int, default=56, help="ICMP payload size in bytes")
    parser.add_argument("--ping-timeout", type=int, default=3)
    parser.add_argument("--tcp-timeout", type=int, default=5)
    parser.add_argument("--tcp-attempts", type=int, default=3)
    parser.add_argument("--dns-timeout", type=int, default=3)
    parser.add_argument("--http-timeout", type=int, default=10)
    parser.add_argument("--max-hops", type=int, default=30)
    parser.add_argument("--trace-timeout", type=int, default=3)
    parser.add_argument("--trace-probes", type=int, default=3)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--skip-speedtest", action="store_true", help="Skip speedtest/fallback throughput test")
    parser.add_argument("--skip-geo", action="store_true", help="Skip IP geolocation")
    parser.add_argument("--skip-mtu", action="store_true", help="Skip path MTU probe")
    parser.add_argument("--watch-interval", type=int, default=0, help="Seconds between live traceroute map refreshes; 0 disables watch mode")
    parser.add_argument("--watch-iterations", type=int, default=0, help="Number of watch iterations; 0 means forever")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    output_dir = Path(args.output_dir).expanduser().resolve()

    print("Running advanced internet audit...")
    report = run_full_audit(args)
    paths = write_outputs(report, output_dir, auto_refresh_seconds=args.watch_interval if args.watch_interval else 0)
    print("Done.")
    print(f"Markdown report: {paths['markdown']}")
    print(f"JSON report: {paths['json']}")
    print(f"Capabilities: {paths['capabilities']}")
    print(f"Route map: {paths['map']}")

    if args.watch_interval > 0:
        print(f"Starting live route watch every {args.watch_interval}s. Press Ctrl+C to stop.")
        try:
            watch_route(args, output_dir)
        except KeyboardInterrupt:
            print("Stopped route watch.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
