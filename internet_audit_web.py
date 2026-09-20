#!/usr/bin/env python3
"""
Interactive web app for Advanced Internet Audit.

This intentionally uses only Python's standard library for the web server so
the app can run on a fresh machine. The audit engine remains in
advanced_internet_audit.py and can later be mounted behind FastAPI, a task
queue, or a real database without replacing the frontend.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import mimetypes
import socket
import threading
import time
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import advanced_internet_audit as audit


ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "webapp_static"
RUNS_DIR = ROOT_DIR / "internet_audit_runs"
INDEX_PATH = RUNS_DIR / "jobs_index.json"
DOWNLOAD_KINDS = {"json", "markdown", "capabilities", "map"}


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def split_values(value: Any, default: List[str]) -> List[str]:
    if value is None:
        return list(default)
    if isinstance(value, list):
        items = value
    else:
        items = str(value).replace(",", "\n").splitlines()
    cleaned = [str(item).strip() for item in items if str(item).strip()]
    return cleaned or list(default)


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def int_value(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def default_config() -> Dict[str, Any]:
    return {
        "targets": audit.DEFAULT_PING_TARGETS,
        "domains": audit.DEFAULT_DOMAINS,
        "urls": audit.DEFAULT_URLS,
        "tcp_targets": [f"{host}:{port}" for host, port in audit.DEFAULT_TCP_TARGETS],
        "dns_servers": audit.DEFAULT_DNS_SERVERS,
        "dns_qtypes": audit.DEFAULT_DNS_QTYPES,
        "traceroute_target": "1.1.1.1",
        "traceroute_mode": "udp",
        "traceroute_tcp_port": 443,
        "mtu_target": "1.1.1.1",
        "ping_count": 8,
        "ping_size": 56,
        "ping_timeout": 3,
        "tcp_timeout": 5,
        "tcp_attempts": 3,
        "dns_timeout": 3,
        "http_timeout": 10,
        "max_hops": 30,
        "trace_timeout": 3,
        "trace_probes": 3,
        "workers": 8,
        "run_speedtest": True,
        "geolocate_route": True,
        "probe_mtu": True,
    }


def sanitize_config(raw: Optional[Dict[str, Any]]) -> argparse.Namespace:
    raw = raw or {}
    defaults = default_config()
    config = argparse.Namespace()
    config.targets = split_values(raw.get("targets"), defaults["targets"])
    config.domains = split_values(raw.get("domains"), defaults["domains"])
    config.urls = split_values(raw.get("urls"), defaults["urls"])
    config.tcp_targets = split_values(raw.get("tcp_targets"), defaults["tcp_targets"])
    config.dns_servers = split_values(raw.get("dns_servers"), defaults["dns_servers"])
    config.dns_qtypes = split_values(raw.get("dns_qtypes"), defaults["dns_qtypes"])
    config.traceroute_target = str(raw.get("traceroute_target") or defaults["traceroute_target"]).strip()
    config.traceroute_mode = str(raw.get("traceroute_mode") or defaults["traceroute_mode"]).strip().lower()
    if config.traceroute_mode not in audit.TRACEROUTE_MODES:
        config.traceroute_mode = defaults["traceroute_mode"]
    config.traceroute_tcp_port = int_value(raw.get("traceroute_tcp_port"), defaults["traceroute_tcp_port"], 1, 65535)
    config.mtu_target = str(raw.get("mtu_target") or defaults["mtu_target"]).strip()
    config.ping_count = int_value(raw.get("ping_count"), defaults["ping_count"], 1, 100)
    config.ping_size = int_value(raw.get("ping_size"), defaults["ping_size"], 0, 1472)
    config.ping_timeout = int_value(raw.get("ping_timeout"), defaults["ping_timeout"], 1, 30)
    config.tcp_timeout = int_value(raw.get("tcp_timeout"), defaults["tcp_timeout"], 1, 30)
    config.tcp_attempts = int_value(raw.get("tcp_attempts"), defaults["tcp_attempts"], 1, 20)
    config.dns_timeout = int_value(raw.get("dns_timeout"), defaults["dns_timeout"], 1, 30)
    config.http_timeout = int_value(raw.get("http_timeout"), defaults["http_timeout"], 1, 60)
    config.max_hops = int_value(raw.get("max_hops"), defaults["max_hops"], 1, 64)
    config.trace_timeout = int_value(raw.get("trace_timeout"), defaults["trace_timeout"], 1, 20)
    config.trace_probes = int_value(raw.get("trace_probes"), defaults["trace_probes"], 1, 10)
    config.workers = int_value(raw.get("workers"), defaults["workers"], 1, 32)
    config.skip_speedtest = not bool_value(raw.get("run_speedtest"), defaults["run_speedtest"])
    config.skip_geo = not bool_value(raw.get("geolocate_route"), defaults["geolocate_route"])
    config.skip_mtu = not bool_value(raw.get("probe_mtu"), defaults["probe_mtu"])
    config.watch_interval = 0
    config.watch_iterations = 0
    config.output_dir = ""
    return config


def namespace_to_public_config(config: argparse.Namespace) -> Dict[str, Any]:
    return {
        "targets": config.targets,
        "domains": config.domains,
        "urls": config.urls,
        "tcp_targets": config.tcp_targets,
        "dns_servers": config.dns_servers,
        "dns_qtypes": config.dns_qtypes,
        "traceroute_target": config.traceroute_target,
        "traceroute_mode": config.traceroute_mode,
        "traceroute_tcp_port": config.traceroute_tcp_port,
        "mtu_target": config.mtu_target,
        "ping_count": config.ping_count,
        "ping_size": config.ping_size,
        "ping_timeout": config.ping_timeout,
        "tcp_timeout": config.tcp_timeout,
        "tcp_attempts": config.tcp_attempts,
        "dns_timeout": config.dns_timeout,
        "http_timeout": config.http_timeout,
        "max_hops": config.max_hops,
        "trace_timeout": config.trace_timeout,
        "trace_probes": config.trace_probes,
        "workers": config.workers,
        "run_speedtest": not config.skip_speedtest,
        "geolocate_route": not config.skip_geo,
        "probe_mtu": not config.skip_mtu,
    }


class JobStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.cancel_flags: Dict[str, threading.Event] = {}
        self.load_index()

    def load_index(self) -> None:
        if not INDEX_PATH.exists():
            return
        try:
            data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        with self.lock:
            for job in data.get("jobs", []):
                job_id = job.get("id")
                if job_id:
                    self.jobs[job_id] = job

    def save_index(self) -> None:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda item: item.get("created_at", ""), reverse=True)[:50]
            lightweight = []
            for job in jobs:
                lightweight.append(
                    {
                        "id": job["id"],
                        "status": job.get("status"),
                        "created_at": job.get("created_at"),
                        "updated_at": job.get("updated_at"),
                        "completed_at": job.get("completed_at"),
                        "progress_pct": job.get("progress_pct", 0),
                        "stage": job.get("stage"),
                        "message": job.get("message"),
                        "config": job.get("config"),
                        "output_dir": job.get("output_dir"),
                        "paths": job.get("paths"),
                        "summary": job.get("summary"),
                        "error": job.get("error"),
                        "events": job.get("events", [])[-20:],
                    }
                )
        atomic_write_json(INDEX_PATH, {"jobs": lightweight})

    def create(self, config: argparse.Namespace) -> Dict[str, Any]:
        job_id = uuid.uuid4().hex[:12]
        created_at = audit.utc_now()
        output_dir = RUNS_DIR / job_id
        job = {
            "id": job_id,
            "status": "queued",
            "created_at": created_at,
            "updated_at": created_at,
            "progress_pct": 0,
            "stage": "queued",
            "message": "Audit queued",
            "config": namespace_to_public_config(config),
            "output_dir": str(output_dir),
            "paths": {},
            "summary": {},
            "events": [],
            "report": None,
            "error": None,
        }
        with self.lock:
            self.jobs[job_id] = job
            self.cancel_flags[job_id] = threading.Event()
        self.add_event(job_id, "queued", "Audit queued", 0)
        self.save_index()
        return job

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            return json.loads(json.dumps(job))

    def list(self) -> List[Dict[str, Any]]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda item: item.get("created_at", ""), reverse=True)
            return [self.public_job(job, include_report=False) for job in jobs[:50]]

    def public_job(self, job: Dict[str, Any], include_report: bool = True) -> Dict[str, Any]:
        public = {key: value for key, value in job.items() if key != "report"}
        if include_report and job.get("report") is not None:
            public["report"] = job["report"]
        return json.loads(json.dumps(public))

    def add_event(self, job_id: str, stage: str, message: str, progress: Optional[int] = None) -> None:
        with self.lock:
            job = self.jobs[job_id]
            now = audit.utc_now()
            if progress is not None:
                job["progress_pct"] = progress
            job["stage"] = stage
            job["message"] = message
            job["updated_at"] = now
            job.setdefault("events", []).append({"time": now, "stage": stage, "message": message, "progress_pct": job.get("progress_pct", 0)})
            job["events"] = job["events"][-200:]

    def update(self, job_id: str, **fields: Any) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job.update(fields)
            job["updated_at"] = audit.utc_now()

    def cancel(self, job_id: str) -> bool:
        with self.lock:
            flag = self.cancel_flags.get(job_id)
            job = self.jobs.get(job_id)
            if not flag or not job:
                return False
            flag.set()
            if job.get("status") in {"queued", "running"}:
                job["status"] = "cancel_requested"
                job["message"] = "Cancel requested"
                job["updated_at"] = audit.utc_now()
        self.save_index()
        return True

    def canceled(self, job_id: str) -> bool:
        with self.lock:
            flag = self.cancel_flags.get(job_id)
            return bool(flag and flag.is_set())


STORE = JobStore()


def summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    latency_items = report.get("latency", [])
    avg_values = [item.get("avg_ms") for item in latency_items if isinstance(item.get("avg_ms"), (int, float))]
    loss_values = [item.get("packet_loss_pct") for item in latency_items if isinstance(item.get("packet_loss_pct"), (int, float))]
    dns_items = report.get("dns", {}).get("system", []) + report.get("dns", {}).get("direct", [])
    dns_values = [item.get("duration_ms") for item in dns_items if isinstance(item.get("duration_ms"), (int, float))]
    http_items = report.get("http", [])
    http_values = [item.get("total_ms") for item in http_items if isinstance(item.get("total_ms"), (int, float))]
    speed = report.get("speed", {})
    identity = report.get("identity", {})
    return {
        "public_ip": identity.get("public_ip", {}).get("ip"),
        "local_ip": identity.get("local_ip"),
        "avg_latency_ms": round(sum(avg_values) / len(avg_values), 1) if avg_values else None,
        "max_loss_pct": round(max(loss_values), 1) if loss_values else None,
        "avg_dns_ms": round(sum(dns_values) / len(dns_values), 1) if dns_values else None,
        "avg_http_ms": round(sum(http_values) / len(http_values), 1) if http_values else None,
        "download_mbps": round(speed.get("download_bps", 0) / 1_000_000, 2) if speed.get("download_bps") else None,
        "upload_mbps": round(speed.get("upload_bps", 0) / 1_000_000, 2) if speed.get("upload_bps") else None,
        "findings_count": len(report.get("findings", [])),
        "hop_count": len(report.get("traceroute", {}).get("hops", [])),
    }


def assert_not_canceled(job_id: str) -> None:
    if STORE.canceled(job_id):
        raise RuntimeError("Audit canceled")


def run_parallel_stage(job_id: str, config: argparse.Namespace, report: Dict[str, Any]) -> None:
    STORE.add_event(job_id, "parallel-tests", "Running latency, TCP, DNS, and HTTP checks", 18)
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.workers) as executor:
        latency_futures = [executor.submit(audit.ping_target, target, config.ping_count, config.ping_timeout, config.ping_size) for target in config.targets]
        tcp_pairs = audit.parse_tcp_targets(config.tcp_targets)
        tcp_futures = [executor.submit(audit.tcp_connect_test, host, port, config.tcp_timeout, config.tcp_attempts) for host, port in tcp_pairs]
        dns_system_futures = [executor.submit(audit.system_dns_lookup, domain) for domain in config.domains]
        http_futures = [executor.submit(audit.http_timing, url, config.http_timeout) for url in config.urls]

        report["latency"] = [future.result() for future in concurrent.futures.as_completed(latency_futures)]
        STORE.add_event(job_id, "latency", "Latency and loss checks completed", 32)
        assert_not_canceled(job_id)

        report["tcp_connect"] = [future.result() for future in concurrent.futures.as_completed(tcp_futures)]
        STORE.add_event(job_id, "tcp", "TCP reachability checks completed", 42)
        assert_not_canceled(job_id)

        dns_system = [future.result() for future in concurrent.futures.as_completed(dns_system_futures)]
        report["http"] = [future.result() for future in concurrent.futures.as_completed(http_futures)]
        report["dns"] = {"system": dns_system, "direct": []}
        STORE.add_event(job_id, "http-dns", "HTTP, TLS, and system DNS checks completed", 52)


def run_job(job_id: str, config: argparse.Namespace) -> None:
    output_dir = RUNS_DIR / job_id
    try:
        STORE.update(job_id, status="running")
        STORE.add_event(job_id, "identity", "Collecting local, gateway, public IP, and interface identity", 6)
        report: Dict[str, Any] = {
            "generated_at_utc": audit.utc_now(),
            "capabilities": audit.CAPABILITIES,
            "config": namespace_to_public_config(config),
        }
        report["identity"] = audit.collect_identity()
        assert_not_canceled(job_id)

        run_parallel_stage(job_id, config, report)
        assert_not_canceled(job_id)

        STORE.add_event(job_id, "direct-dns", "Testing direct DNS resolvers", 60)
        direct_dns = []
        qtypes = audit.parse_dns_qtypes(config.dns_qtypes)
        for domain in config.domains:
            for server in config.dns_servers:
                for qtype in qtypes:
                    assert_not_canceled(job_id)
                    direct_dns.append(audit.udp_dns_query(server, domain, qtype=qtype, timeout_s=config.dns_timeout))
        report.setdefault("dns", {})["direct"] = direct_dns

        STORE.add_event(job_id, "throughput", "Measuring throughput", 70)
        report["speed"] = audit.run_speedtest(config.skip_speedtest)
        assert_not_canceled(job_id)

        STORE.add_event(job_id, "route", "Tracing and geolocating the packet route", 80)
        report["traceroute"] = audit.run_traceroute(
            config.traceroute_target,
            config.max_hops,
            config.trace_timeout,
            config.trace_probes,
            config.traceroute_mode,
            config.traceroute_tcp_port,
        )
        report["traceroute"]["hops"] = audit.enrich_hops_with_geo(report["traceroute"].get("hops", []), config.skip_geo)
        assert_not_canceled(job_id)

        STORE.add_event(job_id, "mtu", "Probing IPv4 path MTU", 88)
        report["mtu"] = audit.probe_mtu(config.mtu_target, config.skip_mtu)

        STORE.add_event(job_id, "analysis", "Generating findings and writing downloadable reports", 94)
        report["findings"] = audit.network_findings(report)
        paths = audit.write_outputs(report, output_dir)
        summary = summarize_report(report)
        STORE.update(job_id, status="completed", completed_at=audit.utc_now(), report=report, paths=paths, summary=summary, progress_pct=100)
        STORE.add_event(job_id, "completed", "Audit completed", 100)
    except RuntimeError as exc:
        if str(exc) == "Audit canceled":
            STORE.update(job_id, status="canceled", completed_at=audit.utc_now(), error=None, progress_pct=0)
            STORE.add_event(job_id, "canceled", "Audit canceled", 0)
        else:
            STORE.update(job_id, status="failed", completed_at=audit.utc_now(), error=str(exc))
            STORE.add_event(job_id, "failed", str(exc))
    except Exception as exc:
        STORE.update(job_id, status="failed", completed_at=audit.utc_now(), error=str(exc), traceback=traceback.format_exc())
        STORE.add_event(job_id, "failed", f"{type(exc).__name__}: {exc}")
    finally:
        STORE.save_index()


def run_route_snapshot(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = raw or {}
    target = str(raw.get("target") or "1.1.1.1").strip()
    max_hops = int_value(raw.get("max_hops"), 30, 1, 64)
    timeout = int_value(raw.get("trace_timeout"), 3, 1, 20)
    probes = int_value(raw.get("trace_probes"), 3, 1, 10)
    mode = str(raw.get("traceroute_mode") or "udp").lower()
    if mode not in audit.TRACEROUTE_MODES:
        mode = "udp"
    tcp_port = int_value(raw.get("traceroute_tcp_port"), 443, 1, 65535)
    skip_geo = not bool_value(raw.get("geolocate_route"), True)
    traceroute = audit.run_traceroute(target, max_hops, timeout, probes, mode, tcp_port)
    traceroute["hops"] = audit.enrich_hops_with_geo(traceroute.get("hops", []), skip_geo)
    traceroute["generated_at_utc"] = audit.utc_now()
    return traceroute


class AppHandler(BaseHTTPRequestHandler):
    server_version = "InternetAuditWeb/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        message = fmt % args
        print(f"[web] {self.address_string()} {message}")

    def read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        payload = self.rfile.read(length)
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        self.send_json({"error": message, "status": status.value}, status)

    def send_file(self, path: Path, download_name: Optional[str] = None) -> None:
        if not path.exists() or not path.is_file():
            self.send_error_json(HTTPStatus.NOT_FOUND, "File not found")
            return
        data = path.read_bytes()
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(data)

    def serve_static(self, parsed_path: str) -> None:
        relative = "index.html" if parsed_path == "/" else parsed_path.removeprefix("/")
        if relative.startswith("assets/"):
            relative = relative.removeprefix("assets/")
        target = (STATIC_DIR / relative).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self.send_error_json(HTTPStatus.FORBIDDEN, "Forbidden")
            return
        self.send_file(target)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/api/health":
            self.send_json({"ok": True, "time": audit.utc_now(), "jobs": len(STORE.list())})
            return
        if path == "/api/default-config":
            self.send_json(default_config())
            return
        if path == "/api/capabilities":
            self.send_json({"capabilities": audit.CAPABILITIES})
            return
        if path == "/api/jobs":
            self.send_json({"jobs": STORE.list()})
            return
        if path.startswith("/api/jobs/"):
            self.handle_job_get(path)
            return
        if path == "/" or path.startswith("/assets/"):
            self.serve_static(path)
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            payload = self.read_json()
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        if path == "/api/jobs":
            try:
                config = sanitize_config(payload)
                audit.parse_tcp_targets(config.tcp_targets)
                audit.parse_dns_qtypes(config.dns_qtypes)
            except Exception as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            job = STORE.create(config)
            thread = threading.Thread(target=run_job, args=(job["id"], config), daemon=True)
            thread.start()
            self.send_json(STORE.public_job(job), HTTPStatus.ACCEPTED)
            return

        if path == "/api/route-snapshot":
            try:
                traceroute = run_route_snapshot(payload)
            except Exception as exc:
                self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
                return
            self.send_json({"traceroute": traceroute})
            return

        if path.startswith("/api/jobs/") and path.endswith("/cancel"):
            parts = path.strip("/").split("/")
            if len(parts) == 4:
                ok = STORE.cancel(parts[2])
                if not ok:
                    self.send_error_json(HTTPStatus.NOT_FOUND, "Job not found")
                    return
                self.send_json({"ok": True})
                return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Not found")

    def handle_job_get(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Job not found")
            return
        job_id = parts[2]
        job = STORE.get(job_id)
        if not job:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Job not found")
            return

        if len(parts) == 3:
            self.send_json(STORE.public_job(job))
            return
        if len(parts) == 5 and parts[3] == "download":
            kind = parts[4]
            if kind not in DOWNLOAD_KINDS:
                self.send_error_json(HTTPStatus.BAD_REQUEST, "Unknown download kind")
                return
            path_value = (job.get("paths") or {}).get(kind)
            if not path_value:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Report file is not ready")
                return
            path = Path(path_value).resolve()
            try:
                path.relative_to(RUNS_DIR.resolve())
            except ValueError:
                self.send_error_json(HTTPStatus.FORBIDDEN, "Forbidden")
                return
            suffix = path.suffix or ".dat"
            self.send_file(path, download_name=f"{job_id}_{kind}{suffix}")
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Not found")


def find_free_port(host: str, preferred_port: int) -> int:
    if preferred_port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return int(sock.getsockname()[1])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, preferred_port))
            return preferred_port
        except OSError:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fallback:
                fallback.bind((host, 0))
                return int(fallback.getsockname()[1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the interactive Advanced Internet Audit web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if not STATIC_DIR.exists():
        raise SystemExit(f"Static web directory not found: {STATIC_DIR}")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    port = find_free_port(args.host, args.port)
    server = ThreadingHTTPServer((args.host, port), AppHandler)
    print(f"Advanced Internet Audit web app running at http://{args.host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping web app.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
