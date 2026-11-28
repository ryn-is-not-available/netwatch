#!/usr/bin/env python3
"""NetWatch chaos toolkit: inject DATA_NET faults into the compose stack and measure detection.

    python scripts/chaos.py loss node-3 --pct 30          # inject, measure detection + recovery
    python scripts/chaos.py delay node-2 --ms 80          # latency SLO breach
    python scripts/chaos.py burst node-1 node-4 --seconds 15 --bandwidth 500M   # iperf3 congestion
    python scripts/chaos.py clear                          # remove any leftover netem qdisc
    python scripts/chaos.py suite --out chaos-report.json  # all of the above, exit 1 on failure

Faults are applied with `tc qdisc ... netem` on the node's DATA_NET interface (found by its
172.29.0.x address; Docker does not guarantee it is eth1) and are always removed afterwards,
also on Ctrl+C or an error. Detection is measured by polling the leader's REST API once a second.
Credentials: --username/--password, or NETWATCH_USERNAME / NETWATCH_PASSWORD (dev default admin).
Standard library only.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
import time
from typing import Any, Callable, Iterator
import urllib.error
import urllib.request

NODES = [f"node-{i}" for i in range(1, 6)]
DATA_PREFIX = "172.29."


# --- plumbing ----------------------------------------------------------------------------------

def docker(*args: str, check: bool = True) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def data_iface(node: str) -> tuple[str, str]:
    """(interface, ip) of the node's DATA_NET address."""
    for line in docker("exec", node, "ip", "-o", "-4", "addr", "show").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet" and parts[3].startswith(DATA_PREFIX):
            return parts[1].split("@")[0], parts[3].split("/")[0]
    raise RuntimeError(f"{node} has no {DATA_PREFIX}x address")


class Api:
    def __init__(self, username: str, password: str) -> None:
        self.base = self._leader()
        self.token = self.call("POST", "/auth/token", {"username": username, "password": password})["access_token"]

    @staticmethod
    def _leader() -> str:
        for port in (8000, 8001):
            try:
                with urllib.request.urlopen(f"http://localhost:{port}/health", timeout=3) as r:
                    if json.loads(r.read())["is_leader"]:
                        return f"http://localhost:{port}"
            except OSError:
                continue
        return "http://localhost:8000"  # either replica forwards writes; reads work on both

    def call(self, method: str, path: str, body: Any = None) -> Any:
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if getattr(self, "token", None):
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"null")


def wait_for(check: Callable[[], bool], timeout_s: float, start: float) -> float | None:
    """Seconds from `start` until check() is true, or None on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if check():
                return round(time.monotonic() - start, 1)
        except (OSError, urllib.error.URLError, ValueError):
            pass  # transient API hiccup: keep polling
        time.sleep(1)
    return None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- faults --------------------------------------------------------------------------------------

@contextmanager
def netem(node: str, spec: list[str]) -> Iterator[None]:
    iface, _ = data_iface(node)
    docker("exec", node, "tc", "qdisc", "replace", "dev", iface, "root", "netem", *spec)
    print(f"  injected on {node}/{iface}: netem {' '.join(spec)}")
    try:
        yield
    finally:
        docker("exec", node, "tc", "qdisc", "del", "dev", iface, "root", check=False)
        print(f"  cleared netem on {node}/{iface}")


def clear(nodes: list[str]) -> None:
    for node in nodes:
        iface, _ = data_iface(node)
        out = docker("exec", node, "tc", "qdisc", "del", "dev", iface, "root", check=False)
        print(f"{node}/{iface}: {'cleared' if not out else out}")


# --- observations --------------------------------------------------------------------------------

def links_of(api: Api, node: str) -> list[dict[str, Any]]:
    return [l for l in api.call("GET", "/topology")["observed_links"] if node in (l["src_node_id"], l["dst_node_id"])]


def open_alerts(api: Api, node: str, prefix: str) -> list[dict[str, Any]]:
    return [a for a in api.call("GET", "/alerts")
            if a["status"] != "resolved" and a["message"].startswith(prefix)
            and (a["affected_node_id"] == node or f"->{node} " in a["message"] or f" {node}->" in a["message"])]


def _detect_and_recover(api: Api, node: str, alert_prefix: str, fault: Callable[[], Any],
                        link_check: Callable[[], bool] | None, hold_after_detect_s: float = 5) -> dict[str, Any]:
    result: dict[str, Any] = {"node": node, "started_at": now_iso()}
    t0 = time.monotonic()
    with fault():
        if link_check is not None:
            result["link_degraded_s"] = wait_for(link_check, 90, t0)
        result["alert_firing_s"] = wait_for(lambda: bool(open_alerts(api, node, alert_prefix)), 120, t0)
        result["alerts_raised"] = len(open_alerts(api, node, alert_prefix))
        time.sleep(hold_after_detect_s)
    t1 = time.monotonic()
    result["recovered_links_s"] = wait_for(lambda: all(l["status"] == "up" for l in links_of(api, node)) and bool(links_of(api, node)), 120, t1)
    result["alerts_resolved_s"] = wait_for(lambda: not open_alerts(api, node, alert_prefix), 150, t1)
    detected = result["alert_firing_s"] is not None and (link_check is None or result.get("link_degraded_s") is not None)
    result["passed"] = detected and result["recovered_links_s"] is not None and result["alerts_resolved_s"] is not None
    return result


def run_loss(api: Api, node: str, pct: float) -> dict[str, Any]:
    print(f"[loss] {pct:g}% packet loss on {node}")
    r = _detect_and_recover(api, node, "Packet loss", lambda: netem(node, ["loss", f"{pct:g}%"]),
                            lambda: any(l["status"] == "degraded" for l in links_of(api, node)))
    return {"scenario": "loss", "loss_pct": pct, **r}


def run_delay(api: Api, node: str, ms: float, jitter_ms: float) -> dict[str, Any]:
    print(f"[delay] +{ms:g} ms (jitter {jitter_ms:g} ms) on {node}")
    spec = ["delay", f"{ms:g}ms"] + ([f"{jitter_ms:g}ms"] if jitter_ms else [])
    r = _detect_and_recover(api, node, "Latency", lambda: netem(node, spec), None)
    return {"scenario": "delay", "delay_ms": ms, "jitter_ms": jitter_ms, **r}


def run_burst(api: Api, src: str, dst: str, seconds: int, bandwidth: str) -> dict[str, Any]:
    print(f"[burst] iperf3 {src} -> {dst} for {seconds}s at {bandwidth}")
    _, dst_ip = data_iface(dst)
    started = now_iso()
    docker("exec", "-d", dst, "iperf3", "-s", "-1")
    time.sleep(1)
    raw = docker("exec", src, "iperf3", "-c", dst_ip, "-t", str(seconds), "-b", bandwidth, "-J")
    report = json.loads(raw)
    sent_bps = report["end"]["sum_sent"]["bits_per_second"]
    recv_bps = report["end"]["sum_received"]["bits_per_second"]
    time.sleep(12)  # let the 1s telemetry reach the worker and the metrics buckets close
    metrics = api.call("GET", f"/nodes/{dst}/metrics?minutes=5")
    start_ts = datetime.fromisoformat(started).timestamp()
    bucket_s = metrics["bucket_seconds"]
    points = [p for p in metrics["points"] if p["rx_bps"] is not None]
    # A bucket counts as "before" only if it ended before the burst began (the bucket holding the
    # burst's first second starts earlier but already contains burst traffic).
    window = [p for p in points if datetime.fromisoformat(p["t"]).timestamp() + bucket_s > start_ts]
    before = [p for p in points if datetime.fromisoformat(p["t"]).timestamp() + bucket_s <= start_ts]
    peak_rx = max((p["rx_bps"] for p in window), default=None)
    baseline_rx = (sum(p["rx_bps"] for p in before[-10:]) / len(before[-10:])) if before else None
    observed = peak_rx is not None and peak_rx * 8 > 0.2 * recv_bps
    return {
        "scenario": "burst", "src": src, "dst": dst, "seconds": seconds, "bandwidth": bandwidth,
        "started_at": started, "iperf_sent_mbps": round(sent_bps / 1e6, 1), "iperf_received_mbps": round(recv_bps / 1e6, 1),
        "netwatch_peak_rx_mbps": None if peak_rx is None else round(peak_rx * 8 / 1e6, 1),
        "netwatch_baseline_rx_kbps": None if baseline_rx is None else round(baseline_rx * 8 / 1e3, 1),
        "passed": observed,
    }


# --- CLI -----------------------------------------------------------------------------------------

def print_result(r: dict[str, Any]) -> None:
    keys = [k for k in r if k not in ("scenario",)]
    print(f"  => {'PASS' if r['passed'] else 'FAIL'} " + ", ".join(f"{k}={r[k]}" for k in keys if k != "passed"))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--username", default=os.environ.get("NETWATCH_USERNAME", "admin"))
    p.add_argument("--password", default=os.environ.get("NETWATCH_PASSWORD", "netwatch-admin-dev"))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("loss"); s.add_argument("node"); s.add_argument("--pct", type=float, default=30)
    s = sub.add_parser("delay"); s.add_argument("node"); s.add_argument("--ms", type=float, default=80); s.add_argument("--jitter", type=float, default=0)
    s = sub.add_parser("burst"); s.add_argument("src"); s.add_argument("dst"); s.add_argument("--seconds", type=int, default=15); s.add_argument("--bandwidth", default="500M")
    s = sub.add_parser("clear"); s.add_argument("nodes", nargs="*", default=NODES)
    s = sub.add_parser("suite"); s.add_argument("--out", default="chaos-report.json")
    args = p.parse_args()

    if args.cmd == "clear":
        clear(args.nodes)
        return 0
    api = Api(args.username, args.password)
    if args.cmd == "loss":
        results = [run_loss(api, args.node, args.pct)]
    elif args.cmd == "delay":
        results = [run_delay(api, args.node, args.ms, args.jitter)]
    elif args.cmd == "burst":
        results = [run_burst(api, args.src, args.dst, args.seconds, args.bandwidth)]
    else:
        results = [
            run_loss(api, "node-3", 30),
            run_delay(api, "node-2", 80, 0),
            run_burst(api, "node-1", "node-4", 15, "500M"),
        ]
    for r in results:
        print_result(r)
    if args.cmd == "suite":
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": now_iso(), "results": results}, fh, indent=2)
        print(f"report written to {args.out}")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
