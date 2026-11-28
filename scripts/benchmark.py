#!/usr/bin/env python3
"""NetWatch benchmarks (README Phase 5.3-5.5). Standard library only; drives docker + the REST API.

    python scripts/benchmark.py snmp --steady 120      # SNMP poller (T0) vs NetWatch (T1)
    python scripts/benchmark.py capture                # MGMT_NET / DATA_NET pcaps + annotations
    python scripts/benchmark.py cold-start --wipe-volumes   # DESTROYS the DB/JetStream volumes
    python scripts/benchmark.py report                 # docs/BENCHMARK.md from the JSON results

snmp: starts snmpd in every node (benchmark only: NetWatch nodes are otherwise outbound-only) and a
classic NMS-style poller (sysUpTime.0 per node every --interval seconds, 1 s timeout, 2 retries) on
MGMT_NET, then measures (a) a steady window for overhead and false positives, (b) a frozen node
(`docker pause`, seen identically by both), (c) 30% loss on one node's DATA_NET.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chaos  # noqa: E402  (shared helpers: Api, docker, data_iface, netem, wait_for, ...)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
RESULTS = DOCS / "benchmark-results.json"
NODES = chaos.NODES
POLLER = "nw-snmp-poller"

POLLER_CODE = r"""
import json, subprocess, sys, time
interval, ips = float(sys.argv[1]), sys.argv[2:]
while True:
    start = time.time()
    for ip in ips:
        r = subprocess.run(["snmpget", "-v2c", "-c", "public", "-t", "1", "-r", "2", "-Oqv", ip, "1.3.6.1.2.1.1.3.0"],
                           capture_output=True, text=True)
        print(json.dumps({"t": time.time(), "ip": ip, "ok": r.returncode == 0}), flush=True)
    time.sleep(max(0.0, interval - (time.time() - start)))
"""


def mgmt_ip(node: str) -> tuple[str, str]:
    for line in chaos.docker("exec", node, "ip", "-o", "-4", "addr", "show").splitlines():
        p = line.split()
        if len(p) >= 4 and p[2] == "inet" and p[3].startswith("172.28."):
            return p[1].split("@")[0], p[3].split("/")[0]
    raise RuntimeError(f"{node} has no MGMT_NET address")


def iface_bytes(container: str, iface: str) -> int:
    for line in chaos.docker("exec", container, "cat", "/proc/net/dev").splitlines():
        if line.strip().startswith(f"{iface}:"):
            c = line.split(":", 1)[1].split()
            return int(c[0]) + int(c[8])
    raise RuntimeError(f"{iface} not found in {container}")


def poller_events() -> list[dict[str, Any]]:
    out = subprocess.run(["docker", "logs", POLLER], capture_output=True, text=True).stdout
    return [json.loads(l) for l in out.splitlines() if l.startswith("{")]


def snmp_start(interval: float) -> dict[str, str]:
    ips = {}
    for node in NODES:
        _, ip = mgmt_ip(node)
        ips[node] = ip
        # snmpd runs permanently on every node (snmp/snmpd.conf); start one only on an older stack.
        chaos.docker("exec", node, "sh", "-c",
                     "[ -f /tmp/snmpd.pid ] && kill -0 $(cat /tmp/snmpd.pid) 2>/dev/null || "
                     "snmpd -C -c /etc/netwatch/snmpd.conf -p /tmp/snmpd.pid -Lf /dev/null")
    subprocess.run(["docker", "rm", "-f", POLLER], capture_output=True)
    chaos.docker("run", "-d", "--name", POLLER, "--network", "mgmt_net", "--entrypoint", "python",
                 "netwatch-agent:latest", "-u", "-c", POLLER_CODE, str(interval), *ips.values())
    return ips


def snmp_stop() -> None:
    subprocess.run(["docker", "rm", "-f", POLLER], capture_output=True)
    # snmpd is part of every node now (planning S2): leave it running.


def first_failure(ip: str, after: float) -> float | None:
    fails = [e["t"] for e in poller_events() if e["ip"] == ip and not e["ok"] and e["t"] >= after]
    return min(fails) if fails else None


def run_snmp(api: chaos.Api, interval: float, steady_s: int) -> dict[str, Any]:
    out: dict[str, Any] = {"generated_at": chaos.now_iso(), "snmp_poll_interval_s": interval}
    ips = snmp_start(interval)
    try:
        time.sleep(5)
        # (a) steady state: overhead + false positives
        print(f"[steady] {steady_s}s without faults")
        t_start = time.time()
        before = {n: (iface_bytes(n, mgmt_ip(n)[0]), iface_bytes(n, chaos.data_iface(n)[0])) for n in NODES}
        poll_before = iface_bytes(POLLER, "eth0")
        alerts_before = {a["alert_id"] for a in api.call("GET", "/alerts")}
        time.sleep(steady_s)
        mins = (time.time() - t_start) / 60
        poll_bytes = iface_bytes(POLLER, "eth0") - poll_before
        mgmt = sum(iface_bytes(n, mgmt_ip(n)[0]) - before[n][0] for n in NODES) / len(NODES)
        data = sum(iface_bytes(n, chaos.data_iface(n)[0]) - before[n][1] for n in NODES) / len(NODES)
        snmp_per_node = poll_bytes / len(NODES)
        events = [e for e in poller_events() if e["t"] >= t_start]
        out["steady"] = {
            "seconds": steady_s,
            "netwatch_mgmt_bytes_per_node_min": round((mgmt - snmp_per_node) / mins),
            "netwatch_data_bytes_per_node_min": round(data / mins),
            "snmp_bytes_per_node_min": round(snmp_per_node / mins),
            "netwatch_false_alerts": len({a["alert_id"] for a in api.call("GET", "/alerts")} - alerts_before),
            "snmp_polls": len(events),
            "snmp_false_failures": sum(not e["ok"] for e in events),
        }
        print("  ", out["steady"])

        # (b) frozen node: both systems lose it at the same instant
        node, ip = "node-4", ips["node-4"]
        print(f"[freeze] docker pause {node}")
        t0m, t0 = time.monotonic(), time.time()
        chaos.docker("pause", node)
        try:
            nw = chaos.wait_for(lambda: any(n["node_id"] == node and n["health_status"] == "offline"
                                            for n in api.call("GET", "/nodes")), 90, t0m)
            snmp_deadline = time.time() + interval + 15
            while first_failure(ip, t0) is None and time.time() < snmp_deadline:
                time.sleep(1)
            sf = first_failure(ip, t0)
        finally:
            chaos.docker("unpause", node)
        out["node_freeze"] = {"node": node, "netwatch_offline_s": nw,
                              "snmp_first_failed_poll_s": None if sf is None else round(sf - t0, 1)}
        print("  ", out["node_freeze"])
        chaos.wait_for(lambda: any(n["node_id"] == node and n["health_status"] == "healthy" for n in api.call("GET", "/nodes")), 60, time.monotonic())

        # (c) data-plane loss: the management path (and SNMP) is unaffected
        node, ip = "node-3", ips["node-3"]
        print(f"[loss] 30% DATA_NET loss on {node}")
        r = chaos.run_loss(api, node, 30)
        t_window = time.time() - 120
        out["data_plane_loss"] = {
            "node": node, "netwatch_link_degraded_s": r.get("link_degraded_s"),
            "netwatch_alert_s": r.get("alert_firing_s"),
            "snmp_detected": first_failure(ip, t_window) is not None,
        }
        print("  ", out["data_plane_loss"])
    finally:
        snmp_stop()
    return out


def run_capture(api: chaos.Api, seconds: int) -> dict[str, Any]:
    cap_dir = DOCS / "captures"
    cap_dir.mkdir(parents=True, exist_ok=True)
    node = "node-1"
    ifaces = {"mgmt": mgmt_ip(node)[0], "data": chaos.data_iface(node)[0]}
    for name, iface in ifaces.items():
        chaos.docker("exec", "-d", node, "timeout", str(seconds), "tcpdump", "-i", iface, "-nn", "-s", "256",
                     "-w", f"/tmp/{name}.pcap")
    time.sleep(2)
    api.call("POST", "/paths/trace", {"src_node_id": node, "dst_node_id": "node-3"})  # traceroute traffic
    time.sleep(seconds)
    summary: dict[str, Any] = {"node": node, "seconds": seconds, "interfaces": ifaces}
    for name in ifaces:
        dest = cap_dir / f"{node}-{name}.pcap"
        chaos.docker("cp", f"{node}:/tmp/{name}.pcap", str(dest))
        text = chaos.docker("exec", node, "tcpdump", "-nn", "-r", f"/tmp/{name}.pcap")
        lines = text.splitlines()
        def count(pred): return sum(1 for l in lines if pred(l))
        raw = dest.read_bytes()
        summary[name] = {
            "file": dest.name, "packets": len(lines), "bytes": len(raw),
            "grpc_mtls_50051": count(lambda l: ".50051" in l),
            "grpc_enroll_tls_50052": count(lambda l: ".50052" in l),
            "nats_tls_4222": count(lambda l: ".4222" in l),
            "icmp": count(lambda l: " ICMP " in l),
            "traceroute_udp": count(lambda l: "UDP," in l and ".334" in l),
            "plaintext_markers_found": [m for m in ("PUB telemetry", "CONNECT {", "\"cpu_pct\"", "SendHeartbeat")
                                        if m.encode() in raw],
        }
    (cap_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def run_cold_start(wipe: bool, limit_s: int) -> dict[str, Any]:
    if not wipe:
        sys.exit("cold-start rebuilds the stack from empty volumes: pass --wipe-volumes "
                 "(it runs `docker compose down -v`, deleting the database and JetStream data)")
    subprocess.run(["docker", "compose", "down", "-v"], cwd=ROOT, check=True)
    t0 = time.monotonic()
    subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=ROOT, check=True)
    marks: dict[str, Any] = {"compose_up_returned_s": round(time.monotonic() - t0, 1)}
    api = None
    def login() -> bool:
        nonlocal api
        api = chaos.Api(os.environ.get("NETWATCH_USERNAME", "admin"), os.environ.get("NETWATCH_PASSWORD", "netwatch-admin-dev"))
        return True
    marks["api_login_s"] = chaos.wait_for(login, limit_s, t0)
    if api is not None:
        marks["five_nodes_healthy_s"] = chaos.wait_for(
            lambda: sum(n["health_status"] == "healthy" for n in api.call("GET", "/nodes")) == 5, limit_s, t0)
        marks["telemetry_flowing_s"] = chaos.wait_for(
            lambda: len(api.call("GET", "/nodes/node-1/metrics?minutes=5")["points"]) > 0, limit_s, t0)
        marks["links_observed_s"] = chaos.wait_for(
            lambda: len(api.call("GET", "/topology")["observed_links"]) >= 20, limit_s, t0)
    total = max((v for k, v in marks.items() if isinstance(v, (int, float)) and k != "compose_up_returned_s"), default=None)
    marks.update(limit_s=limit_s, total_s=total, passed=all(v is not None for v in marks.values()) and total is not None and total <= limit_s)
    return marks


def render_report() -> None:
    data = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}
    s, f, l = data.get("snmp", {}).get("steady", {}), data.get("snmp", {}).get("node_freeze", {}), data.get("snmp", {}).get("data_plane_loss", {})
    cap = data.get("capture", {})
    cold = data.get("cold_start", {})
    chaos_r = data.get("chaos", {}).get("results", [])
    v = lambda x, unit="": "n/a" if x is None else f"{x}{unit}"
    lines = [
        "# NetWatch benchmark report",
        "",
        f"Measured on a local Docker Desktop stack (5 nodes, 2 control planes), generated from "
        f"`docs/benchmark-results.json` by `python scripts/benchmark.py report`. Re-run the scripts to refresh.",
        "",
        "## SNMP (T0) vs NetWatch (T1)",
        "",
        f"T0 is a classic NMS poller: `snmpget sysUpTime.0` per node every {v(data.get('snmp', {}).get('snmp_poll_interval_s'), ' s')} "
        "(1 s timeout, 2 retries) over MGMT_NET. T1 is NetWatch: 5 s heartbeats with 7.5 s / 12 s leases, "
        "5 s DATA_NET probe mesh, 15 s alert pending window.",
        "",
        "| Measure | SNMP poller (T0) | NetWatch (T1) |",
        "|---|---|---|",
        f"| Frozen node (`docker pause {f.get('node', 'node-4')}`): time to detect | {v(f.get('snmp_first_failed_poll_s'), ' s')} (first failed poll) | {v(f.get('netwatch_offline_s'), ' s')} (marked offline) |",
        f"| 30% DATA_NET loss on {l.get('node', 'node-3')} | {'detected' if l.get('snmp_detected') else 'not detected (management path unaffected)'} | links degraded in {v(l.get('netwatch_link_degraded_s'), ' s')}, alert in {v(l.get('netwatch_alert_s'), ' s')} |",
        f"| MGMT_NET overhead per node | {v(s.get('snmp_bytes_per_node_min'), ' B/min')} | {v(s.get('netwatch_mgmt_bytes_per_node_min'), ' B/min')} (heartbeats, 1 s signed telemetry, probe results; all TLS) |",
        f"| DATA_NET overhead per node | none | {v(s.get('netwatch_data_bytes_per_node_min'), ' B/min')} (ICMP probe mesh) |",
        f"| False positives in {v(s.get('seconds'), ' s')} steady state | {v(s.get('snmp_false_failures'))} failed polls of {v(s.get('snmp_polls'))} | {v(s.get('netwatch_false_alerts'))} alerts |",
        "",
        "**Reading it:** NetWatch spends far more management bandwidth. The captures show most of it is gRPC: the agent opens a "
        "new TLS channel for every heartbeat and probe result, so reusing one channel per control plane is the obvious next "
        "optimisation (1 s signed telemetry over NATS is the smaller share). It buys two things with that bandwidth. "
        "It detects a dead node within one lease rather than one polling interval. And it sees data-plane degradation that a "
        "management-plane poller cannot see at all. SNMP's detection time depends on where in its polling cycle the failure lands, "
        "so it varies between near zero and one full interval plus timeouts.",
        "",
        "## Chaos scenarios (5.2)",
        "",
        "| Scenario | Detection | Recovery |",
        "|---|---|---|",
    ]
    for r in chaos_r:
        if r["scenario"] == "loss":
            lines.append(f"| {r['loss_pct']}% loss on {r['node']} | degraded {v(r.get('link_degraded_s'), ' s')}, alert {v(r.get('alert_firing_s'), ' s')} | {v(r.get('alerts_resolved_s'), ' s')} |")
        elif r["scenario"] == "delay":
            lines.append(f"| +{r['delay_ms']} ms on {r['node']} | latency alert {v(r.get('alert_firing_s'), ' s')} | {v(r.get('alerts_resolved_s'), ' s')} |")
        elif r["scenario"] == "burst":
            lines.append(f"| iperf3 {r['bandwidth']} {r['src']} → {r['dst']} | NetWatch rx peak {v(r.get('netwatch_peak_rx_mbps'), ' Mbit/s')} vs iperf3 {v(r.get('iperf_received_mbps'), ' Mbit/s')} | - |")
    lines += [
        "",
        "## Packet captures (5.4)",
        "",
        f"`docs/captures/` holds {cap.get('seconds', 'n/a')} s captures from {cap.get('node', 'node-1')} on both networks "
        "(open them in Wireshark); `summary.json` has the counts below. Annotations are in `docs/captures/README.md`.",
        "",
        "| Interface | Packets | gRPC mTLS :50051 | NATS TLS :4222 | ICMP | traceroute UDP | Plaintext markers |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in ("mgmt", "data"):
        c = cap.get(name, {})
        lines.append(f"| {name.upper()}_NET ({cap.get('interfaces', {}).get(name, '?')}) | {v(c.get('packets'))} | {v(c.get('grpc_mtls_50051'))} | "
                     f"{v(c.get('nats_tls_4222'))} | {v(c.get('icmp'))} | {v(c.get('traceroute_udp'))} | "
                     f"{', '.join(c.get('plaintext_markers_found', [])) or 'none'} |")
    lines += [
        "",
        "## Cold start (5.5)",
        "",
        f"From empty volumes (`docker compose down -v`, images cached) to a working mesh; target under {cold.get('limit_s', 300)} s. "
        "CI repeats this on every push on a fresh runner (`benchmark.py cold-start` in `.github/workflows/ci.yml`).",
        "",
        "| Milestone | Seconds |",
        "|---|---|",
    ]
    for k in ("compose_up_returned_s", "api_login_s", "five_nodes_healthy_s", "telemetry_flowing_s", "links_observed_s", "total_s"):
        lines.append(f"| {k.replace('_s', '').replace('_', ' ')} | {v(cold.get(k))} |")
    if cold.get("source"):
        lines += ["", f"Source: {cold['source']}."]
    (DOCS / "BENCHMARK.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {DOCS / 'BENCHMARK.md'}")


def save(key: str, value: Any) -> None:
    DOCS.mkdir(exist_ok=True)
    data = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}
    data[key] = value
    RESULTS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snmp"); s.add_argument("--interval", type=float, default=60); s.add_argument("--steady", type=int, default=120)
    s = sub.add_parser("capture"); s.add_argument("--seconds", type=int, default=20)
    s = sub.add_parser("cold-start"); s.add_argument("--wipe-volumes", action="store_true"); s.add_argument("--limit", type=int, default=300)
    s.add_argument("--out", help="write the result JSON here instead of docs/benchmark-results.json")
    sub.add_parser("chaos-import").add_argument("file")
    sub.add_parser("report")
    args = p.parse_args()
    user, pw = os.environ.get("NETWATCH_USERNAME", "admin"), os.environ.get("NETWATCH_PASSWORD", "netwatch-admin-dev")

    if args.cmd == "report":
        render_report()
        return 0
    if args.cmd == "chaos-import":
        save("chaos", json.loads(Path(args.file).read_text(encoding="utf-8")))
        return 0
    if args.cmd == "cold-start":
        r = run_cold_start(args.wipe_volumes, args.limit)
        print(json.dumps(r, indent=2))
        if args.out:
            Path(args.out).write_text(json.dumps(r, indent=2), encoding="utf-8")
        else:
            save("cold_start", r)
        return 0 if r["passed"] else 1
    api = chaos.Api(user, pw)
    if args.cmd == "snmp":
        save("snmp", run_snmp(api, args.interval, args.steady))
    else:
        save("capture", run_capture(api, args.seconds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
