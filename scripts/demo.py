#!/usr/bin/env python3
"""NetWatch demo scenario (planning S8): normal operation, then four failures, each checked.

    python scripts/demo.py                 # run every act, unattended, exit 1 if a check fails
    python scripts/demo.py --pause         # live presentation: wait for Enter before each act
    python scripts/demo.py --acts cut stop # run only some acts
    python scripts/demo.py --out demo-report.json

Acts (see docs/demo-scenario.md for what to show on screen):
  baseline  everything green: 5 nodes, 20 links, no alert, one leader, 5 SNMP agents
  loss      30 % packet loss on node-3's DATA_NET (tc netem)
  cut       node-4 disconnected from DATA_NET (link cut), then reconnected
  stop      node-5 stopped (node failure), then started
  failover  the leader control plane stopped, then started again

Every fault is undone afterwards, also on Ctrl+C or an error. Checks read the leader's
unauthenticated /metrics and Prometheus (T0, SNMP), so no credentials are needed. Standard
library only; scripts/chaos.py provides the Docker and netem helpers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from typing import Callable
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chaos import clear, docker, netem  # noqa: E402

NODES = [f"node-{i}" for i in range(1, 6)]
DATA_IP = {f"node-{i}": f"172.29.0.{9 + i}" for i in range(1, 6)}
CONTROL_PLANES = {8000: "control-plane-1", 8001: "control-plane-2"}
PROMETHEUS = "http://localhost:9090"
ACTS = ["baseline", "loss", "cut", "stop", "failover"]


# --- observation ---------------------------------------------------------------------------------

def scrape() -> tuple[int | None, str]:
    """(port, /metrics text) of the current leader, or (None, "")."""
    for port in CONTROL_PLANES:
        try:
            text = urllib.request.urlopen(f"http://localhost:{port}/metrics", timeout=2).read().decode()
        except OSError:
            continue
        if re.search(r'^netwatch_control_plane_leader\{[^}]*\} 1$', text, re.M):
            return port, text
    return None, ""


def values(text: str, name: str, **labels: str) -> list[float]:
    out = []
    for line in text.splitlines():
        if line.startswith(name + "{") and all(f'{k}="{v}"' in line for k, v in labels.items()):
            out.append(float(line.rsplit(" ", 1)[1]))
    return out


def promql(query: str) -> float | None:
    """Sum of an instant PromQL query's result, or None if Prometheus is not reachable."""
    try:
        url = f"{PROMETHEUS}/api/v1/query?" + urllib.parse.urlencode({"query": query})
        result = json.load(urllib.request.urlopen(url, timeout=3))["data"]["result"]
    except OSError:
        return None
    return sum(float(r["value"][1]) for r in result)


class Act:
    def __init__(self, name: str, title: str) -> None:
        self.name, self.title, self.checks, self.start = name, title, [], time.time()
        print(f"\n=== {title}", flush=True)

    def mark(self) -> None:
        """Restart the clock (when the fault is applied, then when it is undone)."""
        self.start = time.time()

    def expect(self, what: str, check: Callable[[str], bool], timeout_s: float = 90) -> bool:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            port, text = scrape()
            if text and check(text):
                secs = round(time.time() - self.start, 1)
                print(f"  ok   {secs:6.1f} s  {what}  (leader :{port})", flush=True)
                self.checks.append({"check": what, "ok": True, "seconds": secs})
                return True
            time.sleep(0.5)
        print(f"  FAIL  after {timeout_s:.0f} s: {what}", flush=True)
        self.checks.append({"check": what, "ok": False, "seconds": None})
        return False

    def note(self, text: str) -> None:
        print(f"  ..   {text}", flush=True)

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)


def healthy(text: str) -> bool:
    return (sum(values(text, "netwatch_node_up")) == 5
            and sum(values(text, "netwatch_link_up")) == 20
            and sum(values(text, "netwatch_alerts_open")) == 0)


# --- acts ----------------------------------------------------------------------------------------

def act_baseline(_hold: float) -> Act:
    a = Act("baseline", "Act 1 - normal operation")
    a.expect("5 nodes up, 20 links up, 0 open alerts", healthy, 180)
    a.expect("exactly one leader", lambda t: bool(values(t, "netwatch_control_plane_leader")))
    snmp = promql('sum(up{job="snmp"})')
    a.note(f"T0: {snmp:.0f} SNMP agents answering" if snmp is not None else "T0: Prometheus not reachable, skipped")
    a.note("show: console :8000 (all green), Grafana :3000 T1 + T0 dashboards")
    return a


def act_loss(hold: float) -> Act:
    a = Act("loss", "Act 2 - 30 % packet loss on node-3 (DATA_NET)")
    errors_query = 'sum(ifInErrors{node="node-3"} + ifInDiscards{node="node-3"} + ifOutErrors{node="node-3"} + ifOutDiscards{node="node-3"})'
    errors_before = promql(errors_query)
    with netem("node-3", ["loss", "30%"]):
        a.mark()
        a.expect("T1: node-3 links lossy (> 2 %)",
                 lambda t: sum(1 for v in values(t, "netwatch_link_packet_loss_percent", dst="node-3") if v > 2) >= 2)
        a.expect("T1: loss alert open", lambda t: sum(values(t, "netwatch_alerts_open")) > 0, 60)
        a.expect("node-3 itself stays up", lambda t: values(t, "netwatch_node_up", node_id="node-3") == [1.0])
        a.note(f"holding the fault {hold:.0f} s: show the red links, the alert and Grafana T1 vs T0")
        time.sleep(hold)
        errors_after = promql(errors_query)
        if errors_before is not None and errors_after is not None:
            a.note(f"T0: SNMP errors+discards on node-3 changed by {errors_after - errors_before:.0f} (SNMP does not see path loss)")
    a.mark()
    a.expect("recovered: all green again", healthy, 120)
    return a


def act_cut(hold: float) -> Act:
    a = Act("cut", "Act 3 - link cut: node-4 disconnected from DATA_NET")
    docker("network", "disconnect", "data_net", "node-4")
    try:
        a.expect("T1: all 4 links from node-4 down (100 % loss)",
                 lambda t: values(t, "netwatch_link_up", src="node-4") != [] and sum(values(t, "netwatch_link_up", src="node-4")) == 0)
        a.expect("node-4 stays up (heartbeats use MGMT_NET)", lambda t: values(t, "netwatch_node_up", node_id="node-4") == [1.0])
        a.expect("T1: alert open", lambda t: sum(values(t, "netwatch_alerts_open")) > 0, 60)
        snmp = promql('up{job="snmp",node="node-4"}')
        if snmp is not None:
            a.note(f"T0: SNMP agent on node-4 {'still answers' if snmp == 1 else 'down'} (it is polled over MGMT_NET)")
        a.note(f"holding the cut {hold:.0f} s: show node-4's links in the console and on Grafana T1")
        time.sleep(hold)
    finally:
        docker("network", "connect", "--ip", DATA_IP["node-4"], "data_net", "node-4", check=False)
    a.mark()
    a.expect("recovered: all green again", healthy, 180)
    return a


def act_stop(hold: float) -> Act:
    a = Act("stop", "Act 4 - node failure: node-5 stopped")
    docker("stop", "node-5")
    try:
        a.expect("T1: node-5 offline", lambda t: values(t, "netwatch_node_status", node_id="node-5", status="offline") == [1.0])
        a.expect("T1: 'Node unreachable' alert open", lambda t: sum(values(t, "netwatch_alerts_open")) > 0)
        a.note(f"holding {hold:.0f} s: node-5 red in the console; T0 loses the SNMP agent at its next poll (15 s)")
        time.sleep(hold)
        snmp = promql('up{job="snmp",node="node-5"}')
        if snmp is not None:
            a.note(f"T0: SNMP agent on node-5 {'down' if snmp == 0 else 'not yet marked down'}")
    finally:
        docker("start", "node-5", check=False)
    a.mark()
    a.expect("recovered: all green again", healthy, 180)
    return a


def act_failover(hold: float) -> Act:
    a = Act("failover", "Act 5 - control-plane failover: the leader is stopped")
    port, _ = scrape()
    if port is None:
        a.expect("a leader exists", lambda t: True, 30)
        return a
    leader, other = CONTROL_PLANES[port], next(p for p in CONTROL_PLANES if p != port)
    a.note(f"leader is {leader} (:{port})")
    docker("stop", leader)
    try:
        a.expect(f"{CONTROL_PLANES[other]} (:{other}) took over", lambda _t: scrape()[0] == other, 60)
        a.expect("no node lost during failover", lambda t: sum(values(t, "netwatch_node_up")) == 5)
        a.note(f"holding {hold:.0f} s: the console keeps working on :{other}; Grafana T1 'Leader' changes")
        time.sleep(hold)
    finally:
        docker("start", leader, check=False)
    a.mark()

    def rejoined_as_standby(t: str) -> bool:
        try:
            back = urllib.request.urlopen(f"http://localhost:{port}/metrics", timeout=2).read().decode()
        except OSError:
            return False
        return healthy(t) and re.search(r'^netwatch_control_plane_leader\{[^}]*\} 0$', back, re.M) is not None

    a.expect(f"{leader} back as standby, all green, one leader", rejoined_as_standby, 120)
    return a


RUNNERS = {"baseline": act_baseline, "loss": act_loss, "cut": act_cut, "stop": act_stop, "failover": act_failover}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--acts", nargs="+", choices=ACTS, default=ACTS)
    ap.add_argument("--pause", action="store_true", help="wait for Enter before each act (live demo)")
    ap.add_argument("--hold", type=float, default=10.0, help="seconds to keep each fault visible (default 10)")
    ap.add_argument("--out", help="write the results as JSON")
    args = ap.parse_args()

    clear(NODES)  # no leftover netem from an interrupted run
    results = []
    for name in args.acts:
        if args.pause:
            input(f"\n[Enter] to start '{name}' ")
        act = RUNNERS[name](args.hold)
        results.append({"act": act.name, "title": act.title, "ok": act.ok, "checks": act.checks})

    print("\n=== Summary")
    for r in results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['title']}")
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
