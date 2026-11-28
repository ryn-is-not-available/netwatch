"""Builds the evidence bundle the model reasons over, and verifies what it returns.

Every evidence item carries a stable id ("node:...", "link:a->b", "missing:a->b",
"alert:<uuid>", "trace:<uuid>"). The model must cite these ids; findings that cite nothing,
or cite ids that are not in the bundle, are rejected. Suggested actions are re-checked
against the same rules the console applies, so a finding can never trigger an action on
a node or link that the evidence does not show.

Evidence text is untrusted (node ids come from enrollment, alert messages embed them), so
every string is stripped of control characters and length-capped before it is sent.
"""
from dataclasses import dataclass, field
import re
from typing import Any

import psycopg

MAX_TEXT = 200
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

SEVERITIES = ("info", "warning", "critical")
ACTION_TYPES = ("none", "declare_link", "run_trace")


def clean(value: Any, limit: int = MAX_TEXT) -> str:
    text = _CONTROL.sub(" ", str(value if value is not None else ""))
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class Evidence:
    items: dict[str, dict[str, Any]] = field(default_factory=dict)
    node_status: dict[str, str] = field(default_factory=dict)
    observed: set[tuple[str, str]] = field(default_factory=set)
    declared: set[tuple[str, str]] = field(default_factory=set)

    def add(self, item_id: str, **fields: Any) -> None:
        self.items[item_id] = {"id": item_id, **fields}

    def as_payload(self) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {"nodes": [], "links": [], "missing_links": [], "alerts": [], "traces": []}
        prefix_to_group = {"node": "nodes", "link": "links", "missing": "missing_links", "alert": "alerts", "trace": "traces"}
        for item_id, item in self.items.items():
            groups[prefix_to_group[item_id.split(":", 1)[0]]].append(item)
        return groups


def build_evidence(conn: psycopg.Connection[Any], window_s: int = 60) -> Evidence:
    """Reads the current network state. Uses only SELECTs (the worker's role is read-only)."""
    ev = Evidence()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT node_id, health_status, EXTRACT(EPOCH FROM NOW() - last_heartbeat) FROM nodes ORDER BY node_id;"
        )
        for node_id, status, age in cur.fetchall():
            nid = clean(node_id, 64)
            ev.node_status[node_id] = status
            ev.add(f"node:{nid}", node_id=nid, status=status,
                   heartbeat_age_s=None if age is None else round(float(age), 1))

        cur.execute("SELECT src_node_id, dst_node_id, expected_latency_ms FROM desired_topology_links;")
        slo = {(s, d): float(ms) for s, d, ms in cur.fetchall()}
        ev.declared = set(slo)

        cur.execute(
            """
            SELECT tl.src_node_id, tl.dst_node_id, tl.status,
                   AVG(pr.packet_loss_pct), AVG(pr.latency_ms) FILTER (WHERE pr.success), COUNT(pr.*)
            FROM topology_links tl
            LEFT JOIN probe_results pr
              ON pr.src_node_id = tl.src_node_id AND pr.dst_node_id = tl.dst_node_id
             AND pr.time >= GREATEST(NOW() - make_interval(secs => %s), lower(tl.valid_during))
            WHERE upper_inf(tl.valid_during) AND upper_inf(tl.recorded_during)
            GROUP BY tl.src_node_id, tl.dst_node_id, tl.status
            ORDER BY 1, 2;
            """,
            (window_s,),
        )
        for src, dst, status, loss, latency, samples in cur.fetchall():
            ev.observed.add((src, dst))
            ev.add(
                f"link:{clean(src, 64)}->{clean(dst, 64)}",
                src=clean(src, 64), dst=clean(dst, 64), status=status, declared=(src, dst) in slo,
                latency_slo_ms=slo.get((src, dst)),
                loss_pct=None if loss is None else round(float(loss), 1),
                latency_ms=None if latency is None else round(float(latency), 2),
                samples=int(samples),
            )
        for src, dst in sorted(ev.declared - ev.observed):
            ev.add(f"missing:{clean(src, 64)}->{clean(dst, 64)}", src=clean(src, 64), dst=clean(dst, 64),
                   note="declared in the desired topology but not currently observed")

        cur.execute(
            """
            SELECT alert_id::text, severity, status, message, affected_node_id,
                   EXTRACT(EPOCH FROM NOW() - created_at)
            FROM alerts WHERE status <> 'resolved' ORDER BY created_at DESC LIMIT 20;
            """
        )
        for alert_id, severity, status, message, node, age in cur.fetchall():
            ev.add(f"alert:{alert_id}", severity=severity, status=status, message=clean(message),
                   node=clean(node, 64) if node else None, age_s=round(float(age), 1))

        cur.execute(
            """
            SELECT trace_id::text, src_node_id, dst_node_id, hops, packet_loss_pct, avg_latency_ms
            FROM path_traces WHERE captured_at > NOW() - interval '15 minutes'
            ORDER BY captured_at DESC LIMIT 10;
            """
        )
        for trace_id, src, dst, hops, loss, latency in cur.fetchall():
            hop_list = hops if isinstance(hops, list) else []
            ev.add(
                f"trace:{trace_id}",
                src=clean(src, 64), dst=clean(dst, 64),
                status=clean((hop_list[0] or {}).get("status", "UNKNOWN") if hop_list else "UNKNOWN", 16),
                hops=[clean(h.get("node_id") or h.get("ip"), 64) for h in hop_list[:8] if isinstance(h, dict)],
                loss_pct=None if loss is None else float(loss),
                latency_ms=None if latency is None else float(latency),
            )
    return ev


def verify(raw: dict[str, Any], ev: Evidence) -> tuple[list[dict[str, Any]], list[str]]:
    """Keeps findings whose citations all exist in the evidence; re-checks their actions.

    Returns (accepted_findings, rejection_notes).
    """
    accepted: list[dict[str, Any]] = []
    notes: list[str] = []
    for i, f in enumerate(raw.get("findings") or []):
        title = clean(f.get("title"), 120) or f"finding {i + 1}"
        cites = [c for c in f.get("citations") or [] if isinstance(c, str)]
        unknown = [c for c in cites if c not in ev.items]
        if not cites:
            notes.append(f"dropped '{title}': no citations")
            continue
        if unknown:
            notes.append(f"dropped '{title}': cites ids not in the evidence ({', '.join(clean(u, 60) for u in unknown[:3])})")
            continue

        rec = f.get("recommendation") or {}
        action = rec.get("action") or {}
        a_type, src, dst = action.get("type"), action.get("src") or "", action.get("dst") or ""
        checked: dict[str, Any] = {"type": "none"}
        if a_type == "declare_link":
            if (src, dst) in ev.observed and (src, dst) not in ev.declared:
                checked = {"type": "declare_link", "src": src, "dst": dst}
            else:
                notes.append(f"'{title}': declare_link {clean(src, 40)}->{clean(dst, 40)} is not an observed undeclared link; action removed")
        elif a_type == "run_trace":
            if src != dst and src in ev.node_status and dst in ev.node_status and ev.node_status[src] not in ("offline", "revoked"):
                checked = {"type": "run_trace", "src": src, "dst": dst}
            else:
                notes.append(f"'{title}': run_trace {clean(src, 40)}->{clean(dst, 40)} is not runnable; action removed")

        accepted.append({
            "title": title,
            "severity": f.get("severity") if f.get("severity") in SEVERITIES else "info",
            "explanation": clean(f.get("explanation"), 1000),
            "suggested_fix": clean(rec.get("suggested_fix"), 500),
            "citations": cites,
            "action": checked,
        })
    return accepted, notes
