"""Prometheus text exposition of NetWatch state (planning S3), served at GET /metrics.

Pure rendering: the route gathers rows, this module turns them into the text format. Only
operational numbers are exposed (health, link quality, alert counts, leadership), never
users, tokens or addresses. Label values come from the database and may be chosen by an
enrolled node, so they are escaped as the format requires.
"""
from typing import Any, Iterable

NODE_STATUSES = ("enrolled", "healthy", "degraded", "offline", "revoked")
LINK_STATUSES = ("up", "degraded", "down")
SEVERITIES = ("info", "warning", "critical")
CUT_LOSS_PCT = 100.0  # every probe in the 30 s window lost


def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**kv: Any) -> str:
    return "{" + ",".join(f'{k}="{_label(v)}"' for k, v in kv.items()) + "}" if kv else ""


class _Doc:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(self, name: str, kind: str, help_text: str, samples: Iterable[tuple[dict[str, Any], float]]) -> None:
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            self.lines.append(f"{name}{_labels(**labels)} {float(value):g}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(
    *,
    instance_id: str,
    is_leader: bool,
    epoch: int,
    db_up: bool | None,
    nodes: list[tuple[str, str, float | None]] | None = None,
    links: list[tuple[str, str, str, float, float]] | None = None,
    open_alerts: list[tuple[str, int]] | None = None,
) -> str:
    """nodes: (node_id, health_status, heartbeat_age_s); links: (src, dst, status, latency_ms,
    loss_pct); open_alerts: (severity, count) for alerts that are not resolved.
    db_up=None (a standby replica) renders the leadership gauges only."""
    doc = _Doc()
    inst = {"instance_id": instance_id}
    doc.family("netwatch_control_plane_leader", "gauge", "1 if this control plane holds the leader lock.",
               [(inst, 1 if is_leader else 0)])
    doc.family("netwatch_control_plane_epoch", "gauge", "Current leader epoch seen by this control plane.",
               [(inst, epoch)])
    if db_up is None:
        return doc.text()
    doc.family("netwatch_db_up", "gauge", "1 if the leader could read the database for this scrape.",
               [(inst, 1 if db_up else 0)])
    if not db_up:
        return doc.text()

    nodes = nodes or []
    doc.family("netwatch_node_status", "gauge", "1 for the node's current health status (one series per status).",
               [({"node_id": n, "status": s}, 1 if st == s else 0) for n, st, _ in nodes for s in NODE_STATUSES])
    doc.family("netwatch_node_up", "gauge", "1 if the node is healthy or degraded (heartbeating), else 0.",
               [({"node_id": n}, 1 if st in ("healthy", "degraded") else 0) for n, st, _ in nodes])
    doc.family("netwatch_node_heartbeat_age_seconds", "gauge", "Seconds since the node's last heartbeat.",
               [({"node_id": n}, age) for n, _, age in nodes if age is not None])

    links = links or []
    # A cut link is stored as `degraded` with 100 % loss (the alert engine keeps alerting on it),
    # so "up" here means "carried probe traffic in the last 30 s".
    doc.family("netwatch_link_up", "gauge",
               "1 if the observed link carried probe traffic in the last 30 s; 0 if down or 100% loss.",
               [({"src": s, "dst": d}, 0 if st == "down" or loss >= CUT_LOSS_PCT else 1)
                for s, d, st, _, loss in links])
    doc.family("netwatch_link_status", "gauge", "1 for the observed link's current status (one series per status).",
               [({"src": s, "dst": d, "status": x}, 1 if st == x else 0) for s, d, st, _, _ in links for x in LINK_STATUSES])
    doc.family("netwatch_link_latency_ms", "gauge", "Mean probe latency over the last 30 s, in milliseconds.",
               [({"src": s, "dst": d}, lat) for s, d, _, lat, _ in links])
    doc.family("netwatch_link_packet_loss_percent", "gauge", "Mean probe packet loss over the last 30 s, in percent.",
               [({"src": s, "dst": d}, loss) for s, d, _, _, loss in links])

    counts = dict(open_alerts or [])
    doc.family("netwatch_alerts_open", "gauge", "Alerts not yet resolved, by severity.",
               [({"severity": sev}, counts.get(sev, 0)) for sev in SEVERITIES])
    return doc.text()
