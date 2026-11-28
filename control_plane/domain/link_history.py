"""Bitemporal history of observed links (topology_links).

Each row states: "during valid_during the link src->dst existed with this status", and
recorded_during says when the database held that belief. Rows are never edited except to
end their recorded_during; every change of belief inserts new rows. So:

- GET /topology?at=T          -> what the network looked like at T (valid time)
- GET /topology?known_at=K    -> what NetWatch believed at K (system time)

A status change at time t (one transaction, t = NOW()):
    current row      valid [t0, inf)  recorded [r0, inf)  ->  recorded [r0, t)   (belief ended)
    closed version   valid [t0, t)    recorded [t, inf)       (same status, now known to end at t)
    new version      valid [t, inf)   recorded [t, inf)       (new status)
Closing a link (node offline/revoked) is the same without the new version.

The no_overlapping_links constraint excludes overlap in *both* time dimensions, so the
retired row and its replacements coexist.

Status is derived from the trailing 30s of probe results with hysteresis, not from a single
2-packet probe (whose loss can only be 0/50/100%), so a lossy link does not create a new
version on every probe.
"""
from typing import Any

import psycopg

from control_plane.adapters.elector import LeaderElector

STATUS_WINDOW_S = 30
DEGRADE_LOSS_PCT = 2.0
RECOVER_LOSS_PCT = 1.0

# The row NetWatch currently believes describes the link right now.
CURRENT_ROW = "upper_inf(valid_during) AND upper_inf(recorded_during)"

_CLOSE_VERSION_INSERT = """
    INSERT INTO topology_links (
        src_node_id, dst_node_id, status, latency_ms, packet_loss_pct, valid_during, recorded_during
    )
    SELECT src_node_id, dst_node_id, status, latency_ms, packet_loss_pct,
           tstzrange(lower(valid_during), NOW(), '[)'), tstzrange(NOW(), NULL, '[)')
    FROM retired
    WHERE lower(valid_during) < NOW()
"""

TRANSITION_SQL = f"""
WITH retired AS (
    UPDATE topology_links
    SET recorded_during = tstzrange(lower(recorded_during), NOW(), '[)')
    WHERE link_id = %s AND {CURRENT_ROW}
    RETURNING src_node_id, dst_node_id, status, latency_ms, packet_loss_pct, valid_during
), closed AS (
    {_CLOSE_VERSION_INSERT}
)
INSERT INTO topology_links (
    src_node_id, dst_node_id, status, latency_ms, packet_loss_pct, valid_during, recorded_during
)
SELECT src_node_id, dst_node_id, %s, %s, %s, tstzrange(NOW(), NULL, '[)'), tstzrange(NOW(), NULL, '[)')
FROM retired;
"""

OPEN_SQL = """
INSERT INTO topology_links (
    src_node_id, dst_node_id, status, latency_ms, packet_loss_pct, valid_during, recorded_during
)
VALUES (%s, %s, %s, %s, %s, tstzrange(NOW(), NULL, '[)'), tstzrange(NOW(), NULL, '[)'));
"""

# {where} filters the current rows to close, e.g. links touching offline nodes.
CLOSE_SQL_TEMPLATE = f"""
WITH retired AS (
    UPDATE topology_links
    SET recorded_during = tstzrange(lower(recorded_during), NOW(), '[)')
    WHERE {CURRENT_ROW} AND ({{where}})
    RETURNING src_node_id, dst_node_id, status, latency_ms, packet_loss_pct, valid_during
)
{_CLOSE_VERSION_INSERT};
"""

CLOSE_FOR_INACTIVE_NODES_SQL = CLOSE_SQL_TEMPLATE.format(
    where=(
        "src_node_id IN (SELECT node_id FROM nodes WHERE health_status IN ('offline', 'revoked')) "
        "OR dst_node_id IN (SELECT node_id FROM nodes WHERE health_status IN ('offline', 'revoked'))"
    )
)
CLOSE_FOR_NODE_SQL = CLOSE_SQL_TEMPLATE.format(where="src_node_id = %s OR dst_node_id = %s")


def next_status(current: str | None, avg_loss_pct: float | None) -> str:
    """Link status from the window's average loss, with hysteresis once degraded."""
    if avg_loss_pct is None:
        return current or "up"
    if current == "degraded":
        return "up" if avg_loss_pct <= RECOVER_LOSS_PCT else "degraded"
    return "degraded" if avg_loss_pct > DEGRADE_LOSS_PCT else "up"


def observe_link(
    conn: psycopg.Connection[Any],
    elector: LeaderElector,
    src: str,
    dst: str,
    probe_success: bool,
    probe_loss_pct: float = 0.0,
    probe_latency_ms: float | None = None,
    window_s: int = STATUS_WINDOW_S,
) -> str:
    """Applies a probe (already written to probe_results) to the link's history.

    Returns 'opened', 'transitioned', 'unchanged', 'skipped' or 'fenced'.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT link_id, status, lower(valid_during) FROM topology_links "
            f"WHERE src_node_id = %s AND dst_node_id = %s AND {CURRENT_ROW} FOR UPDATE;",
            (src, dst),
        )
        current = cur.fetchone()

        if current is None:
            if not probe_success:
                return "skipped"  # a failed probe never opens a link
            # A new segment starts from this probe alone: samples from before it existed (e.g. the
            # failed probes of an outage that just ended) must not colour the reopened link.
            status = next_status(None, probe_loss_pct)
            written = elector.fenced_execute(conn, OPEN_SQL, (src, dst, status, probe_latency_ms, probe_loss_pct))
            return "opened" if written else "fenced"

        link_id, current_status, segment_start = current
        cur.execute(
            """
            SELECT AVG(packet_loss_pct), AVG(latency_ms) FILTER (WHERE success)
            FROM probe_results
            WHERE src_node_id = %s AND dst_node_id = %s
              AND time >= GREATEST(NOW() - make_interval(secs => %s), %s);
            """,
            (src, dst, window_s, segment_start),
        )
        window = cur.fetchone() or (None, None)
    avg_loss = float(window[0]) if window[0] is not None else None
    avg_latency = float(window[1]) if window[1] is not None else None

    status = next_status(current_status, avg_loss)
    if status == current_status:
        return "unchanged"
    written = elector.fenced_execute(conn, TRANSITION_SQL, (link_id, status, avg_latency, avg_loss))
    return "transitioned" if written else "fenced"
