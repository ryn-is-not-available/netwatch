from dataclasses import dataclass
import heapq
import logging
import math
from typing import Any

import psycopg

logger = logging.getLogger("netwatch.control_plane.graph_engine")

LOSS_THRESHOLD_PCT = 2.0


@dataclass(frozen=True)
class DeclaredLink:
    src_node_id: str
    dst_node_id: str
    admin_cost: float = 1.0


@dataclass(frozen=True)
class ObservedLink:
    src_node_id: str
    dst_node_id: str
    status: str  # 'up' | 'degraded' | 'down'
    latency_ms: float = 0.0
    packet_loss_pct: float = 0.0


@dataclass(frozen=True)
class DriftItem:
    drift_type: str  # 'missing_declared' | 'extra_observed' | 'lossy_link'
    src_node_id: str
    dst_node_id: str
    details: str
    severity: str  # 'warning' | 'critical'


class TopologyGraphEngine:
    """Computes nominal Dijkstra routes and detects topology/SLA drift."""

    def __init__(self, loss_threshold_pct: float = LOSS_THRESHOLD_PCT) -> None:
        self.loss_threshold_pct = loss_threshold_pct

    def shortest_path(
        self,
        declared_links: list[DeclaredLink],
        src: str,
        dst: str,
    ) -> tuple[float, list[str]]:
        """Dijkstra shortest path over `admin_cost`.

        Returns `(total_cost, [src, ..., dst])`, or `(math.inf, [])` if no path exists.
        """
        if src == dst:
            return (0.0, [src])

        adj: dict[str, list[tuple[str, float]]] = {}
        for link in declared_links:
            if link.admin_cost < 0:
                continue
            adj.setdefault(link.src_node_id, []).append(
                (link.dst_node_id, float(link.admin_cost))
            )

        best_dist: dict[str, float] = {src: 0.0}
        heap: list[tuple[float, str, list[str]]] = [(0.0, src, [src])]

        while heap:
            cost, node, path = heapq.heappop(heap)

            if node == dst:
                return (cost, path)

            if cost > best_dist.get(node, math.inf):
                continue

            for nxt, weight in adj.get(node, ()):
                new_cost = cost + weight
                if new_cost < best_dist.get(nxt, math.inf):
                    best_dist[nxt] = new_cost
                    heapq.heappush(heap, (new_cost, nxt, path + [nxt]))

        return (math.inf, [])

    def compute_drift(
        self,
        declared_links: list[DeclaredLink],
        observed_links: list[ObservedLink],
    ) -> list[DriftItem]:
        """Diffs declared vs active observed links and flags packet loss above threshold."""
        declared_map: dict[tuple[str, str], DeclaredLink] = {
            (link.src_node_id, link.dst_node_id): link for link in declared_links
        }
        active_obs: dict[tuple[str, str], ObservedLink] = {
            (link.src_node_id, link.dst_node_id): link
            for link in observed_links
            if link.status != "down"
        }

        drift_items: list[DriftItem] = []

        for edge in sorted(set(declared_map) - set(active_obs)):
            drift_items.append(
                DriftItem(
                    "missing_declared",
                    edge[0],
                    edge[1],
                    "Declared link missing or down",
                    "critical",
                )
            )

        for edge in sorted(set(active_obs) - set(declared_map)):
            drift_items.append(
                DriftItem(
                    "extra_observed",
                    edge[0],
                    edge[1],
                    "Undeclared active link observed",
                    "warning",
                )
            )

        for edge in sorted(active_obs):
            obs = active_obs[edge]
            if obs.packet_loss_pct > self.loss_threshold_pct:
                drift_items.append(
                    DriftItem(
                        "lossy_link",
                        edge[0],
                        edge[1],
                        (
                            f"Packet loss {obs.packet_loss_pct:.2f}% > "
                            f"{self.loss_threshold_pct:.2f}%"
                        ),
                        "warning",
                    )
                )

        return drift_items

    def load_observed_from_db(
        self,
        conn: psycopg.Connection[Any],
        window_seconds: int = 30,
    ) -> list[ObservedLink]:
        """Loads currently open topology_links enriched with trailing window average metrics."""
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    tl.src_node_id,
                    tl.dst_node_id,
                    tl.status,
                    COALESCE(AVG(pr.latency_ms), tl.latency_ms, 0.0) AS avg_lat,
                    COALESCE(AVG(pr.packet_loss_pct), tl.packet_loss_pct, 0.0) AS avg_loss
                FROM topology_links tl
                LEFT JOIN probe_results pr
                  ON pr.src_node_id = tl.src_node_id
                 AND pr.dst_node_id = tl.dst_node_id
                 AND pr.time >= NOW() - make_interval(secs => %s)
                WHERE upper_inf(tl.valid_during)
                GROUP BY tl.src_node_id, tl.dst_node_id, tl.status, tl.latency_ms, tl.packet_loss_pct;
                """,
                (window_seconds,),
            )
            return [
                ObservedLink(
                    src_node_id=row[0],
                    dst_node_id=row[1],
                    status=row[2],
                    latency_ms=float(row[3] or 0.0),
                    packet_loss_pct=float(row[4] or 0.0),
                )
                for row in cur.fetchall()
            ]