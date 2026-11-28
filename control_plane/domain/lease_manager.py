import logging
import threading
import time
from typing import Any

import psycopg

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.link_history import CLOSE_FOR_INACTIVE_NODES_SQL

logger = logging.getLogger("netwatch.control_plane.lease_manager")

DEGRADED_THRESHOLD_S = 7.5
UNREACHABLE_THRESHOLD_S = 12.0
# Stable message prefix: one open "unreachable" alert per node, resolved when it heartbeats again.
UNREACHABLE_ALERT_PREFIX = "Node unreachable"


class LeaseManager:
    """Leader-only background worker that detects silent nodes and closes dead observed links."""

    def __init__(
        self,
        db_dsn: str,
        elector: LeaderElector,
        degraded_after_s: float = DEGRADED_THRESHOLD_S,
        unreachable_after_s: float = UNREACHABLE_THRESHOLD_S,
        tick_interval_s: float = 0.5,
        takeover_grace_s: float | None = None,
    ) -> None:
        self._db_dsn = db_dsn
        self._elector = elector
        self.degraded_after_s = degraded_after_s
        self.unreachable_after_s = unreachable_after_s
        self.tick_interval_s = tick_interval_s
        # After winning an election, give every node one full lease before judging it: while
        # no leader existed, both replicas declined heartbeats, so last_heartbeat went stale
        # through no fault of the nodes.
        self.takeover_grace_s = unreachable_after_s if takeover_grace_s is None else takeover_grace_s
        self._term_epoch = 0
        self._term_started = 0.0

    def evaluate_once(self) -> tuple[int, int, int]:
        """Runs a single fenced lease evaluation pass.

        Returns (degraded_count, offline_count, closed_links_count).
        """
        is_ldr, epoch = self._elector.current_term()
        if not is_ldr or epoch <= 0:
            return (0, 0, 0)

        if epoch != self._term_epoch:
            self._term_epoch = epoch
            self._term_started = time.monotonic()
            if self.takeover_grace_s > 0:
                logger.info(
                    "New leader term (epoch=%d): lease grace period of %.1fs before evicting nodes",
                    epoch,
                    self.takeover_grace_s,
                )
        if time.monotonic() - self._term_started < self.takeover_grace_s:
            return (0, 0, 0)

        with psycopg.connect(self._db_dsn) as conn:
            degraded_count = self._mark_degraded(conn, epoch)
            offline_count = self._mark_offline(conn, epoch)
            closed_links = self._close_links_for_offline_nodes(conn, epoch)
            self._sync_unreachable_alerts(conn, epoch)
            conn.commit()

        if degraded_count or offline_count or closed_links:
            logger.warning(
                "Lease sweep (epoch=%d): degraded=%d, offline=%d, closed_links=%d",
                epoch,
                degraded_count,
                offline_count,
                closed_links,
            )
        return (degraded_count, offline_count, closed_links)

    def _mark_degraded(self, conn: psycopg.Connection[Any], epoch: int) -> int:
        sql = """
        UPDATE nodes
        SET health_status = 'degraded'
        WHERE health_status = 'healthy'
          AND last_heartbeat < NOW() - make_interval(secs => %s)
          AND last_heartbeat >= NOW() - make_interval(secs => %s);
        """
        return self._elector.fenced_execute(
            conn,
            sql,
            (self.degraded_after_s, self.unreachable_after_s),
            expected_epoch=epoch,
        )

    def _mark_offline(self, conn: psycopg.Connection[Any], epoch: int) -> int:
        sql = """
        UPDATE nodes
        SET health_status = 'offline'
        WHERE health_status IN ('enrolled', 'healthy', 'degraded')
          AND last_heartbeat <= NOW() - make_interval(secs => %s);
        """
        return self._elector.fenced_execute(
            conn,
            sql,
            (self.unreachable_after_s,),
            expected_epoch=epoch,
        )

    def _close_links_for_offline_nodes(self, conn: psycopg.Connection[Any], epoch: int) -> int:
        # Ends the links' valid time as a new version; the old belief is kept (bitemporal).
        close_sql = CLOSE_FOR_INACTIVE_NODES_SQL
        return self._elector.fenced_execute(
            conn,
            close_sql,
            (),
            expected_epoch=epoch,
        )

    def _sync_unreachable_alerts(self, conn: psycopg.Connection[Any], epoch: int) -> None:
        """Raises one alert per offline node (deduplicated) and resolves it once the node is back."""
        self._elector.fenced_execute(
            conn,
            """
            INSERT INTO alerts (affected_node_id, severity, status, message)
            SELECT n.node_id, 'critical', 'new', %s
            FROM nodes n
            WHERE n.health_status = 'offline'
              AND NOT EXISTS (
                  SELECT 1 FROM alerts a
                  WHERE a.affected_node_id = n.node_id
                    AND a.status <> 'resolved'
                    AND a.message LIKE %s
              );
            """,
            (
                f"{UNREACHABLE_ALERT_PREFIX} (>{self.unreachable_after_s:g}s heartbeat timeout); "
                "observed links closed",
                f"{UNREACHABLE_ALERT_PREFIX}%",
            ),
            expected_epoch=epoch,
        )
        self._elector.fenced_execute(
            conn,
            """
            UPDATE alerts a
            SET status = 'resolved'
            FROM nodes n
            WHERE a.affected_node_id = n.node_id
              AND n.health_status IN ('enrolled', 'healthy')
              AND a.status <> 'resolved'
              AND a.message LIKE %s;
            """,
            (f"{UNREACHABLE_ALERT_PREFIX}%",),
            expected_epoch=epoch,
        )

    def run_forever(self, stop_event: threading.Event) -> None:
        logger.info(
            "Starting LeaseManager loop (degraded>%.1fs, unreachable>%.1fs)",
            self.degraded_after_s,
            self.unreachable_after_s,
        )
        while not stop_event.is_set():
            if self._elector.is_leader:
                try:
                    self.evaluate_once()
                except Exception as exc:
                    logger.error("LeaseManager sweep failed: %s", exc)
            stop_event.wait(timeout=self.tick_interval_s)