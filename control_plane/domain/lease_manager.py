import logging
import threading
import time
from typing import Any

import psycopg

from control_plane.adapters.elector import LeaderElector

logger = logging.getLogger("netwatch.control_plane.lease_manager")

DEGRADED_THRESHOLD_S = 7.5
UNREACHABLE_THRESHOLD_S = 12.0


class LeaseManager:
    """Leader-only background worker that detects silent nodes and closes dead observed links."""

    def __init__(
        self,
        db_dsn: str,
        elector: LeaderElector,
        degraded_after_s: float = DEGRADED_THRESHOLD_S,
        unreachable_after_s: float = UNREACHABLE_THRESHOLD_S,
        tick_interval_s: float = 0.5,
    ) -> None:
        self._db_dsn = db_dsn
        self._elector = elector
        self.degraded_after_s = degraded_after_s
        self.unreachable_after_s = unreachable_after_s
        self.tick_interval_s = tick_interval_s

    def evaluate_once(self) -> tuple[int, int, int]:
        """Runs a single fenced lease evaluation pass.

        Returns (degraded_count, offline_count, closed_links_count).
        """
        is_ldr, epoch = self._elector.current_term()
        if not is_ldr or epoch <= 0:
            return (0, 0, 0)

        with psycopg.connect(self._db_dsn) as conn:
            degraded_count = self._mark_degraded(conn, epoch)
            offline_count = self._mark_offline(conn, epoch)
            closed_links = self._close_links_for_offline_nodes(conn, epoch)
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
        close_sql = """
        UPDATE topology_links
        SET status = 'down',
            valid_during = tstzrange(lower(valid_during), NOW(), '[)')
        WHERE upper_inf(valid_during)
          AND (
              src_node_id IN (SELECT node_id FROM nodes WHERE health_status = 'offline')
              OR dst_node_id IN (SELECT node_id FROM nodes WHERE health_status = 'offline')
          );
        """
        closed = self._elector.fenced_execute(
            conn,
            close_sql,
            (),
            expected_epoch=epoch,
        )

        if closed > 0:
            alert_sql = """
            INSERT INTO alerts (severity, status, message)
            VALUES (%s, %s, %s);
            """
            self._elector.fenced_execute(
                conn,
                alert_sql,
                (
                    "critical",
                    "new",
                    "Node unreachable (>12s heartbeat timeout); observed links closed",
                ),
                expected_epoch=epoch,
            )

        return closed

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