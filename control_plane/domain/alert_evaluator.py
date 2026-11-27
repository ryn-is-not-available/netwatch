from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any

import psycopg

from control_plane.adapters.elector import FencingError, LeaderElector

logger = logging.getLogger("netwatch.control_plane.alert_evaluator")

CREATE_ALERT_TIMERS_SQL = """
CREATE TABLE IF NOT EXISTS alert_timers (
    fingerprint VARCHAR(255) PRIMARY KEY,
    state VARCHAR(32) NOT NULL CHECK (state IN ('PENDING', 'FIRING')),
    pending_since TIMESTAMPTZ NOT NULL,
    fired_at TIMESTAMPTZ,
    alert_id UUID REFERENCES alerts(alert_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass(frozen=True)
class AlertRuleEval:
    fingerprint: str
    severity: str  # 'info' | 'warning' | 'critical'
    message: str
    value: float
    trigger_threshold: float
    resolve_threshold: float
    pending_duration_s: float = 30.0
    affected_node_id: str | None = None


class AlertEvaluator:
    """Stateful alert evaluator with persisted PENDING timers, hysteresis, and fingerprint dedupe."""

    def __init__(self, elector: LeaderElector) -> None:
        self._elector = elector

    def ensure_schema(self, conn: psycopg.Connection[Any]) -> None:
        with conn.cursor() as cur:
            cur.execute(CREATE_ALERT_TIMERS_SQL)

    def _insert_alert(
        self,
        conn: psycopg.Connection[Any],
        rule: AlertRuleEval,
        epoch: int,
    ) -> Any:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM leader_epoch
                WHERE epoch = %s AND leader_id = %s AND status = 'active'
                FOR SHARE;
                """,
                (epoch, self._elector.instance_id),
            )
            if cur.fetchone() is None:
                raise FencingError(f"Stale leader epoch {epoch} during alert creation")

            cur.execute(
                """
                INSERT INTO alerts (affected_node_id, severity, status, message)
                VALUES (%s, %s, 'new', %s)
                RETURNING alert_id;
                """,
                (rule.affected_node_id, rule.severity, rule.message),
            )
            row = cur.fetchone()
            return row[0] if row else None

    def evaluate(
        self,
        conn: psycopg.Connection[Any],
        rule: AlertRuleEval,
        now: datetime | None = None,
    ) -> str:
        """Evaluates one rule sample and returns resulting state: 'OK', 'PENDING', or 'FIRING'."""
        now_ts = now or datetime.now(timezone.utc)
        is_ldr, epoch = self._elector.current_term()
        if not is_ldr or epoch <= 0:
            return "OK"

        with conn.cursor() as cur:
            cur.execute(
                "SELECT state, pending_since, alert_id FROM alert_timers WHERE fingerprint = %s FOR UPDATE;",
                (rule.fingerprint,),
            )
            existing = cur.fetchone()

        cur_state: str = existing[0] if existing else "OK"
        pending_since: datetime | None = existing[1] if existing else None
        alert_id: Any = existing[2] if existing else None

        breached = rule.value > rule.trigger_threshold
        recovered = rule.value <= rule.resolve_threshold

        if breached:
            if cur_state == "OK":
                if rule.pending_duration_s <= 0:
                    new_alert_id = self._insert_alert(conn, rule, epoch)
                    self._elector.fenced_execute(
                        conn,
                        """
                        INSERT INTO alert_timers (fingerprint, state, pending_since, fired_at, alert_id, updated_at)
                        VALUES (%s, 'FIRING', %s, %s, %s, %s);
                        """,
                        (rule.fingerprint, now_ts, now_ts, new_alert_id, now_ts),
                        expected_epoch=epoch,
                    )
                    return "FIRING"

                self._elector.fenced_execute(
                    conn,
                    """
                    INSERT INTO alert_timers (fingerprint, state, pending_since, updated_at)
                    VALUES (%s, 'PENDING', %s, %s);
                    """,
                    (rule.fingerprint, now_ts, now_ts),
                    expected_epoch=epoch,
                )
                return "PENDING"

            if cur_state == "PENDING":
                elapsed = (
                    (now_ts - pending_since).total_seconds()
                    if pending_since is not None
                    else rule.pending_duration_s
                )
                if elapsed >= rule.pending_duration_s:
                    new_alert_id = self._insert_alert(conn, rule, epoch)
                    self._elector.fenced_execute(
                        conn,
                        """
                        UPDATE alert_timers
                        SET state = 'FIRING', fired_at = %s, alert_id = %s, updated_at = %s
                        WHERE fingerprint = %s;
                        """,
                        (now_ts, new_alert_id, now_ts, rule.fingerprint),
                        expected_epoch=epoch,
                    )
                    return "FIRING"
                return "PENDING"

            if cur_state == "FIRING":
                self._elector.fenced_execute(
                    conn,
                    """
                    UPDATE alert_timers
                    SET updated_at = %s
                    WHERE fingerprint = %s;
                    """,
                    (now_ts, rule.fingerprint),
                    expected_epoch=epoch,
                )
                return "FIRING"

        if cur_state == "PENDING":
            self._elector.fenced_execute(
                conn,
                "DELETE FROM alert_timers WHERE fingerprint = %s;",
                (rule.fingerprint,),
                expected_epoch=epoch,
            )
            return "OK"

        if cur_state == "FIRING":
            if recovered:
                if alert_id is not None:
                    self._elector.fenced_execute(
                        conn,
                        "UPDATE alerts SET status = 'resolved' WHERE alert_id = %s;",
                        (alert_id,),
                        expected_epoch=epoch,
                    )
                self._elector.fenced_execute(
                    conn,
                    "DELETE FROM alert_timers WHERE fingerprint = %s;",
                    (rule.fingerprint,),
                    expected_epoch=epoch,
                )
                return "OK"
            return "FIRING"

        return "OK"