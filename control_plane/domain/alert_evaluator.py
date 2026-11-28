from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import threading
from typing import Any

import psycopg

from control_plane.adapters.elector import FencingError, LeaderElector
from control_plane.domain.graph_engine import ObservedLink, TopologyGraphEngine

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


# --- Link SLA rules driven by the AlertEvaluator ---

LINK_RULE_PREFIX = "link_"
LOSS_TRIGGER_PCT = 2.0      # same threshold as the graph engine's lossy_link drift rule
LOSS_RESOLVE_PCT = 1.0
LOSS_CRITICAL_PCT = 20.0
DEFAULT_LATENCY_SLO_MS = 20.0  # used for links that are observed but not declared
LATENCY_RESOLVE_RATIO = 0.8


class AlertEngine:
    """Leader-only loop that turns observed link quality into PENDING/FIRING alerts.

    Every pass loads the open links with their trailing-window average loss and latency,
    builds one loss rule and one latency rule per link, and feeds them to the
    AlertEvaluator. Timers for links that no longer exist are evaluated with a zero value
    so their alerts resolve instead of firing forever.
    """

    def __init__(
        self,
        db_dsn: str,
        elector: LeaderElector,
        graph_engine: TopologyGraphEngine | None = None,
        interval_s: float = 5.0,
        window_s: int = 30,
        pending_s: float = 15.0,
    ) -> None:
        self._db_dsn = db_dsn
        self._elector = elector
        self._graph = graph_engine or TopologyGraphEngine()
        self._evaluator = AlertEvaluator(elector)
        self.interval_s = interval_s
        self.window_s = window_s
        self.pending_s = pending_s

    def build_rules(
        self,
        observed: list[ObservedLink],
        expected_latency_ms: dict[tuple[str, str], float],
    ) -> list[AlertRuleEval]:
        rules: list[AlertRuleEval] = []
        for link in observed:
            if link.status == "down":
                continue
            edge = f"{link.src_node_id}->{link.dst_node_id}"
            loss = link.packet_loss_pct
            rules.append(
                AlertRuleEval(
                    fingerprint=f"{LINK_RULE_PREFIX}loss:{edge}",
                    severity="critical" if loss >= LOSS_CRITICAL_PCT else "warning",
                    message=(
                        f"Packet loss {loss:.1f}% on {edge} "
                        f"(> {LOSS_TRIGGER_PCT:g}% for {self.pending_s:g}s)"
                    ),
                    value=loss,
                    trigger_threshold=LOSS_TRIGGER_PCT,
                    resolve_threshold=LOSS_RESOLVE_PCT,
                    pending_duration_s=self.pending_s,
                    affected_node_id=link.src_node_id,
                )
            )
            slo = expected_latency_ms.get((link.src_node_id, link.dst_node_id), DEFAULT_LATENCY_SLO_MS)
            rules.append(
                AlertRuleEval(
                    fingerprint=f"{LINK_RULE_PREFIX}latency:{edge}",
                    severity="warning",
                    message=(
                        f"Latency {link.latency_ms:.1f} ms on {edge} "
                        f"(> {slo:g} ms SLO for {self.pending_s:g}s)"
                    ),
                    value=link.latency_ms,
                    trigger_threshold=slo,
                    resolve_threshold=slo * LATENCY_RESOLVE_RATIO,
                    pending_duration_s=self.pending_s,
                    affected_node_id=link.src_node_id,
                )
            )
        return rules

    def evaluate_once(self) -> dict[str, str]:
        """Runs one pass and returns {fingerprint: state} for every rule evaluated."""
        if not self._elector.is_leader:
            return {}

        states: dict[str, str] = {}
        with psycopg.connect(self._db_dsn) as conn:
            observed = self._graph.load_observed_from_db(conn, window_seconds=self.window_s)
            with conn.cursor() as cur:
                cur.execute("SELECT src_node_id, dst_node_id, expected_latency_ms FROM desired_topology_links;")
                expected = {(r[0], r[1]): float(r[2]) for r in cur.fetchall()}
                cur.execute(
                    "SELECT fingerprint FROM alert_timers WHERE fingerprint LIKE %s;",
                    (f"{LINK_RULE_PREFIX}%",),
                )
                existing = {r[0] for r in cur.fetchall()}

            rules = self.build_rules(observed, expected)
            current = {r.fingerprint for r in rules}
            for stale in sorted(existing - current):
                # The link closed (node offline/revoked): clear its timer and resolve its alert.
                rules.append(
                    AlertRuleEval(
                        fingerprint=stale,
                        severity="info",
                        message="link no longer observed",
                        value=0.0,
                        trigger_threshold=1.0,
                        resolve_threshold=0.0,
                    )
                )

            for rule in rules:
                states[rule.fingerprint] = self._evaluator.evaluate(conn, rule)
            conn.commit()
        return states

    def run_forever(self, stop_event: threading.Event) -> None:
        logger.info(
            "Starting AlertEngine loop every %.1fs (window=%ds, pending=%.0fs)",
            self.interval_s,
            self.window_s,
            self.pending_s,
        )
        while not stop_event.is_set():
            try:
                states = self.evaluate_once()
                firing = sorted(fp for fp, s in states.items() if s == "FIRING")
                if firing:
                    logger.info("AlertEngine: %d rule(s) firing: %s", len(firing), ", ".join(firing))
            except FencingError as exc:
                logger.warning("AlertEngine pass aborted (lost leadership): %s", exc)
            except Exception as exc:
                logger.error("AlertEngine pass failed: %s", exc)
            stop_event.wait(self.interval_s)