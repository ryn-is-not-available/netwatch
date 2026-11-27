from datetime import datetime, timedelta, timezone
import math
from unittest.mock import MagicMock, patch

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.alert_evaluator import AlertEvaluator, AlertRuleEval
from control_plane.domain.graph_engine import (
    DeclaredLink,
    ObservedLink,
    TopologyGraphEngine,
)
from control_plane.domain.lease_manager import LeaseManager


class FakeCursor:
    def __init__(self, fetchone_queue=None, fetchall_queue=None, rowcount=1) -> None:
        self.fetchone_queue = list(fetchone_queue or [])
        self.fetchall_queue = list(fetchall_queue or [])
        self.rowcount = rowcount
        self.executed: list[tuple[str, tuple]] = []

    def execute(self, sql: str, params=()) -> None:
        self.executed.append((sql, tuple(params) if params is not None else ()))

    def fetchone(self):
        return self.fetchone_queue.pop(0) if self.fetchone_queue else None

    def fetchall(self):
        return self.fetchall_queue.pop(0) if self.fetchall_queue else []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _make_leader_elector(is_leader: bool = True, epoch: int = 3) -> LeaderElector:
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader = is_leader
    elector._epoch = epoch
    return elector


# --- 3.6a: LeaseManager tests ---


def test_lease_manager_skips_when_standby() -> None:
    elector = _make_leader_elector(is_leader=False, epoch=0)
    lm = LeaseManager(db_dsn="postgresql://unused", elector=elector)
    assert lm.evaluate_once() == (0, 0, 0)


def test_lease_manager_transitions_and_closes_links() -> None:
    elector = _make_leader_elector(is_leader=True, epoch=4)
    # 4 fenced calls: degraded, offline, close_links, insert_alert -> 4 FOR SHARE checks
    cur = FakeCursor(fetchone_queue=[(1,), (1,), (1,), (1,)], rowcount=2)
    conn = FakeConnection(cur)

    lm = LeaseManager(db_dsn="postgresql://unused", elector=elector)
    with patch("control_plane.domain.lease_manager.psycopg.connect", return_value=conn):
        degraded, offline, closed = lm.evaluate_once()

    assert (degraded, offline, closed) == (2, 2, 2)
    assert conn.committed is True
    assert any("health_status = 'degraded'" in sql for sql, _ in cur.executed)
    assert any("health_status = 'offline'" in sql for sql, _ in cur.executed)
    assert any("UPDATE topology_links" in sql for sql, _ in cur.executed)


# --- 3.6b: TopologyGraphEngine tests ---


def test_dijkstra_shortest_path_prefers_lower_admin_cost() -> None:
    engine = TopologyGraphEngine()
    links = [
        DeclaredLink("node-1", "node-3", admin_cost=10.0),
        DeclaredLink("node-1", "node-2", admin_cost=2.0),
        DeclaredLink("node-2", "node-3", admin_cost=3.0),
        DeclaredLink("node-1", "node-4", admin_cost=-5.0),  # ignored
    ]
    cost, path = engine.shortest_path(links, "node-1", "node-3")
    assert cost == 5.0
    assert path == ["node-1", "node-2", "node-3"]
    assert engine.shortest_path(links, "node-1", "node-1") == (0.0, ["node-1"])
    assert engine.shortest_path(links, "node-1", "node-5") == (math.inf, [])


def test_compute_drift_detects_missing_extra_and_lossy_links() -> None:
    engine = TopologyGraphEngine(loss_threshold_pct=2.0)
    declared = [
        DeclaredLink("node-1", "node-2", admin_cost=1.0),
        DeclaredLink("node-2", "node-3", admin_cost=1.0),
    ]
    observed = [
        ObservedLink("node-1", "node-2", status="up", latency_ms=2.5, packet_loss_pct=4.5),
        ObservedLink("node-1", "node-4", status="up", latency_ms=1.2, packet_loss_pct=0.0),
        ObservedLink("node-3", "node-5", status="down", latency_ms=0.0, packet_loss_pct=100.0),
    ]

    drifts = engine.compute_drift(declared, observed)
    by_type = {(d.drift_type, d.src_node_id, d.dst_node_id): d for d in drifts}

    assert ("missing_declared", "node-2", "node-3") in by_type
    assert ("extra_observed", "node-1", "node-4") in by_type
    assert ("lossy_link", "node-1", "node-2") in by_type
    assert ("extra_observed", "node-3", "node-5") not in by_type


def test_load_observed_from_db() -> None:
    engine = TopologyGraphEngine()
    cur = FakeCursor(
        fetchall_queue=[[("node-1", "node-2", "up", 1.5, 0.25)]]
    )
    conn = FakeConnection(cur)
    rows = engine.load_observed_from_db(conn, window_seconds=30)
    assert rows == [ObservedLink("node-1", "node-2", "up", 1.5, 0.25)]


# --- 3.5a & 3.5b: AlertEvaluator tests ---


def test_alert_evaluator_pending_to_firing_and_hysteresis_recovery() -> None:
    elector = _make_leader_elector(is_leader=True, epoch=5)
    evaluator = AlertEvaluator(elector)
    t0 = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Initial breach -> PENDING
    cur1 = FakeCursor(fetchone_queue=[None, (1,)])
    conn1 = FakeConnection(cur1)
    rule_breach = AlertRuleEval(
        fingerprint="loss:node-1->node-2",
        severity="warning",
        message="High packet loss",
        value=3.5,
        trigger_threshold=2.0,
        resolve_threshold=1.0,
        pending_duration_s=30.0,
        affected_node_id="node-1",
    )
    assert evaluator.evaluate(conn1, rule_breach, now=t0) == "PENDING"

    # 2. After 35s (surviving restart via persisted pending_since) -> FIRING
    cur2 = FakeCursor(
        fetchone_queue=[
            ("PENDING", t0, None),
            (1,),
            ("uuid-alert-123",),
            (1,),
        ]
    )
    conn2 = FakeConnection(cur2)
    assert evaluator.evaluate(conn2, rule_breach, now=t0 + timedelta(seconds=35)) == "FIRING"

    # 3. Hysteresis band (value = 1.5 between resolve=1.0 and trigger=2.0) -> stays FIRING
    rule_hysteresis = AlertRuleEval(
        fingerprint="loss:node-1->node-2",
        severity="warning",
        message="High packet loss",
        value=1.5,
        trigger_threshold=2.0,
        resolve_threshold=1.0,
        pending_duration_s=30.0,
    )
    cur3 = FakeCursor(fetchone_queue=[("FIRING", t0, "uuid-alert-123")])
    conn3 = FakeConnection(cur3)
    assert evaluator.evaluate(conn3, rule_hysteresis, now=t0 + timedelta(seconds=45)) == "FIRING"

    # 4. Full recovery (value = 0.5 <= resolve=1.0) -> OK (resolved)
    rule_recovered = AlertRuleEval(
        fingerprint="loss:node-1->node-2",
        severity="warning",
        message="High packet loss",
        value=0.5,
        trigger_threshold=2.0,
        resolve_threshold=1.0,
        pending_duration_s=30.0,
    )
    cur4 = FakeCursor(fetchone_queue=[("FIRING", t0, "uuid-alert-123"), (1,), (1,)])
    conn4 = FakeConnection(cur4)
    assert evaluator.evaluate(conn4, rule_recovered, now=t0 + timedelta(seconds=55)) == "OK"
    assert any("SET status = 'resolved'" in sql for sql, _ in cur4.executed)