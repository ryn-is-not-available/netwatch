from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.alert_evaluator import (
    DEFAULT_LATENCY_SLO_MS,
    AlertEngine,
)
from control_plane.domain.graph_engine import ObservedLink
from tests.fakes import FakeConnection, FakeCursor


def _elector(is_leader: bool = True, epoch: int = 4) -> LeaderElector:
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader = is_leader
    elector._epoch = epoch
    return elector


def test_build_rules_covers_loss_and_latency_per_link() -> None:
    engine = AlertEngine(db_dsn="postgresql://unused", elector=_elector(), pending_s=15.0)
    observed = [
        ObservedLink("node-1", "node-2", "degraded", latency_ms=3.0, packet_loss_pct=35.0),
        ObservedLink("node-2", "node-3", "up", latency_ms=42.0, packet_loss_pct=0.0),
        ObservedLink("node-3", "node-4", "down", latency_ms=0.0, packet_loss_pct=100.0),
    ]
    rules = {r.fingerprint: r for r in engine.build_rules(observed, {("node-1", "node-2"): 5.0})}

    # Down links are the LeaseManager's job, not an SLA breach.
    assert not any("node-3->node-4" in fp for fp in rules)

    loss = rules["link_loss:node-1->node-2"]
    assert (loss.value, loss.trigger_threshold, loss.resolve_threshold) == (35.0, 2.0, 1.0)
    assert loss.severity == "critical" and loss.affected_node_id == "node-1"
    assert loss.pending_duration_s == 15.0

    # Declared links use their expected latency; undeclared ones the default SLO.
    assert rules["link_latency:node-1->node-2"].trigger_threshold == 5.0
    undeclared = rules["link_latency:node-2->node-3"]
    assert undeclared.trigger_threshold == DEFAULT_LATENCY_SLO_MS
    assert undeclared.resolve_threshold == DEFAULT_LATENCY_SLO_MS * 0.8
    assert rules["link_loss:node-2->node-3"].severity == "warning"


def test_evaluate_once_is_noop_on_standby() -> None:
    engine = AlertEngine(db_dsn="postgresql://unused", elector=_elector(is_leader=False, epoch=0))
    connect = MagicMock()
    with patch("control_plane.domain.alert_evaluator.psycopg.connect", connect):
        assert engine.evaluate_once() == {}
    connect.assert_not_called()


def test_evaluate_once_starts_pending_for_lossy_link() -> None:
    engine = AlertEngine(db_dsn="postgresql://unused", elector=_elector())
    lossy = ObservedLink("node-1", "node-2", "degraded", latency_ms=1.0, packet_loss_pct=10.0)
    cur = FakeCursor(
        # desired links, then existing link_ timers
        fetchall_queue=[[], []],
        # loss rule: no timer row, then FOR SHARE epoch check for the PENDING insert.
        # latency rule (1 ms < 20 ms SLO): no timer row -> OK, no writes.
        fetchone_queue=[None, (1,), None],
    )
    conn = FakeConnection(cur)
    with patch("control_plane.domain.alert_evaluator.psycopg.connect", return_value=conn), \
         patch.object(engine._graph, "load_observed_from_db", return_value=[lossy]):
        states = engine.evaluate_once()

    assert states == {"link_loss:node-1->node-2": "PENDING", "link_latency:node-1->node-2": "OK"}
    assert conn.committed
    assert any("INSERT INTO alert_timers" in sql and "'PENDING'" in sql for sql, _ in cur.executed)


def test_evaluate_once_resolves_alerts_of_links_that_disappeared() -> None:
    engine = AlertEngine(db_dsn="postgresql://unused", elector=_elector())
    fired_at = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)
    cur = FakeCursor(
        fetchall_queue=[[], [("link_loss:node-1->node-2",)]],
        # stale timer is FIRING -> resolve alert (epoch check) -> delete timer (epoch check)
        fetchone_queue=[("FIRING", fired_at, "alert-1"), (1,), (1,)],
    )
    conn = FakeConnection(cur)
    with patch("control_plane.domain.alert_evaluator.psycopg.connect", return_value=conn), \
         patch.object(engine._graph, "load_observed_from_db", return_value=[]):
        states = engine.evaluate_once()

    assert states == {"link_loss:node-1->node-2": "OK"}
    assert any("SET status = 'resolved'" in sql for sql, _ in cur.executed)
    assert any("DELETE FROM alert_timers" in sql for sql, _ in cur.executed)
