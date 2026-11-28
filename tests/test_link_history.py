from datetime import datetime, timezone

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.link_history import (
    CLOSE_FOR_INACTIVE_NODES_SQL,
    CLOSE_FOR_NODE_SQL,
    OPEN_SQL,
    TRANSITION_SQL,
    next_status,
    observe_link,
)
from tests.fakes import FakeConnection, FakeCursor


T0 = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)


def _elector() -> LeaderElector:
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader, elector._epoch = True, 3
    return elector


def test_next_status_uses_window_loss_with_hysteresis() -> None:
    assert next_status(None, 0.0) == "up"
    assert next_status(None, 10.0) == "degraded"
    assert next_status("up", 2.0) == "up"            # at the threshold: not degraded yet
    assert next_status("up", 2.5) == "degraded"
    assert next_status("degraded", 1.5) == "degraded"  # hysteresis band keeps it degraded
    assert next_status("degraded", 1.0) == "up"
    assert next_status("degraded", None) == "degraded"  # no samples: keep current


def test_failed_probe_never_opens_a_link() -> None:
    cur = FakeCursor(fetchone_queue=[None])
    assert observe_link(FakeConnection(cur), _elector(), "node-1", "node-2", probe_success=False,
                        probe_loss_pct=100.0) == "skipped"
    assert not any("INSERT" in sql for sql, _ in cur.executed)


def test_reopened_link_starts_from_its_own_probe_not_the_outage_window() -> None:
    # No current row (the link was evicted during an outage); epoch check passes.
    cur = FakeCursor(fetchone_queue=[None, (1,)])
    assert observe_link(FakeConnection(cur), _elector(), "node-1", "node-2", probe_success=True,
                        probe_loss_pct=0.0, probe_latency_ms=0.2) == "opened"
    sql, params = cur.executed[-1]
    assert sql == OPEN_SQL and params == ("node-1", "node-2", "up", 0.2, 0.0)
    # The outage's failed samples are never read for a new segment.
    assert not any("FROM probe_results" in sql for sql, _ in cur.executed)


def test_status_change_writes_a_new_version_not_an_update() -> None:
    cur = FakeCursor(fetchone_queue=[("link-1", "up", T0), (33.3, 0.4), (1,)])
    assert observe_link(FakeConnection(cur), _elector(), "node-1", "node-2", probe_success=True) == "transitioned"
    sql, params = cur.executed[-1]
    assert sql == TRANSITION_SQL and params == ("link-1", "degraded", 0.4, 33.3)
    # The only UPDATE ends the retired row's system time; facts are re-inserted, never edited.
    assert "SET recorded_during = tstzrange(lower(recorded_during), NOW(), '[)')" in TRANSITION_SQL
    assert "SET status" not in TRANSITION_SQL
    # The status window never reaches back before this segment started.
    window_sql, window_params = cur.executed[1]
    assert "GREATEST(NOW()" in window_sql and window_params[-1] == T0


def test_same_status_writes_nothing() -> None:
    cur = FakeCursor(fetchone_queue=[("link-1", "degraded", T0), (1.5, 0.3)])
    assert observe_link(FakeConnection(cur), _elector(), "node-1", "node-2", probe_success=True) == "unchanged"
    assert len(cur.executed) == 2  # the two reads only


def test_fenced_out_leader_writes_nothing() -> None:
    cur = FakeCursor(fetchone_queue=[("link-1", "up", T0), (50.0, 0.4), None])  # epoch check fails
    assert observe_link(FakeConnection(cur), _elector(), "node-1", "node-2", probe_success=False) == "fenced"
    assert not any(sql == TRANSITION_SQL for sql, _ in cur.executed)


def test_close_statements_retire_rows_instead_of_editing_them() -> None:
    for sql in (CLOSE_FOR_INACTIVE_NODES_SQL, CLOSE_FOR_NODE_SQL):
        assert "SET recorded_during" in sql and "SET status" not in sql
        assert "tstzrange(lower(valid_during), NOW(), '[)')" in sql
