"""Node metrics series and actionable recommendations (REST, DB faked)."""
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from control_plane.adapters.elector import LeaderElector
from control_plane.api.rest import create_rest_app
from control_plane.domain.auth import hash_password
from tests.fakes import FakeConnection, FakeCursor

ADMIN = (hash_password("admin-password"), "admin", False)
T = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)


def _connections(*scripts):
    """Each psycopg.connect() gets the next (fetchone_queue, fetchall_queue); cursors are recorded."""
    queue, cursors = list(scripts), []

    def _connect(*_a, **_k):
        one, many = queue.pop(0) if queue else ([], [])
        cur = FakeCursor(fetchone_queue=one, fetchall_queue=many)
        cursors.append(cur)
        return FakeConnection(cur)

    return _connect, cursors


def _client_and_token():
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader, elector._epoch = True, 4
    with patch.dict("os.environ", {"JWT_SECRET": "unit-test-jwt-secret-of-at-least-32-bytes", "PEER_REST_URL": ""}):
        client = TestClient(create_rest_app(db_dsn="postgresql://unused", elector=elector))
    connect, _ = _connections(([ADMIN], []))
    with patch("control_plane.api.rest.psycopg.connect", connect):
        token = client.post("/auth/token", json={"username": "admin", "password": "admin-password"}).json()["access_token"]
    return client, {"Authorization": f"Bearer {token}"}


def test_node_metrics_series_and_unknown_node() -> None:
    client, auth = _client_and_token()
    rows = [(T, 2.5, 10.0, None, None), (T.replace(second=7), 3.0, 10.1, 150.0, 140.0)]
    connect, cursors = _connections(([ADMIN], []), ([], [[("node-1", "healthy")], rows]))
    with patch("control_plane.api.rest.psycopg.connect", connect):
        r = client.get("/nodes/node-1/metrics?minutes=15", headers=auth)
    body = r.json()
    assert r.status_code == 200 and body["bucket_seconds"] == 7
    assert body["points"][0] == {"t": T.isoformat(), "cpu_pct": 2.5, "mem_pct": 10.0, "rx_bps": None, "tx_bps": None}
    assert body["points"][1]["rx_bps"] == 150.0
    sql = cursors[1].executed[-1][0]
    assert "time_bucket" in sql and "LAG(rx)" in sql  # throughput from counter deltas

    connect, _ = _connections(([ADMIN], []), ([], [[]]), ([ADMIN], []))
    with patch("control_plane.api.rest.psycopg.connect", connect):
        assert client.get("/nodes/ghost/metrics", headers=auth).status_code == 404
        # The range is capped at 24h.
        assert client.get("/nodes/node-1/metrics?minutes=5000", headers=auth).status_code == 422


def test_applying_declare_link_recommendation_declares_it() -> None:
    client, auth = _client_and_token()
    action = {"type": "declare_link", "src": "node-1", "dst": "node-2"}
    connect, cursors = _connections(
        ([ADMIN], []),
        ([(1,), ("pending", action), ("11111111-1111-1111-1111-111111111111", "applied")],
         [[("node-1", "healthy"), ("node-2", "healthy")]]),
    )
    with patch("control_plane.api.rest.psycopg.connect", connect):
        r = client.patch("/recommendations/11111111-1111-1111-1111-111111111111", json={"status": "applied"}, headers=auth)
    assert r.status_code == 200 and r.json()["result"] == {"declared_link": "node-1->node-2"}
    executed = [sql for sql, _ in cursors[1].executed]
    assert any("INSERT INTO desired_topology_links" in sql for sql in executed)
    assert any("PATCH_RECOMMENDATION" in str(params) for _, params in cursors[1].executed)


def test_recommendation_cannot_be_applied_twice_and_dismiss_runs_nothing() -> None:
    client, auth = _client_and_token()
    rid = "22222222-2222-2222-2222-222222222222"
    connect, _ = _connections(([ADMIN], []), ([(1,), ("applied", {"type": "run_trace"})], []))
    with patch("control_plane.api.rest.psycopg.connect", connect):
        assert client.patch(f"/recommendations/{rid}", json={"status": "applied"}, headers=auth).status_code == 409

    connect, cursors = _connections(
        ([ADMIN], []), ([(1,), ("pending", {"type": "run_trace", "src": "node-1", "dst": "node-2"}), (rid, "dismissed")], [])
    )
    with patch("control_plane.api.rest.psycopg.connect", connect):
        r = client.patch(f"/recommendations/{rid}", json={"status": "dismissed"}, headers=auth)
    assert r.status_code == 200 and r.json()["result"] == {}
    assert not any("node_commands" in sql for sql, _ in cursors[1].executed)
