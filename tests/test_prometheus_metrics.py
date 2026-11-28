"""GET /metrics: Prometheus text exposition (planning S3), DB faked."""
from unittest.mock import patch

from fastapi.testclient import TestClient
import psycopg

from control_plane.adapters.elector import LeaderElector
from control_plane.api.rest import create_rest_app
from control_plane.domain import prom_metrics
from tests.fakes import FakeConnection, FakeCursor


def _client(leader: bool = True) -> TestClient:
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader, elector._epoch = leader, 7
    with patch.dict("os.environ", {"JWT_SECRET": "unit-test-jwt-secret-of-at-least-32-bytes", "PEER_REST_URL": ""}):
        return TestClient(create_rest_app(db_dsn="postgresql://unused", elector=elector))


def test_metrics_endpoint_is_public_and_reports_state() -> None:
    rows = [
        [("node-1", "healthy", 1.5), ("node-2", "offline", 40.0)],
        [("node-1", "node-2", "down", 0.0, 100.0), ("node-2", "node-1", "degraded", 12.5, 3.0)],
        [("critical", 2)],
    ]
    with patch("control_plane.api.rest.psycopg.connect", return_value=FakeConnection(FakeCursor(fetchall_queue=rows))):
        r = _client().get("/metrics")  # no Authorization header
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert 'netwatch_control_plane_leader{instance_id="cp-1"} 1' in body
    assert 'netwatch_control_plane_epoch{instance_id="cp-1"} 7' in body
    assert 'netwatch_node_up{node_id="node-1"} 1' in body and 'netwatch_node_up{node_id="node-2"} 0' in body
    assert 'netwatch_node_status{node_id="node-2",status="offline"} 1' in body
    assert 'netwatch_link_up{src="node-1",dst="node-2"} 0' in body
    assert 'netwatch_link_packet_loss_percent{src="node-1",dst="node-2"} 100' in body
    assert 'netwatch_link_latency_ms{src="node-2",dst="node-1"} 12.5' in body
    assert 'netwatch_alerts_open{severity="critical"} 2' in body and 'netwatch_alerts_open{severity="info"} 0' in body


def test_metrics_survive_a_database_outage() -> None:
    with patch("control_plane.api.rest.psycopg.connect", side_effect=psycopg.OperationalError("down")):
        r = _client().get("/metrics")
    assert r.status_code == 200
    assert 'netwatch_db_up{instance_id="cp-1"} 0' in r.text and "netwatch_node_up" not in r.text
    assert 'netwatch_control_plane_leader{instance_id="cp-1"} 1' in r.text


def test_standby_exposes_only_its_leadership() -> None:
    with patch("control_plane.api.rest.psycopg.connect", side_effect=AssertionError("standby must not query")):
        r = _client(leader=False).get("/metrics")
    assert r.status_code == 200
    assert 'netwatch_control_plane_leader{instance_id="cp-1"} 0' in r.text
    assert "netwatch_db_up" not in r.text and "netwatch_node_up" not in r.text


def test_label_values_are_escaped() -> None:
    text = prom_metrics.render(instance_id="cp", is_leader=True, epoch=1, db_up=True,
                               nodes=[('ev"il\\\nx', "healthy", None)])
    assert 'netwatch_node_up{node_id="ev\\"il\\\\\\nx"} 1' in text
    assert all(line.count("\n") == 0 for line in text.splitlines())
