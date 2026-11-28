"""Password hashing, login, DB-backed roles and standby write forwarding."""
import io
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from control_plane.adapters.elector import LeaderElector
from control_plane.api.rest import create_rest_app
from control_plane.domain.auth import check_credentials, hash_password, verify_password
from tests.fakes import FakeConnection, FakeCursor

OPERATOR_HASH = hash_password("operator-pass")


def test_password_hashing() -> None:
    stored = hash_password("correct horse")
    assert stored.startswith("scrypt$") and "correct horse" not in stored
    assert verify_password("correct horse", stored)
    assert not verify_password("wrong horse", stored)
    assert hash_password("correct horse") != stored  # salted
    assert not verify_password("x", "not-a-hash") and not verify_password("x", "bcrypt$1$2$3$4$5")
    assert not check_credentials(None, "anything")  # unknown user
    with pytest.raises(ValueError):
        hash_password("short")


def _connections(*rows_per_connection):
    """psycopg.connect stand-in: each call gets the next scripted fetchone queue."""
    queues = list(rows_per_connection)

    def _connect(*_args, **_kwargs):
        return FakeConnection(FakeCursor(fetchone_queue=queues.pop(0) if queues else []))

    return _connect


def _client(is_leader: bool = True, peer: str = "") -> TestClient:
    elector = LeaderElector(db_dsn="postgresql://unused", instance_id="cp-1")
    elector._is_leader, elector._epoch = is_leader, (3 if is_leader else 0)
    with patch.dict("os.environ", {"PEER_REST_URL": peer, "JWT_SECRET": "unit-test-jwt-secret-of-at-least-32-bytes"}):
        return TestClient(create_rest_app(db_dsn="postgresql://unused", elector=elector))


def _login(client: TestClient, user_row) -> dict:
    with patch("control_plane.api.rest.psycopg.connect", _connections([user_row])):
        return client.post("/auth/token", json={"username": "olivia", "password": "operator-pass"}).json()


def test_login_issues_token_with_role_from_db() -> None:
    body = _login(_client(), (OPERATOR_HASH, "operator", False))
    assert body["role"] == "operator" and body["username"] == "olivia" and body["access_token"]


@pytest.mark.parametrize("user_row", [None, (OPERATOR_HASH, "operator", True)], ids=["unknown", "disabled"])
def test_login_rejects_unknown_and_disabled_users(user_row) -> None:
    client = _client()
    with patch("control_plane.api.rest.psycopg.connect", _connections([user_row])):
        r = client.post("/auth/token", json={"username": "olivia", "password": "operator-pass"})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"


def test_login_rejects_wrong_password_and_old_role_picker_body() -> None:
    client = _client()
    with patch("control_plane.api.rest.psycopg.connect", _connections([(OPERATOR_HASH, "operator", False)])):
        assert client.post("/auth/token", json={"username": "olivia", "password": "nope"}).status_code == 401
    # The old dev endpoint let anyone pick a role; that request shape is no longer accepted.
    assert client.post("/auth/token", json={"subject": "x", "role": "admin"}).status_code == 422


def test_roles_are_rechecked_against_the_db_on_every_request() -> None:
    client = _client()
    token = _login(client, (OPERATOR_HASH, "operator", False))["access_token"]
    auth = {"Authorization": f"Bearer {token}"}

    # Demoted to viewer after the token was issued: operator-only endpoint is now refused.
    with patch("control_plane.api.rest.psycopg.connect", _connections([(OPERATOR_HASH, "viewer", False)])):
        r = client.post("/diagnose", headers=auth)
    assert r.status_code == 403 and "viewer" in r.json()["detail"]

    # Disabled after the token was issued: every request is refused.
    with patch("control_plane.api.rest.psycopg.connect", _connections([(OPERATOR_HASH, "operator", True)])):
        assert client.get("/auth/me", headers=auth).status_code == 401

    with patch("control_plane.api.rest.psycopg.connect", _connections([(OPERATOR_HASH, "operator", False)])):
        assert client.get("/auth/me", headers=auth).json() == {"username": "olivia", "role": "operator"}


class _FakeResponse(io.BytesIO):
    status = 202
    headers = {"content-type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_standby_forwards_writes_to_the_leader() -> None:
    client = _client(is_leader=False, peer="http://172.28.0.32:8000")
    captured = {}

    def _urlopen(req, timeout):
        captured.update(url=req.full_url, method=req.get_method(), headers=dict(req.header_items()), body=req.data)
        return _FakeResponse(json.dumps({"trace_id": "t-1", "status": "PENDING"}).encode())

    with patch("control_plane.api.rest.urllib.request.urlopen", _urlopen):
        r = client.post(
            "/paths/trace",
            json={"src_node_id": "node-1", "dst_node_id": "node-2"},
            headers={"Authorization": "Bearer abc"},
        )

    assert r.status_code == 202 and r.json()["trace_id"] == "t-1"
    assert captured["url"] == "http://172.28.0.32:8000/paths/trace" and captured["method"] == "POST"
    assert captured["headers"]["Authorization"] == "Bearer abc"
    assert captured["headers"]["X-netwatch-forwarded"] == "cp-1"
    assert json.loads(captured["body"]) == {"src_node_id": "node-1", "dst_node_id": "node-2"}


def test_standby_never_forwards_twice_and_serves_reads_locally() -> None:
    client = _client(is_leader=False, peer="http://172.28.0.32:8000")
    with patch("control_plane.api.rest.urllib.request.urlopen") as urlopen:
        r = client.post("/diagnose", headers={"x-netwatch-forwarded": "cp-2"})
        assert r.status_code == 503
        assert client.get("/health").json()["is_leader"] is False  # GETs are not forwarded
    urlopen.assert_not_called()
