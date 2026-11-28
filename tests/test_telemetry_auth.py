"""Per-message telemetry signatures and the worker's verifier."""
import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shared.telemetry_auth import load_private_key, public_key_from_cert_pem, sign_payload, verify_payload
from tests.fakes import FakeConnection, FakeCursor
from worker.verifier import TelemetryVerifier


def _node_identity(node_id: str) -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=24))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


KEY_1, CERT_1 = _node_identity("node-1")
KEY_1_ROTATED, CERT_1_ROTATED = _node_identity("node-1")
KEY_2, CERT_2 = _node_identity("node-2")


def _payload(node_id: str, seq: int = 1) -> bytes:
    return json.dumps({"node_id": node_id, "seq_id": seq}).encode()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_sign_verify_roundtrip_and_tamper_detection() -> None:
    pem = KEY_1.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    key = load_private_key(pem)
    sig = sign_payload(key, b"payload")
    public = public_key_from_cert_pem(CERT_1)
    assert verify_payload(public, b"payload", sig)
    assert not verify_payload(public, b"payload!", sig)
    assert not verify_payload(public, b"payload", "not-base64!!")


def test_verifier_accepts_authentic_messages_and_caches_lookups() -> None:
    cur = FakeCursor(fetchone_queue=[("healthy", CERT_1)])
    conn = FakeConnection(cur)
    v = TelemetryVerifier(clock=Clock())
    for seq in (1, 2, 3):
        body = _payload("node-1", seq)
        assert v.check(conn, "telemetry.node-1", body, sign_payload(KEY_1, body)) is None
    assert len(cur.executed) == 1  # one DB lookup, then cached


def test_verifier_rejections() -> None:
    v = TelemetryVerifier(clock=Clock())
    body = _payload("node-1")
    sig = sign_payload(KEY_1, body)

    # node-2 publishing on its own subject but claiming node-1 in the payload
    assert "does not match" in v.check(FakeConnection(FakeCursor()), "telemetry.node-2", body, sig)
    assert v.check(FakeConnection(FakeCursor()), "telemetry.node-1", body, None) == "missing signature"
    assert "unknown node" in v.check(FakeConnection(FakeCursor(fetchone_queue=[None])), "telemetry.node-1", body, sig)
    assert "revoked" in TelemetryVerifier().check(
        FakeConnection(FakeCursor(fetchone_queue=[("revoked", CERT_1)])), "telemetry.node-1", body, sig
    )
    # node-2's key cannot sign for node-1, even with a matching subject and payload
    forged = sign_payload(KEY_2, body)
    assert TelemetryVerifier().check(
        FakeConnection(FakeCursor(fetchone_queue=[("healthy", CERT_1)])), "telemetry.node-1", body, forged
    ) == "invalid signature"


def test_verifier_follows_key_rotation_and_keeps_previous_cert() -> None:
    clock = Clock()
    v = TelemetryVerifier(clock=clock)
    old_body = _payload("node-1", 1)
    cur = FakeCursor(fetchone_queue=[("healthy", CERT_1), ("healthy", CERT_1_ROTATED)])
    conn = FakeConnection(cur)
    assert v.check(conn, "telemetry.node-1", old_body, sign_payload(KEY_1, old_body)) is None

    # node-1 re-enrolled: new key. Cached cert misses, so the verifier reloads once.
    clock.now += 5
    new_body = _payload("node-1", 2)
    assert v.check(conn, "telemetry.node-1", new_body, sign_payload(KEY_1_ROTATED, new_body)) is None

    # A message signed with the old key just before rotation is still accepted.
    late_body = _payload("node-1", 3)
    assert v.check(conn, "telemetry.node-1", late_body, sign_payload(KEY_1, late_body)) is None
    assert len(cur.executed) == 2
