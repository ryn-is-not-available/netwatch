"""Authenticates telemetry messages before they are written to TimescaleDB.

A message is accepted only if:
  1. it was published on `telemetry.<node_id>` and its payload claims that same node_id,
  2. the node is enrolled and not revoked, and
  3. its Netwatch-Sig header verifies against the node's enrolled certificate
     (the current one, or the one it replaced, so a 24h key rotation does not drop
     messages that were already in flight).
"""
from dataclasses import dataclass, field
import json
import logging
import time
from typing import Any, Callable

import psycopg

from shared.telemetry_auth import public_key_from_cert_pem, verify_payload

logger = logging.getLogger("netwatch.worker.verifier")


@dataclass
class _NodeEntry:
    status: str
    certs: list[tuple[str, Any]] = field(default_factory=list)  # (pem, public key), newest first
    loaded_at: float = 0.0


class TelemetryVerifier:
    def __init__(self, cache_ttl_s: float = 30.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = cache_ttl_s
        self._clock = clock
        self._nodes: dict[str, _NodeEntry] = {}

    def _load(self, conn: psycopg.Connection[Any], node_id: str) -> _NodeEntry | None:
        with conn.cursor() as cur:
            cur.execute("SELECT health_status, active_certificate FROM nodes WHERE node_id = %s;", (node_id,))
            row = cur.fetchone()
        if row is None:
            self._nodes.pop(node_id, None)
            return None

        status, cert_pem = row[0], row[1]
        previous = self._nodes.get(node_id)
        certs: list[tuple[str, Any]] = []
        if cert_pem:
            try:
                certs.append((cert_pem, public_key_from_cert_pem(cert_pem)))
            except (ValueError, TypeError) as exc:
                logger.warning("Stored certificate for %s is unusable: %s", node_id, exc)
        if previous is not None:
            # Keep the certificate this one replaced: messages signed just before a rotation.
            certs += [c for c in previous.certs if not certs or c[0] != certs[0][0]][:1]
        entry = _NodeEntry(status=status, certs=certs, loaded_at=self._clock())
        self._nodes[node_id] = entry
        return entry

    def _entry(self, conn: psycopg.Connection[Any], node_id: str) -> tuple[_NodeEntry | None, bool]:
        entry = self._nodes.get(node_id)
        if entry is not None and self._clock() - entry.loaded_at < self._ttl:
            return entry, False
        return self._load(conn, node_id), True

    def check(self, conn: psycopg.Connection[Any], subject: str, payload: bytes, signature: str | None) -> str | None:
        """Returns None if the message is authentic, else the reason it is rejected."""
        prefix, _, subject_node = subject.partition(".")
        if prefix != "telemetry" or not subject_node:
            return f"unexpected subject {subject!r}"
        try:
            claimed = json.loads(payload.decode()).get("node_id")
        except (ValueError, AttributeError):
            return "payload is not a JSON object"
        if claimed != subject_node:
            return f"payload node_id {claimed!r} does not match subject node {subject_node!r}"
        if not signature:
            return "missing signature"

        entry, fresh = self._entry(conn, subject_node)
        if entry is None:
            return f"unknown node {subject_node!r}"
        if entry.status == "revoked":
            return f"node {subject_node!r} is revoked"
        if any(verify_payload(key, payload, signature) for _, key in entry.certs):
            return None
        if not fresh:
            # The node may have re-enrolled since we cached its certificate.
            entry = self._load(conn, subject_node)
            if entry is not None and entry.status != "revoked" and any(
                verify_payload(key, payload, signature) for _, key in entry.certs
            ):
                return None
        return "invalid signature"
