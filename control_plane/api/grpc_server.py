import asyncio
from concurrent import futures
from datetime import datetime, timezone
import hmac
import json
import logging
import os
from pathlib import Path
import signal
import threading
import time
from urllib.parse import unquote

import grpc
import nats
from nats.js.api import RetentionPolicy, StorageType, StreamConfig
from nats.js.errors import NotFoundError
import psycopg

from certs.client import sign_client_csr
from control_plane.adapters.elector import LeaderElector
from control_plane.domain.lease_manager import LeaseManager
from shared import netwatch_pb2, netwatch_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.control_plane.grpc")


def _extract_peer_ip(context: grpc.ServicerContext) -> str:
    peer = unquote(context.peer() or "")
    # e.g. "ipv4:172.28.0.40:51234" or "ipv6:[::1]:51234"
    if peer.startswith("ipv4:"):
        return peer.split(":")[1]
    if peer.startswith("ipv6:["):
        return peer.split("[", 1)[1].split("]", 1)[0]
    return "0.0.0.0"


class ControlServiceServicer(netwatch_pb2_grpc.ControlServiceServicer):
    def __init__(
        self,
        join_token: str,
        ca_dir: Path,
        elector: LeaderElector,
        db_dsn: str,
    ) -> None:
        self.join_token = join_token
        self.ca_dir = ca_dir
        self.elector = elector
        self.db_dsn = db_dsn

    def _verify_client_identity(
        self,
        context: grpc.ServicerContext,
        expected_node_id: str,
    ) -> bool:
        if not expected_node_id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "NODE ID IS MANDATORY")
        resp = context.auth_context().get("x509_common_name")
        if not resp:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "CLIENT CERTIFICATE IS REQUIRED")
        if resp[0].decode("utf-8") != expected_node_id.strip():
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "PERMISSION DENIED")
        return True

    def Enroll(
        self,
        request: netwatch_pb2.EnrollRequest,
        context: grpc.ServicerContext,
    ) -> netwatch_pb2.EnrollResponse:
        node_id = request.node_id.strip()
        if not node_id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "node_id is required")

        if not hmac.compare_digest(request.enrollment_token, self.join_token):
            logger.warning("Rejected enrollment for node_id=%s: invalid token", node_id)
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid enrollment token")

        try:
            cert_pem = sign_client_csr(
                csr_pem=request.csr_pem,
                node_id=node_id,
                hours=24,
                ca_dir=self.ca_dir,
            )
        except Exception as exc:
            logger.warning("Rejected enrollment for node_id=%s: %s", node_id, exc)
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

        peer_ip = _extract_peer_ip(context)
        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO nodes (node_id, ip_address, health_status, active_certificate, last_heartbeat)
                    VALUES (%s, %s, 'enrolled', %s, NOW())
                    ON CONFLICT (node_id) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        health_status = CASE
                            WHEN nodes.health_status = 'revoked' THEN 'revoked'
                            ELSE 'enrolled'
                        END,
                        active_certificate = EXCLUDED.active_certificate,
                        last_heartbeat = NOW();
                    """,
                    (node_id, peer_ip, cert_pem.decode("utf-8")),
                )
            conn.commit()

        logger.info("Enrolled node_id=%s (%s) and issued 24h client certificate", node_id, peer_ip)
        return netwatch_pb2.EnrollResponse(cert_pem=cert_pem)

    def SendHeartbeat(
        self,
        request: netwatch_pb2.Heartbeat,
        context: grpc.ServicerContext,
    ) -> netwatch_pb2.Ack:
        self._verify_client_identity(context, request.node_id)
        node_id = request.node_id.strip()
        peer_ip = _extract_peer_ip(context)
        claimed_commands: list[dict[str, object]] = []

        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO nodes (node_id, ip_address, health_status, last_heartbeat)
                    VALUES (%s, %s, 'healthy', NOW())
                    ON CONFLICT (node_id) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        health_status = CASE
                            WHEN nodes.health_status = 'revoked' THEN 'revoked'
                            ELSE 'healthy'
                        END,
                        last_heartbeat = NOW();
                    """,
                    (node_id, peer_ip),
                )

                cur.execute(
                    """
                    WITH claimed AS (
                        SELECT command_id
                        FROM node_commands
                        WHERE target_node_id = %s
                          AND status = 'queued'
                        ORDER BY created_at ASC
                        LIMIT 10
                        FOR UPDATE SKIP LOCKED
                    )
                    UPDATE node_commands nc
                    SET status = 'delivered'
                    FROM claimed
                    WHERE nc.command_id = claimed.command_id
                    RETURNING nc.command_id::text, nc.command_type, nc.payload, nc.leader_epoch;
                    """,
                    (node_id,),
                )
                for row in cur.fetchall():
                    claimed_commands.append(
                        {
                            "command_id": row[0],
                            "command_type": row[1],
                            "payload": row[2],
                            "leader_epoch": row[3],
                        }
                    )
            conn.commit()

        ack_message = (
            json.dumps({"commands": claimed_commands})
            if claimed_commands
            else "heartbeat received"
        )
        return netwatch_pb2.Ack(
            ok=True,
            message=ack_message,
            server_timestamp_ms=int(time.time() * 1000),
            leader_epoch=self.elector.epoch,
        )

    def SubmitProbeResult(
        self,
        request: netwatch_pb2.ProbeResult,
        context: grpc.ServicerContext,
    ) -> netwatch_pb2.Ack:
        self._verify_client_identity(context, request.node_id)
        src_node_id = request.node_id.strip()
        dst_node_id = request.probe_target.strip()
        if not dst_node_id or src_node_id == dst_node_id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Valid distinct probe_target is required")

        ts = (
            request.timestamp.ToDatetime(tzinfo=timezone.utc)
            if request.HasField("timestamp")
            else datetime.now(timezone.utc)
        )
        link_status = "up" if (request.success and request.packet_loss_pct <= 2.0) else "degraded"

        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO probe_results (
                        time, src_node_id, dst_node_id, probe_type,
                        latency_ms, packet_loss_pct, jitter_ms, success
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        ts,
                        src_node_id,
                        dst_node_id,
                        request.probe_type or "icmp",
                        request.latency_ms,
                        request.packet_loss_pct,
                        request.jitter_ms,
                        request.success,
                    ),
                )

            if self.elector.is_leader:
                epoch = self.elector.epoch
                updated = self.elector.fenced_execute(
                    conn,
                    """
                    UPDATE topology_links
                    SET status = %s,
                        latency_ms = %s,
                        packet_loss_pct = %s
                    WHERE src_node_id = %s
                      AND dst_node_id = %s
                      AND upper_inf(valid_during);
                    """,
                    (link_status, request.latency_ms, request.packet_loss_pct, src_node_id, dst_node_id),
                    expected_epoch=epoch,
                )
                if updated == 0:
                    self.elector.fenced_execute(
                        conn,
                        """
                        INSERT INTO topology_links (
                            src_node_id, dst_node_id, status,
                            latency_ms, packet_loss_pct,
                            valid_during, recorded_during
                        )
                        VALUES (
                            %s, %s, %s, %s, %s,
                            tstzrange(NOW(), 'infinity', '[)'),
                            tstzrange(NOW(), 'infinity', '[)')
                        )
                        ON CONFLICT DO NOTHING;
                        """,
                        (src_node_id, dst_node_id, link_status, request.latency_ms, request.packet_loss_pct),
                        expected_epoch=epoch,
                    )
            conn.commit()

        return netwatch_pb2.Ack(
            ok=True,
            message="Probe received",
            server_timestamp_ms=int(time.time() * 1000),
            leader_epoch=self.elector.epoch,
        )


async def _ensure_telemetry_stream(nats_url: str, retries: int = 15, delay_s: float = 1.0) -> None:
    nc = None
    for attempt in range(1, retries + 1):
        try:
            nc = await nats.connect(
                servers=[nats_url],
                name="control-plane-bootstrap",
                connect_timeout=2.0,
            )
            break
        except Exception as exc:
            if attempt == retries:
                raise
            logger.warning(
                "Waiting for NATS before JetStream bootstrap (attempt %d/%d): %s",
                attempt,
                retries,
                exc,
            )
            await asyncio.sleep(delay_s)

    try:
        js = nc.jetstream()
        stream_cfg = StreamConfig(
            name="TELEMETRY",
            subjects=["telemetry.>"],
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            max_age=24 * 60 * 60,
            duplicate_window=120,
        )
        try:
            await js.stream_info("TELEMETRY")
            await js.update_stream(stream_cfg)
            logger.info("Verified JetStream stream TELEMETRY (subjects=['telemetry.>'])")
        except NotFoundError:
            await js.add_stream(stream_cfg)
            logger.info("Created JetStream stream TELEMETRY (subjects=['telemetry.>'])")
    finally:
        await nc.drain()


def _build_db_dsn() -> str:
    host = os.environ.get("DB_HOST", "172.28.0.30")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "netwatch")
    user = os.environ.get("DB_USER", "postgres")
    password = os.environ.get("DB_PASSWORD", "netwatch_dev_pass")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def serve() -> None:
    join_token = (os.environ.get("JOIN_TOKEN") or "").strip()
    if not join_token:
        raise RuntimeError("JOIN_TOKEN environment variable is required")

    nats_url = (os.environ.get("NATS_URL") or "").strip()
    if not nats_url:
        raise RuntimeError("NATS_URL environment variable is required")
    asyncio.run(_ensure_telemetry_stream(nats_url))

    instance_id = (os.environ.get("INSTANCE_ID") or "control-plane-1").strip()
    db_dsn = _build_db_dsn()

    stop_event = threading.Event()
    elector = LeaderElector(db_dsn=db_dsn, instance_id=instance_id, poll_interval_s=0.5)
    elector_thread = threading.Thread(
        target=elector.run_forever,
        args=(stop_event,),
        name="leader-elector",
        daemon=True,
    )
    elector_thread.start()

    lease_manager = LeaseManager(db_dsn=db_dsn, elector=elector)
    lease_thread = threading.Thread(
        target=lease_manager.run_forever,
        args=(stop_event,),
        name="lease-manager",
        daemon=True,
    )
    lease_thread.start()

    cert_dir = Path(os.environ.get("CERT_DIR") or "/app/certs")
    server_cert = (cert_dir / "control-plane.crt").read_bytes()
    server_key = (cert_dir / "control-plane.key").read_bytes()
    ca_cert = (cert_dir / "ca.crt").read_bytes()

    creds_enroll = grpc.ssl_server_credentials(
        [(server_key, server_cert)],
        root_certificates=ca_cert,
        require_client_auth=False,
    )
    creds_mtls = grpc.ssl_server_credentials(
        [(server_key, server_cert)],
        root_certificates=ca_cert,
        require_client_auth=True,
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    netwatch_pb2_grpc.add_ControlServiceServicer_to_server(
        ControlServiceServicer(
            join_token=join_token,
            ca_dir=cert_dir,
            elector=elector,
            db_dsn=db_dsn,
        ),
        server,
    )
    server.add_secure_port("0.0.0.0:50051", creds_mtls)
    server.add_secure_port("0.0.0.0:50052", creds_enroll)
    server.start()
    logger.info(
        "Control plane (%s) listening with mTLS on 0.0.0.0:50051 and TLS on 0.0.0.0:50052",
        instance_id,
    )

    def _shutdown(signum: int, _frame: object) -> None:
        logger.info("Received signal %s; shutting down %s...", signum, instance_id)
        stop_event.set()
        server.stop(grace=2.0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server.wait_for_termination()
    stop_event.set()
    elector_thread.join(timeout=3.0)
    lease_thread.join(timeout=3.0)


if __name__ == "__main__":
    serve()