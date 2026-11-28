import threading
import logging
import psycopg
import asyncio
import uvicorn
import signal
import json
import hmac
import grpc
import nats
import uuid 
import time
import os


from nats.js.api import RetentionPolicy, StorageType, StreamConfig
from control_plane.domain.alert_evaluator import AlertEngine
from control_plane.domain.auth import seed_admin
from control_plane.domain.lease_manager import LeaseManager
from control_plane.domain.link_history import observe_link
from control_plane.adapters.elector import LeaderElector
from control_plane.api.rest import create_rest_app
from shared import netwatch_pb2, netwatch_pb2_grpc
from shared.telemetry_auth import tls_context
from nats.js.errors import NotFoundError
from certs.client import sign_client_csr
from datetime import datetime, timezone
from urllib.parse import unquote
from concurrent import futures
from pathlib import Path

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


# Nodes in these states must not have links opened or refreshed by probe results.
INACTIVE_NODE_STATES = ("offline", "revoked")


def _node_status(cur: psycopg.Cursor, node_id: str) -> str | None:
    cur.execute("SELECT health_status FROM nodes WHERE node_id = %s;", (node_id,))
    row = cur.fetchone()
    return row[0] if row else None


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

        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                if _node_status(cur, node_id) == "revoked":
                    logger.warning("Rejected enrollment for node_id=%s: node is revoked", node_id)
                    context.abort(grpc.StatusCode.PERMISSION_DENIED, "Node is revoked")

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
        if not self.elector.is_leader:
            return netwatch_pb2.Ack(
                ok=False,
                message="Not leader; retry against active leader",
                server_timestamp_ms=int(time.time() * 1000),
                leader_epoch=self.elector.epoch,
            )
        node_id = request.node_id.strip()
        peer_ip = _extract_peer_ip(context)
        claimed_commands: list[dict[str, object]] = []

        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                if _node_status(cur, node_id) == "revoked":
                    context.abort(grpc.StatusCode.PERMISSION_DENIED, "Node is revoked")
                cur.execute(
                    """
                    INSERT INTO nodes (node_id, ip_address, data_ip, health_status, last_heartbeat)
                    VALUES (%s, %s, NULLIF(%s, ''), 'healthy', NOW())
                    ON CONFLICT (node_id) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        data_ip = COALESCE(EXCLUDED.data_ip, nodes.data_ip),
                        health_status = CASE
                            WHEN nodes.health_status = 'revoked' THEN 'revoked'
                            ELSE 'healthy'
                        END,
                        last_heartbeat = NOW();
                    """,
                    (node_id, peer_ip, request.data_ip.strip()),
                )

                # Probe targets for this node: every other live node with a known DATA_NET address.
                cur.execute(
                    """
                    SELECT node_id, data_ip FROM nodes
                    WHERE node_id <> %s
                      AND data_ip IS NOT NULL
                      AND health_status IN ('enrolled', 'healthy', 'degraded')
                    ORDER BY node_id;
                    """,
                    (node_id,),
                )
                peers = [netwatch_pb2.Peer(node_id=r[0], data_ip=r[1]) for r in cur.fetchall()]

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
            peers=peers,
        )

    def SubmitProbeResult(
        self,
        request: netwatch_pb2.ProbeResult,
        context: grpc.ServicerContext,
    ) -> netwatch_pb2.Ack:
        self._verify_client_identity(context, request.node_id)
        if not self.elector.is_leader:
            return netwatch_pb2.Ack(
                ok=False,
                message="Not leader; retry against active leader",
                server_timestamp_ms=int(time.time() * 1000),
                leader_epoch=self.elector.epoch,
            )
        src_node_id = request.node_id.strip()
        dst_node_id = request.probe_target.strip()
        if not dst_node_id or src_node_id == dst_node_id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Valid distinct probe_target is required")

        ts = (
            request.timestamp.ToDatetime(tzinfo=timezone.utc)
            if request.HasField("timestamp")
            else datetime.now(timezone.utc)
        )

        trace_uuid: str | None = None
        if request.probe_type == "trace" and request.probe_id:
            try:
                trace_uuid = str(uuid.UUID(request.probe_id.strip()))
            except ValueError:
                trace_uuid = None

        with psycopg.connect(self.db_dsn) as conn:
            with conn.cursor() as cur:
                src_status = _node_status(cur, src_node_id)
                if src_status is None:
                    context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Node is not enrolled")
                if src_status == "revoked":
                    context.abort(grpc.StatusCode.PERMISSION_DENIED, "Node is revoked")
                dst_status = _node_status(cur, dst_node_id)
                if dst_status is None:
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Unknown probe_target {dst_node_id!r}")

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

                if trace_uuid is not None:
                    measured_hops: list[dict[str, object]] | None = None
                    if request.error_message and request.error_message.startswith("["):
                        try:
                            parsed = json.loads(request.error_message)
                            if isinstance(parsed, list) and all(isinstance(h, dict) for h in parsed):
                                measured_hops = parsed
                        except json.JSONDecodeError:
                            measured_hops = None

                    if not measured_hops:
                        measured_hops = [
                            {
                                "status": "DONE",
                                "hop": 1,
                                "node_id": dst_node_id,
                                "rtt_ms": request.latency_ms,
                                "success": request.success,
                            }
                        ]
                    else:
                        measured_hops[0]["status"] = "DONE"

                    cur.execute(
                        """
                        UPDATE path_traces
                        SET hops = %s::jsonb,
                            packet_loss_pct = %s,
                            avg_latency_ms = %s,
                            captured_at = %s
                        WHERE trace_id = %s::uuid AND src_node_id = %s;
                        """,
                        (
                            json.dumps(measured_hops),
                            request.packet_loss_pct,
                            request.latency_ms,
                            ts,
                            trace_uuid,
                            src_node_id,
                        ),
                    )
                    cur.execute(
                        """
                        UPDATE node_commands
                        SET status = %s, executed_at = NOW(), result_output = %s
                        WHERE command_type = 'run_trace'
                          AND target_node_id = %s
                          AND payload->>'trace_id' = %s
                          AND status IN ('queued', 'delivered');
                        """,
                        (
                            "executed" if request.success else "failed",
                            json.dumps(measured_hops),
                            src_node_id,
                            trace_uuid,
                        ),
                    )

            # Never resurrect links touching an offline/revoked node: peers keep probing a dead
            # node, and re-opening its links would undo the LeaseManager's eviction every sweep.
            link_mutable = (
                src_status not in INACTIVE_NODE_STATES and dst_status not in INACTIVE_NODE_STATES
            )
            if link_mutable and self.elector.is_leader:
                # Versioned, bitemporal update (see control_plane/domain/link_history.py).
                observe_link(
                    conn,
                    self.elector,
                    src_node_id,
                    dst_node_id,
                    request.success,
                    probe_loss_pct=request.packet_loss_pct,
                    probe_latency_ms=request.latency_ms if request.success else None,
                )
            conn.commit()

        return netwatch_pb2.Ack(
            ok=True,
            message="Probe received",
            server_timestamp_ms=int(time.time() * 1000),
            leader_epoch=self.elector.epoch,
        )

async def _ensure_telemetry_stream(
    nats_url: str, nats_ca: str = "", retries: int = 15, delay_s: float = 1.0
) -> None:
    nc = None
    for attempt in range(1, retries + 1):
        try:
            nc = await nats.connect(
                servers=[nats_url],
                name="control-plane-bootstrap",
                connect_timeout=2.0,
                tls=tls_context(nats_ca) if nats_ca else None,
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
    asyncio.run(_ensure_telemetry_stream(nats_url, (os.environ.get("NATS_CA_PATH") or "").strip()))

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

    alert_engine = AlertEngine(db_dsn=db_dsn, elector=elector)
    alert_thread = threading.Thread(
        target=alert_engine.run_forever,
        args=(stop_event,),
        name="alert-engine",
        daemon=True,
    )
    alert_thread.start()

    admin_username = (os.environ.get("ADMIN_USERNAME") or "admin").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD") or ""
    if admin_password:
        seed_admin(db_dsn, admin_username, admin_password)
    else:
        logger.warning("ADMIN_PASSWORD is not set: no bootstrap admin was created")

    rest_app = create_rest_app(db_dsn=db_dsn, elector=elector)
    rest_config = uvicorn.Config(
        rest_app,
        host="0.0.0.0",
        port=int(os.environ.get("REST_PORT", "8000")),
        log_level="info",
    )
    rest_server = uvicorn.Server(rest_config)
    rest_thread = threading.Thread(
        target=rest_server.run,
        name="rest-api",
        daemon=True,
    )
    rest_thread.start()

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
    alert_thread.join(timeout=3.0)
    rest_server.should_exit = True


if __name__ == "__main__":
    serve()