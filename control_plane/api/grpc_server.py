import asyncio
import hmac
import logging
import os
import time
import grpc
import nats
from nats.js.api import RetentionPolicy, StreamConfig , StorageType
from shared import netwatch_pb2, netwatch_pb2_grpc
from nats.js.errors import NotFoundError
from certs.client import sign_client_csr
from concurrent import futures
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.control_plane.grpc")


class ControlServiceServicer(netwatch_pb2_grpc.ControlServiceServicer):
    def __init__(self, join_token: str, ca_dir: Path) -> None:
        self.join_token = join_token
        self.ca_dir = ca_dir

    def _verify_client_identity(
        self,
        context: grpc.ServicerContext,
        expected_node_id: str):
        if not expected_node_id:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "NODE ID IS MANDATORY"
            )
        resp = context.auth_context().get("x509_common_name")
        if not resp:
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "CLIETN CERTIFICATION IS REQUIRED")
        if resp[0].decode("utf-8") != expected_node_id.strip() :
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "PERMESSION DENIED"
            )
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

        logger.info("Enrolled node_id=%s and issued 24h client certificate", node_id)
        return netwatch_pb2.EnrollResponse(cert_pem=cert_pem)

    def SendHeartbeat(
        self,
        request: netwatch_pb2.Heartbeat,
        context: grpc.ServicerContext,
    ) -> netwatch_pb2.Ack:
        self._verify_client_identity(context,request.node_id)
        return netwatch_pb2.Ack(
            ok=True,
            message="heartbeat received",
            server_timestamp_ms=int(time.time() * 1000),
            leader_epoch=1,
        )

    def SubmitProbeResult(
            self,
            request : netwatch_pb2.ProbeResult,
            context : grpc.ServicerContext
            ) -> netwatch_pb2.Ack:
            self._verify_client_identity(context,request.node_id)
            return netwatch_pb2.Ack(
                ok=True,
                message="Probe received",
                server_timestamp_ms=int(time.time()*1000),
                leader_epoch=1,
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
            max_age=24 * 60 * 60,  # 24h retention in seconds
            duplicate_window=120,  # 2m window matching Nats-Msg-Id header
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

def serve() -> None:
    join_token = (os.environ.get("JOIN_TOKEN") or "").strip()
    if not join_token:
        raise RuntimeError("JOIN_TOKEN environment variable is required")

    cert_dir = Path(os.environ.get("CERT_DIR") or "/app/certs")
    server_cert = (cert_dir / "control-plane.crt").read_bytes()
    server_key = (cert_dir / "control-plane.key").read_bytes()
    ca_cert = (cert_dir / "ca.crt").read_bytes()

    # require_client_auth=False allows un-enrolled nodes to connect over TLS using JOIN_TOKEN;
    # RPCs like SendHeartbeat will verify peer client certificates at the application/interceptor layer.
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
        ControlServiceServicer(join_token=join_token, ca_dir=cert_dir),
        server,
    )
    server.add_secure_port("0.0.0.0:50051", creds_mtls)
    server.add_secure_port("0.0.0.0:50052", creds_enroll)

    nats_url = (os.environ.get("NATS_URL") or "").strip()
    if not nats_url :
        raise RuntimeError("NATS_URL environment variable is required")
    asyncio.run(_ensure_telemetry_stream(nats_url))
    server.start()
    logger.info("Control plane gRPC server listening with mTLS on 0.0.0.0:50051 and TLS on 0.0.0.0:50052")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()