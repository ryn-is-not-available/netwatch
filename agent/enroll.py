import datetime
import logging
import os
from pathlib import Path
from cryptography import x509
import grpc
from agent.config import AgentConfig
from certs.client import generate_node_key_and_csr
from shared import netwatch_pb2, netwatch_pb2_grpc

logger = logging.getLogger("netwatch.agent.enroll")


def is_cert_valid(cert_path: Path, key_path: Path, min_remaining_hours: float = 1.0) -> bool:
    if not cert_path.is_file() or not key_path.is_file():
        return False
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        cutoff = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=min_remaining_hours
        )
        return cert.not_valid_after_utc > cutoff
    except Exception:
        return False


def ensure_enrolled(config: AgentConfig, force: bool = False) -> tuple[Path, Path]:
    """Ensure the agent holds a valid 24h client certificate and private key in config.cert_dir."""
    config.cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = config.cert_dir / "agent.crt"
    key_path = config.cert_dir / "agent.key"

    if not force and is_cert_valid(cert_path, key_path):
        logger.info("Existing client certificate at %s is still valid; skipping enrollment", cert_path)
        return cert_path, key_path

    key_pem, csr_pem = generate_node_key_and_csr(config.node_id)
    ca_pem = config.ca_cert_path.read_bytes()
    creds = grpc.ssl_channel_credentials(root_certificates=ca_pem)

    req = netwatch_pb2.EnrollRequest(
        node_id=config.node_id,
        enrollment_token=config.join_token,
        csr_pem=csr_pem,
    )

    last_err: Exception | None = None
    for addr in config.cp_addrs:
        try:
            with grpc.secure_channel(addr, creds) as channel:
                stub = netwatch_pb2_grpc.ControlServiceStub(channel)
                resp = stub.Enroll(req, timeout=5.0)

            tmp_key = config.cert_dir / "agent.key.tmp"
            tmp_cert = config.cert_dir / "agent.crt.tmp"
            tmp_key.write_bytes(key_pem)
            os.chmod(tmp_key, 0o600)
            tmp_cert.write_bytes(resp.cert_pem)
            os.chmod(tmp_cert, 0o644)

            os.replace(tmp_key, key_path)
            os.replace(tmp_cert, cert_path)

            cert = x509.load_pem_x509_certificate(resp.cert_pem)
            logger.info(
                "Enrolled node_id=%s via %s; saved 24h cert to %s (expires %s)",
                config.node_id,
                addr,
                cert_path,
                cert.not_valid_after_utc.isoformat(),
            )
            return cert_path, key_path
        except grpc.RpcError as exc:
            logger.warning("Enrollment attempt to %s failed (%s): %s", addr, exc.code(), exc.details())
            last_err = exc

    raise RuntimeError(f"Failed to enroll node_id={config.node_id} with any control plane") from last_err