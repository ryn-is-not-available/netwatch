from dataclasses import dataclass
import logging
import os
from pathlib import Path
from socket import gethostname
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("netwatch.agent.config")


def _mask_secret(secret: str) -> str:
    if len(secret) <= 4:
        return "****"
    return f"****{secret[-4:]}"


def _mask_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.password:
        netloc = f"{parsed.username}:****@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse(parsed._replace(netloc=netloc))
    return raw_url


@dataclass(frozen=True)
class AgentConfig:
    node_id: str
    data_ip: str
    cp_addrs: tuple[str, ...]
    join_token: str
    nats_url: str
    ca_cert_path: Path
    cert_dir: Path
    heartbeat_interval_s: float = 5.0
    collect_interval_s: float = 1.0
    buffer_capacity: int = 1000

    @classmethod
    def from_env(cls) -> "AgentConfig":
        raw_node_id = (os.environ.get("NODE_ID") or "").strip()
        node_id = raw_node_id if raw_node_id else gethostname()

        data_ip = (os.environ.get("DATA_IP") or "").strip()
        join_token = (os.environ.get("JOIN_TOKEN") or "").strip()
        nats_url = (os.environ.get("NATS_URL") or "").strip()

        missing = [
            name
            for name, val in [
                ("DATA_IP", data_ip),
                ("JOIN_TOKEN", join_token),
                ("NATS_URL", nats_url),
            ]
            if not val
        ]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        raw_cp_addrs = (os.environ.get("CP_ADDRS") or "").strip()
        if raw_cp_addrs:
            cp_addrs = tuple(addr.strip() for addr in raw_cp_addrs.split(",") if addr.strip())
        else:
            cp_1_addr = (os.environ.get("CP_1_ADDR") or "").strip()
            cp_2_addr = (os.environ.get("CP_2_ADDR") or "").strip()
            cp_addrs = tuple(addr for addr in (cp_1_addr, cp_2_addr) if addr)

        if not cp_addrs:
            raise ValueError("At least one control-plane address must be set via CP_ADDRS or CP_1_ADDR/CP_2_ADDR")

        ca_cert_raw = (os.environ.get("CA_CERT_PATH") or "/app/pki/ca.crt").strip()
        cert_dir_raw = (os.environ.get("CERT_DIR") or "/var/lib/netwatch/certs").strip()

        heartbeat_raw = os.environ.get("HEARTBEAT_INTERVAL_S")
        collect_raw = os.environ.get("COLLECT_INTERVAL_S")
        buffer_raw = os.environ.get("BUFFER_CAPACITY")

        heartbeat_interval_s = float(heartbeat_raw) if heartbeat_raw and heartbeat_raw.strip() else 5.0
        collect_interval_s = float(collect_raw) if collect_raw and collect_raw.strip() else 1.0
        buffer_capacity = int(buffer_raw) if buffer_raw and buffer_raw.strip() else 1000

        return cls(
            node_id=node_id,
            data_ip=data_ip,
            cp_addrs=cp_addrs,
            join_token=join_token,
            nats_url=nats_url,
            ca_cert_path=Path(ca_cert_raw),
            cert_dir=Path(cert_dir_raw),
            heartbeat_interval_s=heartbeat_interval_s,
            collect_interval_s=collect_interval_s,
            buffer_capacity=buffer_capacity,
        )

    def log_config(self) -> None:
        logger.info(
            "Agent configuration loaded: node_id=%s data_ip=%s cp_addrs=%s "
            "join_token=%s nats_url=%s ca_cert=%s cert_dir=%s "
            "heartbeat_s=%.1f collect_s=%.1f buffer_cap=%d",
            self.node_id,
            self.data_ip,
            list(self.cp_addrs),
            _mask_secret(self.join_token),
            _mask_url(self.nats_url),
            self.ca_cert_path,
            self.cert_dir,
            self.heartbeat_interval_s,
            self.collect_interval_s,
            self.buffer_capacity,
        )