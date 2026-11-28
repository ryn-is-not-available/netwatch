from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

import grpc

from agent.config import AgentConfig
from agent.enroll import ensure_enrolled
from shared import netwatch_pb2, netwatch_pb2_grpc

logger = logging.getLogger("netwatch.agent.prober")

DEFAULT_PEER_IPS: dict[str, str] = {
    "node-1": "172.29.0.10",
    "node-2": "172.29.0.11",
    "node-3": "172.29.0.12",
    "node-4": "172.29.0.13",
    "node-5": "172.29.0.14",
}
IP_TO_NODE: dict[str, str] = {ip: nid for nid, ip in DEFAULT_PEER_IPS.items()}


def parse_ping_output(stdout: str) -> tuple[bool, float, float, float]:
    """Parses `ping -c N -W 2 -q` output -> (success, avg_rtt_ms, jitter_ms, packet_loss_pct)."""
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", stdout)
    packet_loss_pct = float(loss_match.group(1)) if loss_match else 100.0

    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev|/stddev)?\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)",
        stdout,
    )
    if not rtt_match or packet_loss_pct >= 100.0:
        return (False, 0.0, 0.0, 100.0)

    min_ms = float(rtt_match.group(1))
    avg_ms = float(rtt_match.group(2))
    max_ms = float(rtt_match.group(3))
    jitter_ms = round((max_ms - min_ms) / 2.0, 3)
    return (True, avg_ms, jitter_ms, packet_loss_pct)


class ActiveProber:
    """Runs bounded ICMP probes & traceroutes over DATA_NET and reports via SubmitProbeResult."""

    def __init__(
        self,
        config: AgentConfig,
        peer_ips: dict[str, str] | None = None,
        probe_interval_s: float = 5.0,
    ) -> None:
        self._config = config
        self._peer_ips = dict(peer_ips or DEFAULT_PEER_IPS)
        self._probe_interval_s = probe_interval_s

    def run_icmp_probe(
        self,
        target_ip: str,
        count: int = 3,
        timeout_s: int = 2,
    ) -> tuple[bool, float, float, float, str]:
        """4.2a: Executes bounded ICMP ping (<= 5 packets, 2s timeout)."""
        bounded_count = max(1, min(5, count))
        bounded_timeout = max(1, min(2, timeout_s))
        try:
            proc = subprocess.run(
                [
                    "ping",
                    "-c",
                    str(bounded_count),
                    "-W",
                    str(bounded_timeout),
                    "-q",
                    target_ip,
                ],
                capture_output=True,
                text=True,
                timeout=bounded_count * bounded_timeout + 2,
            )
        except subprocess.TimeoutExpired:
            return (False, 0.0, 0.0, 100.0, "TIMEOUT")
        except Exception as exc:
            return (False, 0.0, 0.0, 100.0, str(exc))

        ok, avg_ms, jitter_ms, loss_pct = parse_ping_output(proc.stdout)
        err = "" if ok else (proc.stderr.strip() or "100% packet loss")
        return (ok, avg_ms, jitter_ms, loss_pct, err)

    def run_traceroute(
        self,
        dst_node_id: str,
        target_ip: str,
        timeout_s: int = 2,
    ) -> tuple[bool, float, float, float, list[dict[str, object]]]:
        """4.2a + 4.2b: Measures hops and RTT toward `target_ip`."""
        ok, avg_ms, jitter_ms, loss_pct, err = self.run_icmp_probe(
            target_ip, count=3, timeout_s=timeout_s
        )
        hops: list[dict[str, object]] = []
        try:
            proc = subprocess.run(
                ["traceroute", "-n", "-m", "8", "-w", str(timeout_s), "-q", "1", target_ip],
                capture_output=True,
                text=True,
                timeout=8,
            )
            for line in proc.stdout.splitlines()[1:]:
                m = re.match(r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+([\d.]+)\s*ms", line)
                if m:
                    hop_num = int(m.group(1))
                    hop_ip = m.group(2)
                    hop_rtt = float(m.group(3))
                    hops.append(
                        {
                            "status": "DONE",
                            "hop": hop_num,
                            "ip": hop_ip,
                            "node_id": IP_TO_NODE.get(hop_ip, hop_ip),
                            "rtt_ms": hop_rtt,
                        }
                    )
        except Exception as exc:
            logger.warning("traceroute to %s failed: %s", target_ip, exc)

        if not hops and ok:
            hops.append(
                {
                    "status": "DONE",
                    "hop": 1,
                    "ip": target_ip,
                    "node_id": dst_node_id,
                    "rtt_ms": avg_ms,
                }
            )
        elif not hops and not ok:
            hops.append(
                {
                    "status": "TIMEOUT",
                    "hop": 1,
                    "ip": target_ip,
                    "node_id": dst_node_id,
                    "error": err or "TIMEOUT",
                }
            )

        return (ok, avg_ms, jitter_ms, loss_pct, hops)

    def submit_probe_result(
        self,
        dst_node_id: str,
        probe_type: str,
        success: bool,
        latency_ms: float,
        jitter_ms: float,
        packet_loss_pct: float,
        probe_id: str | None = None,
        error_message: str = "",
    ) -> None:
        cert_path, key_path = ensure_enrolled(self._config)
        creds = grpc.ssl_channel_credentials(
            root_certificates=Path(self._config.ca_cert_path).read_bytes(),
            private_key=key_path.read_bytes(),
            certificate_chain=cert_path.read_bytes(),
        )
        msg = netwatch_pb2.ProbeResult(
            node_id=self._config.node_id,
            probe_id=probe_id or str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            probe_type=probe_type,
            probe_target=dst_node_id,
            latency_ms=latency_ms,
            jitter_ms=jitter_ms,
            packet_loss_pct=packet_loss_pct,
            success=success,
            error_message=error_message,
        )
        last_err: Exception | None = None
        for addr in self._config.cp_addrs:
            try:
                with grpc.secure_channel(addr, creds) as channel:
                    stub = netwatch_pb2_grpc.ControlServiceStub(channel)
                    ack = stub.SubmitProbeResult(msg, timeout=5.0)
                if ack.ok:
                    return
            except grpc.RpcError as exc:
                last_err = exc
        if last_err is not None:
            raise RuntimeError(f"Failed to submit probe result: {last_err}")

    def execute_trace_command(self, payload: dict[str, object]) -> None:
        trace_id = str(payload.get("trace_id", "")).strip()
        dst_node_id = str(payload.get("dst_node_id", "")).strip()
        target_ip = self._peer_ips.get(dst_node_id, dst_node_id)
        if not trace_id or not dst_node_id:
            return

        logger.info("Executing trace_id=%s -> %s (%s)", trace_id, dst_node_id, target_ip)
        ok, avg_ms, jitter_ms, loss_pct, hops = self.run_traceroute(dst_node_id, target_ip)
        self.submit_probe_result(
            dst_node_id=dst_node_id,
            probe_type="trace",
            success=ok,
            latency_ms=avg_ms,
            jitter_ms=jitter_ms,
            packet_loss_pct=loss_pct,
            probe_id=trace_id,
            error_message=json.dumps(hops),
        )

    def probe_all_peers_once(self) -> None:
        for peer_id, peer_ip in self._peer_ips.items():
            if peer_id == self._config.node_id:
                continue
            ok, avg_ms, jitter_ms, loss_pct, err = self.run_icmp_probe(peer_ip, count=2, timeout_s=2)
            try:
                self.submit_probe_result(
                    dst_node_id=peer_id,
                    probe_type="icmp",
                    success=ok,
                    latency_ms=avg_ms,
                    jitter_ms=jitter_ms,
                    packet_loss_pct=loss_pct,
                    error_message=err,
                )
            except Exception as exc:
                logger.debug("Probe submit %s->%s failed: %s", self._config.node_id, peer_id, exc)

    def run_forever(self, stop_event: threading.Event) -> None:
        logger.info("Starting ActiveProber loop every %.1fs for %s", self._probe_interval_s, self._config.node_id)
        while not stop_event.is_set():
            try:
                self.probe_all_peers_once()
            except Exception as exc:
                logger.error("ActiveProber sweep error: %s", exc)
            stop_event.wait(self._probe_interval_s)