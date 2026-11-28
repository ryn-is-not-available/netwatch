from certs.client import load_certificate_from_file , load_private_key_from_file
from shared import netwatch_pb2 , netwatch_pb2_grpc
from agent.collector import MetricsCollector
from agent.enroll import ensure_enrolled
from datetime import datetime,timezone
from agent.config import AgentConfig
from typing import Callable , Any
from pathlib import Path

import threading
import logging
import time
import grpc
import json


logger = logging.getLogger("netwatch.agent.heartbeat")

class HeartBeat:
    
    def __init__(
        self,
        config : AgentConfig,
        collector : MetricsCollector,
        on_command: Callable[[dict[str, Any]], None] | None = None,
        ) -> None:
        self._on_command = on_command
        self._metricCollector = collector
        self._config = config
        self.current_leader_epoch = 0

    def generatePulse(self) -> netwatch_pb2.Heartbeat:
        return netwatch_pb2.Heartbeat(
            node_id = self._config.node_id,
            timestamp=datetime.now(timezone.utc),
            cpu_usage_pct = self._metricCollector.read_cpu_pct(),
            memory_usage_pct = self._metricCollector.read_mem_info()[-1],
            uptime_seconds = int(self._metricCollector.read_uptime_sec())
        )

    def heartbeatClient(self) -> netwatch_pb2.Ack:
            cert_path, key_path = ensure_enrolled(self._config)

            ca_pem = Path(self._config.ca_cert_path).read_bytes()
            agent_crt_pem = cert_path.read_bytes()
            agent_key_pem = key_path.read_bytes()

            creds = grpc.ssl_channel_credentials(
                root_certificates=ca_pem,
                private_key=agent_key_pem,
                certificate_chain=agent_crt_pem,
            )

            pulse = self.generatePulse()
            last_err: Exception | None = None

            for addr in self._config.cp_addrs:
                try:
                    t0_ms = int(time.time() * 1000)
                    with grpc.secure_channel(addr, creds) as channel:
                        stub = netwatch_pb2_grpc.ControlServiceStub(channel)
                        resp = stub.SendHeartbeat(pulse, timeout=5.0)
                    rtt_ms = int(time.time() * 1000) - t0_ms

                    if not resp.ok:
                        logger.info("CP %s declined heartbeat: %s", addr, resp.message)
                        last_err = RuntimeError(f"{addr} declined heartbeat: {resp.message}")
                        continue

                    if resp.leader_epoch < self.current_leader_epoch:
                        logger.warning(
                            "Ignoring stale CP %s (epoch %d < current %d)",
                            addr,
                            resp.leader_epoch,
                            self.current_leader_epoch,
                        )
                        last_err = RuntimeError(f"Stale leader epoch from {addr}")
                        continue

                    if resp.leader_epoch > self.current_leader_epoch:
                        logger.info(
                            "Leader epoch updated: %d -> %d (via %s)",
                            self.current_leader_epoch,
                            resp.leader_epoch,
                            addr,
                        )
                        self.current_leader_epoch = resp.leader_epoch

                    estimated_local_ms = t0_ms + (rtt_ms // 2)
                    drift_ms = resp.server_timestamp_ms - estimated_local_ms
                    if abs(drift_ms) > 5000:
                        logger.warning("Clock drift with %s is %+d ms", addr, drift_ms)

                    return resp

                except grpc.RpcError as exc:
                    logger.warning("Heartbeat to %s failed (%s): %s", addr, exc.code().name, exc.details())
                    if exc.code() in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                        ensure_enrolled(self._config, force=True)
                    last_err = exc

            raise RuntimeError(f"All control planes unreachable for heartbeat: {last_err}")

    def runForever(self, stop_event: threading.Event) -> None:
            logger.info(
                "Starting heartbeat loop every %.1fs for node_id=%s",
                self._config.heartbeat_interval_s,
                self._config.node_id,
            )
            while not stop_event.is_set():
                try:
                    ack = self.heartbeatClient()
                    if self._on_command and ack.message.startswith("{"):
                        try:
                            data = json.loads(ack.message)
                            for cmd in data.get("commands", []):
                                self._on_command(cmd)
                        except Exception as exc:
                            logger.error("Failed to dispatch command from heartbeat Ack: %s", exc)
                except Exception as exc:
                    logger.error("Heartbeat tick failed: %s", exc)
                stop_event.wait(self._config.heartbeat_interval_s)
            
