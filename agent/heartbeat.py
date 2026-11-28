from certs.client import load_certificate_from_file , load_private_key_from_file
from shared import netwatch_pb2 , netwatch_pb2_grpc
from agent.collector import MetricsCollector
from agent.enroll import ensure_enrolled
from datetime import datetime,timezone
from agent.config import AgentConfig
from agent.peers import PeerDirectory
from typing import Callable , Any
from pathlib import Path

import threading
import logging
import time
import grpc
import json
import os


logger = logging.getLogger("netwatch.agent.heartbeat")

# Per-attempt RPC deadline. Must stay well under the control plane's 7.5s "degraded" lease
# threshold: a replica that died without closing its socket costs one full deadline.
HEARTBEAT_RPC_TIMEOUT_S = 2.0
# Retry backoff after a failed tick (e.g. no leader yet during a failover), capped at the interval.
FAILED_TICK_RETRY_S = (0.5, 1.0, 2.0, 4.0)
# Touched after every accepted heartbeat; the container healthcheck checks its age.
HEALTH_FILE = Path(os.environ.get("AGENT_HEALTH_FILE", "/tmp/netwatch-agent.health"))

class HeartBeat:
    
    def __init__(
        self,
        config : AgentConfig,
        collector : MetricsCollector,
        on_command: Callable[[dict[str, Any]], None] | None = None,
        peers: PeerDirectory | None = None,
        ) -> None:
        self._on_command = on_command
        self._peers = peers
        self._metricCollector = collector
        self._config = config
        self.current_leader_epoch = 0
        # Last control plane that accepted a heartbeat. Tried first so that, after a failover,
        # each heartbeat does not wait out the full RPC deadline on the dead replica.
        self._preferred_addr: str | None = None

    def _ordered_addrs(self) -> list[str]:
        addrs = list(self._config.cp_addrs)
        preferred = self._preferred_addr
        if preferred in addrs:
            addrs.remove(preferred)
            addrs.insert(0, preferred)
        return addrs

    def generatePulse(self) -> netwatch_pb2.Heartbeat:
        # Use the collector loop's latest sample: calling read_cpu_pct() from this thread
        # would advance the shared CPU-delta state and skew both readings.
        latest = self._metricCollector.latest()
        if latest is not None:
            cpu_pct, mem_pct = latest.cpu_pct, latest.mem_pct
        else:
            cpu_pct, mem_pct = 0.0, self._metricCollector.read_mem_info()[-1]
        return netwatch_pb2.Heartbeat(
            node_id = self._config.node_id,
            timestamp=datetime.now(timezone.utc),
            cpu_usage_pct = cpu_pct,
            memory_usage_pct = mem_pct,
            uptime_seconds = int(self._metricCollector.read_uptime_sec()),
            data_ip = self._config.data_ip,
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

            for addr in self._ordered_addrs():
                try:
                    t0_ms = int(time.time() * 1000)
                    with grpc.secure_channel(addr, creds) as channel:
                        stub = netwatch_pb2_grpc.ControlServiceStub(channel)
                        resp = stub.SendHeartbeat(pulse, timeout=HEARTBEAT_RPC_TIMEOUT_S)
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

                    self._preferred_addr = addr
                    if self._peers is not None:
                        self._peers.update({p.node_id: p.data_ip for p in resp.peers})
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
            interval_s = self._config.heartbeat_interval_s
            consecutive_failures = 0
            while not stop_event.is_set():
                tick_started = time.monotonic()
                try:
                    ack = self.heartbeatClient()
                    consecutive_failures = 0
                    try:
                        HEALTH_FILE.touch()
                    except OSError as exc:
                        logger.debug("Could not touch health file %s: %s", HEALTH_FILE, exc)
                    if self._on_command and ack.message.startswith("{"):
                        try:
                            data = json.loads(ack.message)
                            for cmd in data.get("commands", []):
                                self._on_command(cmd)
                        except Exception as exc:
                            logger.error("Failed to dispatch command from heartbeat Ack: %s", exc)
                except Exception as exc:
                    consecutive_failures += 1
                    logger.error("Heartbeat tick failed: %s", exc)

                if consecutive_failures:
                    # No control plane accepted the heartbeat (e.g. a leader election is in
                    # progress): retry soon instead of letting the lease lapse for a full interval.
                    step = FAILED_TICK_RETRY_S[min(consecutive_failures, len(FAILED_TICK_RETRY_S)) - 1]
                    delay_s = min(step, interval_s)
                else:
                    # Fixed-rate schedule: RPC latency does not stretch the heartbeat period.
                    delay_s = max(0.0, interval_s - (time.monotonic() - tick_started))
                stop_event.wait(delay_s)
            
