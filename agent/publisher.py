import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
import threading
from typing import Any

import nats
from nats.errors import Error as NatsError
from nats.js.api import PubAck

from agent.collector import MetricsCollector, SystemMetrics
from agent.config import AgentConfig
from agent.ring_buffer import BufferTick, RingBuffer

logger = logging.getLogger("netwatch.agent.publisher")


class TelemetryPublisher:
    def __init__(
        self,
        config: AgentConfig,
        collector: MetricsCollector,
        ring_buffer: RingBuffer,
        batch_size: int = 50,
    ) -> None:
        self._config = config
        self._collector = collector
        self._ring_buffer = ring_buffer
        self._batch_size = batch_size
        self._subject = f"telemetry.{config.node_id}"

    def _serialize_metrics(self, metrics: SystemMetrics) -> dict[str, Any]:
        data = asdict(metrics)
        data["node_id"] = self._config.node_id
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        return data

    def run_collector_forever(self, stop_event: threading.Event) -> None:
        """Samples /proc every collect_interval_s and pushes ticks into RingBuffer."""
        logger.info(
            "Starting telemetry collector loop every %.1fs (buffer capacity=%d)",
            self._config.collect_interval_s,
            self._ring_buffer.capacity,
        )
        while not stop_event.is_set():
            try:
                metrics = self._collector.collect()
                payload = self._serialize_metrics(metrics)
                seq_id = self._ring_buffer.push(payload=payload)
                logger.debug(
                    "Processed tick seq_id=%s | buffer_len=%d | evicted_count=%d",
                    seq_id,
                    len(self._ring_buffer),
                    self._ring_buffer.evicted_count,
                )
            except Exception as exc:
                logger.error("Telemetry collection tick failed: %s", exc)
            stop_event.wait(self._config.collect_interval_s)

    def _build_wire_bytes(self, tick: BufferTick) -> tuple[bytes, str]:
        """Injects (boot_id, seq_id) into the payload and returns (utf8_bytes, msg_id)."""
        envelope = {
            **tick.payload,
            "boot_id": tick.boot_id,
            "seq_id": tick.seq_id
        }
        msg_id = f"{self._config.node_id}:{tick.boot_id}:{tick.seq_id}"
        return json.dumps(envelope).encode(), msg_id
    
    async def _publish_loop(self, stop_event: threading.Event) -> None:
        """Connects to NATS JetStream and drains RingBuffer only upon PubAck."""
        nc = None
        while not stop_event.is_set():
            try:
                if nc is None or not nc.is_connected:
                    nc = await nats.connect(
                        servers=[self._config.nats_url],
                        name=f"agent-{self._config.node_id}",
                        max_reconnect_attempts=-1,
                        reconnect_time_wait=1.0,
                    )
                    js = nc.jetstream()
                    logger.info("Connected to NATS JetStream; publishing to %s", self._subject)

                batch = self._ring_buffer.peek_batch(max_items=self._batch_size)
                if not batch:
                    await asyncio.sleep(0.2)
                    continue

                for tick in batch:
                    raw_bytes, msg_id = self._build_wire_bytes(tick)
                    ack: PubAck = await js.publish(
                        self._subject,
                        raw_bytes,
                        headers={"Nats-Msg-Id": msg_id},
                        timeout=2.0,
                    )
                    logger.debug(
                        "Published msg_id=%s to subject=%s stream=%s seq=%s",
                        msg_id,
                        self._subject,
                        ack.stream,
                        ack.seq,
                    )
                    self._ring_buffer.ack_up_to(tick.seq_id)
                    

            except (NatsError, asyncio.TimeoutError, OSError) as exc:
                logger.warning(
                    "NATS publish paused (%s); %d ticks buffered in RingBuffer",
                    exc,
                    len(self._ring_buffer),
                )
                await asyncio.sleep(1.0)
            except Exception as exc:
                logger.error("Unexpected publisher error: %s", exc)
                await asyncio.sleep(1.0)

        if nc is not None and nc.is_connected:
            await nc.drain()

    def run_publisher_forever(self, stop_event: threading.Event) -> None:
        asyncio.run(self._publish_loop(stop_event))