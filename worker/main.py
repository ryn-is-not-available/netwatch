import asyncio
from dataclasses import dataclass
from datetime import datetime
import json
import logging
import os
import signal
from typing import Any

import nats
from nats.errors import TimeoutError as NatsTimeoutError
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
import psycopg

from shared.telemetry_auth import SIGNATURE_HEADER, tls_context
from worker.verifier import TelemetryVerifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.worker")

# Touched on every loop iteration while the DB connection is usable; the container
# healthcheck checks its age, so a worker stuck reconnecting shows as unhealthy.
HEALTH_FILE = os.environ.get("WORKER_HEALTH_FILE", "/tmp/netwatch-worker.health")


def _touch_health() -> None:
    try:
        with open(HEALTH_FILE, "a"):
            os.utime(HEALTH_FILE, None)
    except OSError as exc:
        logger.debug("Could not touch health file %s: %s", HEALTH_FILE, exc)

INSERT_NODE_METRICS_SQL = """
INSERT INTO node_metrics (
    time,
    node_id,
    boot_id,
    seq_id,
    cpu_usage_pct,
    memory_usage_pct,
    uptime_seconds,
    data_iface,
    rx_bytes,
    tx_bytes,
    rx_drops,
    tx_drops
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (time, node_id, boot_id, seq_id) DO NOTHING;
"""


# Interface inventory is upserted only for enrolled nodes (the FK would otherwise fail the
# whole batch for ticks that arrive before the node's Enroll call).
UPSERT_INTERFACE_SQL = """
INSERT INTO network_interfaces (node_id, name, mac_address, ip_addresses, oper_status, updated_at)
SELECT %s, %s, %s::macaddr, %s::inet[], %s, NOW()
WHERE EXISTS (SELECT 1 FROM nodes WHERE node_id = %s)
ON CONFLICT (node_id, name) DO UPDATE SET
    mac_address = EXCLUDED.mac_address,
    ip_addresses = EXCLUDED.ip_addresses,
    oper_status = EXCLUDED.oper_status,
    updated_at = NOW()
RETURNING interface_id;
"""

INSERT_INTERFACE_METRICS_SQL = """
INSERT INTO interface_metrics (
    time, interface_id, interface_name, node_id, rx_bytes, tx_bytes, rx_errors, tx_errors
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (time, node_id, interface_name) DO NOTHING;
"""

_OPER_STATES = {"up", "down", "degraded", "dormant"}


@dataclass(frozen=True)
class Tick:
    node_id: str
    time: datetime
    node_row: tuple[Any, ...]          # parameters for INSERT_NODE_METRICS_SQL
    interfaces: list[dict[str, Any]]


def _parse_tick(raw_data: bytes) -> Tick:
    """Parses a JSON telemetry message (one agent collector tick)."""
    doc = json.loads(raw_data.decode())
    ts = datetime.fromisoformat(doc["timestamp"])
    node_id = doc["node_id"]
    node_row = (
        ts,
        node_id,
        doc["boot_id"],
        int(doc["seq_id"]),
        doc.get("cpu_pct"),
        doc.get("mem_pct"),
        int(doc.get("uptime_sec", 0)),
        doc.get("data_iface"),
        doc.get("rx_bytes"),
        doc.get("tx_bytes"),
        doc.get("rx_drops"),
        doc.get("tx_drops"),
    )
    interfaces = [i for i in doc.get("interfaces") or [] if isinstance(i, dict) and i.get("name")]
    return Tick(node_id=node_id, time=ts, node_row=node_row, interfaces=interfaces)


def _flush_batch_to_db(conn: psycopg.Connection[Any], ticks: list[Tick]) -> int:
    """Writes node and interface metrics for a batch in one idempotent transaction."""
    try:
        with conn.cursor() as cur:
            cur.executemany(INSERT_NODE_METRICS_SQL, [t.node_row for t in ticks])

            # Inventory: latest metadata per (node, interface) in this batch.
            latest: dict[tuple[str, str], dict[str, Any]] = {}
            for t in ticks:
                for iface in t.interfaces:
                    latest[(t.node_id, iface["name"])] = iface
            interface_ids: dict[tuple[str, str], Any] = {}
            for (node_id, name), iface in latest.items():
                oper = iface.get("oper_status") if iface.get("oper_status") in _OPER_STATES else "up"
                cur.execute(
                    UPSERT_INTERFACE_SQL,
                    (
                        node_id,
                        name,
                        iface.get("mac") or "00:00:00:00:00:00",
                        list(iface.get("ips") or []),
                        oper,
                        node_id,
                    ),
                )
                row = cur.fetchone()
                if row is not None:
                    interface_ids[(node_id, name)] = row[0]

            metric_rows = [
                (
                    t.time,
                    interface_ids[(t.node_id, iface["name"])],
                    iface["name"],
                    t.node_id,
                    iface.get("rx_bytes"),
                    iface.get("tx_bytes"),
                    iface.get("rx_errors"),
                    iface.get("tx_errors"),
                )
                for t in ticks
                for iface in t.interfaces
                if (t.node_id, iface["name"]) in interface_ids
            ]
            if metric_rows:
                cur.executemany(INSERT_INTERFACE_METRICS_SQL, metric_rows)
        conn.commit()
        return len(ticks)
    except Exception:
        conn.rollback()
        raise
    
    


async def _connect_db(db_dsn: str, stop_event: asyncio.Event) -> psycopg.Connection[Any]:
    """Connects to TimescaleDB, retrying until it succeeds (or shutdown is requested)."""
    delay_s = 1.0
    while True:
        try:
            conn = await asyncio.to_thread(psycopg.connect, db_dsn)
            logger.info("Connected to TimescaleDB")
            return conn
        except psycopg.OperationalError as exc:
            if stop_event.is_set():
                raise
            logger.warning("TimescaleDB unavailable (%s); retrying in %.0fs", exc, delay_s)
            await asyncio.sleep(delay_s)
            delay_s = min(delay_s * 2, 10.0)


async def run_worker(stop_event: asyncio.Event) -> None:
    db_dsn = (os.environ.get("DB_DSN") or "").strip()
    nats_url = (os.environ.get("NATS_URL") or "").strip()
    if not db_dsn or not nats_url:
        raise RuntimeError("DB_DSN and NATS_URL environment variables are required")

    conn = await _connect_db(db_dsn, stop_event)

    nats_ca = (os.environ.get("NATS_CA_PATH") or "").strip()
    nc = await nats.connect(
        servers=[nats_url],
        name="telemetry-worker-1",
        max_reconnect_attempts=-1,
        reconnect_time_wait=1.0,
        tls=tls_context(nats_ca) if nats_ca else None,
    )
    verifier = TelemetryVerifier()
    js = nc.jetstream()

    consumer_cfg = ConsumerConfig(
        durable_name="telemetry-ingestor",
        ack_policy=AckPolicy.EXPLICIT,
        deliver_policy=DeliverPolicy.ALL,
        ack_wait=15.0,
        max_deliver=10,
    )
    psub = await js.pull_subscribe(
        subject="telemetry.>",
        durable="telemetry-ingestor",
        stream="TELEMETRY",
        config=consumer_cfg,
    )
    logger.info("Subscribed durable pull consumer 'telemetry-ingestor' on stream TELEMETRY")

    try:
        while not stop_event.is_set():
            _touch_health()
            try:
                msgs = await psub.fetch(batch=100, timeout=1.0)
            except NatsTimeoutError:
                continue

            try:
                # Authenticate first: a node must not be able to write telemetry as another node.
                verdicts = await asyncio.to_thread(
                    lambda: [
                        verifier.check(conn, m.subject, m.data, (m.headers or {}).get(SIGNATURE_HEADER))
                        for m in msgs
                    ]
                )

                rows: list[Tick] = []
                valid_msgs = []
                for msg, reason in zip(msgs, verdicts):
                    if reason is not None:
                        logger.warning("Rejected telemetry on %s: %s", msg.subject, reason)
                        await msg.term()
                        continue
                    try:
                        rows.append(_parse_tick(msg.data))
                        valid_msgs.append(msg)
                    except Exception as exc:
                        logger.error("Poison telemetry message dropped (terminating): %s", exc)
                        await msg.term()

                if not rows:
                    continue

                inserted = await asyncio.to_thread(_flush_batch_to_db, conn, rows)
                # Ack only after the commit succeeded so JetStream advances the consumer cursor.
                for msg in valid_msgs:
                    await msg.ack()

                logger.info("Flushed and acked %d telemetry ticks into TimescaleDB", inserted)
            except Exception as exc:
                logger.error("Telemetry batch failed (leaving msgs unacked for redelivery): %s", exc)
                if conn.closed or conn.broken:
                    # A dead connection never recovers by itself (e.g. after a DB restart).
                    await asyncio.to_thread(conn.close)
                    conn = await _connect_db(db_dsn, stop_event)
                else:
                    await asyncio.sleep(1.0)
    finally:
        await nc.drain()
        await asyncio.to_thread(conn.close)
        logger.info("Worker shut down cleanly")


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop_event = asyncio.Event()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        loop.run_until_complete(run_worker(stop_event))
    finally:
        loop.close()


if __name__ == "__main__":
    main()