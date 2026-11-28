import asyncio
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.worker")

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


def _parse_tick_row(raw_data: bytes) -> tuple[Any, ...]:
    """Parses a JSON telemetry message into a parameter tuple matching INSERT_NODE_METRICS_SQL."""

    doc = json.loads(raw_data.decode())
    
    return (
            datetime.fromisoformat(doc["timestamp"]),
            doc["node_id"], doc["boot_id"],
            int(doc["seq_id"]),
            doc.get("cpu_pct"),
            doc.get("mem_pct"),
            int(doc.get("uptime_sec", 0)),
            doc.get("data_iface"),
            doc.get("rx_bytes"),
            doc.get("tx_bytes"),
            doc.get("rx_drops"),
            doc.get("tx_drops")
            )


def _flush_batch_to_db(conn: psycopg.Connection[Any], rows: list[tuple[Any, ...]]) -> int:
    """Executes an idempotent batch insert inside a single transaction."""
    try:
        with conn.cursor() as cur:
            cur.executemany(INSERT_NODE_METRICS_SQL, rows)
        conn.commit()
        return len(rows)
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

    nc = await nats.connect(
        servers=[nats_url],
        name="telemetry-worker-1",
        max_reconnect_attempts=-1,
        reconnect_time_wait=1.0,
    )
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
            try:
                msgs = await psub.fetch(batch=100, timeout=1.0)
            except NatsTimeoutError:
                continue

            rows: list[tuple[Any, ...]] = []
            valid_msgs = []
            for msg in msgs:
                try:
                    rows.append(_parse_tick_row(msg.data))
                    valid_msgs.append(msg)
                except Exception as exc:
                    logger.error("Poison telemetry message dropped (terminating): %s", exc)
                    await msg.term()

            if not rows:
                continue

            try:
                inserted = await asyncio.to_thread(_flush_batch_to_db, conn, rows)
                # Ack only after the commit succeeded so JetStream advances the consumer cursor.
                for msg in valid_msgs:
                    await msg.ack()

                logger.info("Flushed and acked %d telemetry ticks into TimescaleDB", inserted)
            except Exception as exc:
                logger.error("DB batch flush failed (leaving %d msgs unacked for redelivery): %s", len(valid_msgs), exc)
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