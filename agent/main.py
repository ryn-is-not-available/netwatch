import logging
import signal
import threading

from agent.collector import MetricsCollector
from agent.config import AgentConfig
from agent.heartbeat import HeartBeat
from agent.publisher import TelemetryPublisher
from agent.ring_buffer import RingBuffer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.agent.main")


def main() -> None:
    cfg = AgentConfig.from_env()
    logger.info(
        "Starting NetWatch agent node_id=%s data_ip=%s cp_addrs=%s heartbeat_interval=%.1fs collect_interval=%.1fs",
        cfg.node_id,
        cfg.data_ip,
        cfg.cp_addrs,
        cfg.heartbeat_interval_s,
        cfg.collect_interval_s,
    )

    stop_event = threading.Event()

    def _handle_shutdown(signum: int, _frame: object) -> None:
        logger.info("Received signal %s; shutting down agent...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    collector = MetricsCollector(data_ip=cfg.data_ip)
    ring_buffer = RingBuffer(capacity=cfg.buffer_capacity)
    heartbeat = HeartBeat(cfg, collector)
    publisher = TelemetryPublisher(cfg, collector, ring_buffer)

    threads = [
        threading.Thread(
            target=heartbeat.runForever,
            args=(stop_event,),
            name="heartbeat-loop",
            daemon=True,
        ),
        threading.Thread(
            target=publisher.run_collector_forever,
            args=(stop_event,),
            name="telemetry-collector",
            daemon=True,
        ),
        threading.Thread(
            target=publisher.run_publisher_forever,
            args=(stop_event,),
            name="telemetry-publisher",
            daemon=True,
        ),
    ]

    for t in threads:
        t.start()

    while not stop_event.is_set():
        stop_event.wait(timeout=1.0)

    for t in threads:
        t.join(timeout=5.0)
    logger.info("NetWatch agent stopped cleanly")


if __name__ == "__main__":
    main()