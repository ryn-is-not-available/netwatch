import logging
import signal
import threading

from agent.collector import MetricsCollector
from agent.config import AgentConfig
from agent.heartbeat import HeartBeat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netwatch.agent.main")


def main() -> None:
    cfg = AgentConfig.from_env()
    logger.info(
        "Starting NetWatch agent node_id=%s data_ip=%s cp_addrs=%s heartbeat_interval=%.1fs",
        cfg.node_id,
        cfg.data_ip,
        cfg.cp_addrs,
        cfg.heartbeat_interval_s,
    )

    stop_event = threading.Event()

    def _handle_shutdown(signum: int, _frame: object) -> None:
        logger.info("Received signal %s; shutting down agent...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    collector = MetricsCollector(data_ip=cfg.data_ip)
    heartbeat = HeartBeat(cfg, collector)

    hb_thread = threading.Thread(
        target=heartbeat.runForever,
        args=(stop_event,),
        name="heartbeat-loop",
        daemon=True,
    )
    hb_thread.start()

    while not stop_event.is_set():
        stop_event.wait(timeout=1.0)

    hb_thread.join(timeout=5.0)
    logger.info("NetWatch agent stopped cleanly")


if __name__ == "__main__":
    main()