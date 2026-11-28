import logging
import threading
from typing import Any

import psycopg

logger = logging.getLogger("netwatch.control_plane.elector")

# Arbitrary 64-bit constant identifying the NetWatch control-plane leader lock
NETWATCH_LEADER_LOCK_KEY = 4829104729104721


class FencingError(RuntimeError):
    """Raised when a write is attempted by a non-leader or with a stale leader epoch."""


class LeaderElector:
    """Postgres session-level advisory lock elector with monotonic epoch fencing."""

    def __init__(
        self,
        db_dsn: str,
        instance_id: str,
        poll_interval_s: float = 0.5,
        lock_key: int = NETWATCH_LEADER_LOCK_KEY,
    ) -> None:
        self._db_dsn = db_dsn
        self.instance_id = instance_id
        self._poll_interval_s = poll_interval_s
        self._lock_key = lock_key

        self._state_lock = threading.Lock()
        self._is_leader = False
        self._epoch = 0
        self._lock_conn: psycopg.Connection[Any] | None = None

    @property
    def is_leader(self) -> bool:
        with self._state_lock:
            return self._is_leader

    @property
    def epoch(self) -> int:
        with self._state_lock:
            return self._epoch

    def current_term(self) -> tuple[bool, int]:
        with self._state_lock:
            return self._is_leader, self._epoch

    def _ensure_lock_conn(self) -> psycopg.Connection[Any]:
        if self._lock_conn is None or self._lock_conn.closed:
            # autocommit=True ensures session-level advisory locks persist outside transactions
            self._lock_conn = psycopg.connect(
                self._db_dsn,
                autocommit=True,
                application_name=f"elector-{self.instance_id}",
            )
        return self._lock_conn

    def _step_down(self, reason: str) -> None:
        with self._state_lock:
            was_leader = self._is_leader
            self._is_leader = False
        if was_leader:
            logger.warning("Instance %s stepped down from leadership (%s)", self.instance_id, reason)
        if self._lock_conn is not None:
            try:
                self._lock_conn.close()
            except Exception:
                pass
            self._lock_conn = None

    def _promote_to_leader(self, conn: psycopg.Connection[Any]) -> int:
        """Atomically revokes any prior active epoch, allocates epoch + 1, and records this leader."""
        with psycopg.connect(self._db_dsn) as tx_conn:
            with tx_conn.cursor() as cur:
                cur.execute(
                    "UPDATE leader_epoch SET status = 'revoked' WHERE status = 'active';"
                )
                cur.execute("SELECT COALESCE(MAX(epoch), 0) + 1 FROM leader_epoch;")
                row = cur.fetchone()
                if row is None:
                    raise RuntimeError("Failed to compute next leader epoch.")
                new_epoch = int(row[0])

                cur.execute(
                    "INSERT INTO leader_epoch (epoch, leader_id, status) VALUES (%s, %s, 'active');",
                    (new_epoch, self.instance_id),
                )
            tx_conn.commit()
        return new_epoch

    def try_acquire_or_renew(self) -> bool:
        """Attempts to acquire or verify the session advisory lock. Returns True iff this node is leader."""
        try:
            conn = self._ensure_lock_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT pg_try_advisory_lock(%s);", (self._lock_key,))
                row = cur.fetchone()
                acquired = bool(row and row[0])

            if not acquired:
                self._step_down("advisory lock held by peer")
                return False

            if not self.is_leader:
                new_epoch = self._promote_to_leader(conn)
                with self._state_lock:
                    self._is_leader = True
                    self._epoch = new_epoch
                logger.info(
                    "Instance %s ACQUIRED leadership (epoch=%d)",
                    self.instance_id,
                    new_epoch,
                )
            return True
        except Exception as exc:
            self._step_down(f"DB connection error: {exc}")
            return False

    def fenced_execute(
        self,
        conn: psycopg.Connection[Any],
        sql: str,
        params: tuple[Any, ...] = (),
        expected_epoch: int | None = None,
    ) -> int:
        """Executes a leader-only SQL statement guarded by active epoch fencing.

        Returns affected rowcount (0 if this instance is no longer the active epoch leader).
        """
        with conn.cursor() as cur:
            if expected_epoch is not None:
                cur.execute(
                    """
                    SELECT 1
                    FROM leader_epoch
                    WHERE epoch = %s AND leader_id = %s AND status = 'active'
                    FOR SHARE
                    """,
                    (expected_epoch, self.instance_id),
                )
            else:
                cur.execute(
                    """
                    SELECT 1
                    FROM leader_epoch
                    WHERE leader_id = %s AND status = 'active'
                    FOR SHARE
                    """,
                    (self.instance_id,),
                )
            if cur.fetchone() is None:
                return 0

            cur.execute(sql, params)
            return cur.rowcount

    def release(self) -> None:
        """Cleanly releases the advisory lock and marks the current epoch expired on graceful shutdown."""
        is_ldr, cur_epoch = self.current_term()
        if is_ldr and cur_epoch > 0:
            try:
                with psycopg.connect(self._db_dsn) as tx_conn:
                    with tx_conn.cursor() as cur:
                        cur.execute(
                            "UPDATE leader_epoch SET status = 'expired' WHERE epoch = %s AND leader_id = %s AND status = 'active';",
                            (cur_epoch, self.instance_id),
                        )
                    tx_conn.commit()
            except Exception as exc:
                logger.warning("Failed to expire epoch %d during shutdown: %s", cur_epoch, exc)
        self._step_down("graceful shutdown")

    def run_forever(self, stop_event: threading.Event) -> None:
        """Background loop polling advisory lock every `poll_interval_s` seconds."""
        logger.info("Starting LeaderElector loop for instance_id=%s", self.instance_id)
        while not stop_event.is_set():
            self.try_acquire_or_renew()
            stop_event.wait(timeout=self._poll_interval_s)
        self.release()