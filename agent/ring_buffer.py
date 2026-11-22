from collections import deque
from dataclasses import dataclass
from itertools import islice
import threading
from typing import Any
import uuid


@dataclass(frozen=True)
class BufferTick:
    boot_id: str
    seq_id: int
    payload: Any


class RingBuffer:
    def __init__(self, capacity: int = 1000) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")

        self.capacity = capacity
        self.boot_id: str = str(uuid.uuid4())
        self._seq_id: int = 0
        self._buf: deque[BufferTick] = deque(maxlen=capacity)
        self.evicted_count: int = 0
        self._lock = threading.Lock()

    def push(self, payload: Any) -> int:
        with self._lock:
            self._seq_id += 1

            if len(self._buf) == self.capacity:
                self.evicted_count += 1

            tick = BufferTick(
                boot_id=self.boot_id,
                seq_id=self._seq_id,
                payload=payload,
            )
            self._buf.append(tick)
            return self._seq_id

    def peek_batch(self, max_items: int = 100) -> list[BufferTick]:
        if max_items <= 0:
            return []
        with self._lock:
            return list(islice(self._buf, 0, max_items))

    def ack_up_to(self, seq_id: int) -> int:
        count = 0
        with self._lock:
            while self._buf and self._buf[0].seq_id <= seq_id:
                self._buf.popleft()
                count += 1
            return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)