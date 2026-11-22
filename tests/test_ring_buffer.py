import threading
import uuid
import pytest
from agent.ring_buffer import RingBuffer


def test_push_monotonic_seq_and_unique_boot_id():
    rb1 = RingBuffer()
    rb2 = RingBuffer()

    # Valid UUIDv4 format and unique per process/instance
    assert uuid.UUID(rb1.boot_id).version == 4
    assert rb1.boot_id != rb2.boot_id

    seqs = [rb1.push({"cpu": i}) for i in range(1, 5)]
    assert seqs == [1, 2, 3, 4]
    assert len(rb1) == 4

    batch = rb1.peek_batch(10)
    assert all(item.boot_id == rb1.boot_id for item in batch)
    assert [item.seq_id for item in batch] == [1, 2, 3, 4]


def test_eviction_at_1000_capacity():
    rb = RingBuffer(capacity=1000)

    for i in range(1, 1006):
        seq = rb.push({"tick": i})
        assert seq == i

    assert len(rb) == 1000
    assert rb.evicted_count == 5

    remaining = rb.peek_batch(1000)
    assert remaining[0].seq_id == 6
    assert remaining[-1].seq_id == 1005


def test_peek_is_nondestructive_and_ack_is_cumulative_and_idempotent():
    rb = RingBuffer(capacity=10)
    for i in range(1, 6):
        rb.push(f"msg-{i}")

    # Peek twice -> identical result, buffer untouched
    first_peek = rb.peek_batch(3)
    second_peek = rb.peek_batch(3)
    assert first_peek == second_peek
    assert len(rb) == 5

    # Cumulative ack up to seq 3 removes 1, 2, 3
    removed = rb.ack_up_to(3)
    assert removed == 3
    assert len(rb) == 2
    assert [t.seq_id for t in rb.peek_batch(10)] == [4, 5]

    # Re-acking an already-acked seq_id is a safe no-op
    assert rb.ack_up_to(3) == 0
    assert len(rb) == 2

    # Acking past the end clears the remaining items
    assert rb.ack_up_to(99) == 2
    assert len(rb) == 0


def test_invalid_capacity_raises():
    with pytest.raises(ValueError):
        RingBuffer(capacity=0)
    with pytest.raises(ValueError):
        RingBuffer(capacity=-5)


def test_concurrent_push_peek_and_ack():
    rb = RingBuffer(capacity=500)
    total_pushes = 2000

    def producer():
        for i in range(total_pushes):
            rb.push(i)

    def consumer():
        acked = 0
        while acked < total_pushes:
            batch = rb.peek_batch(25)
            if batch:
                last_seq = batch[-1].seq_id
                rb.ack_up_to(last_seq)
                acked = last_seq

    t_prod = threading.Thread(target=producer)
    t_cons = threading.Thread(target=consumer)
    t_prod.start()
    t_cons.start()
    t_prod.join(timeout=5)
    t_cons.join(timeout=5)

    assert not t_prod.is_alive()
    assert not t_cons.is_alive()
    assert len(rb) == 0