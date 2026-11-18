import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnrollRequest(_message.Message):
    __slots__ = ("node_id", "enrollment_token", "csr_pem")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CSR_PEM_FIELD_NUMBER: _ClassVar[int]
    node_id: str
    enrollment_token: str
    csr_pem: bytes
    def __init__(self, node_id: _Optional[str] = ..., enrollment_token: _Optional[str] = ..., csr_pem: _Optional[bytes] = ...) -> None: ...

class EnrollResponse(_message.Message):
    __slots__ = ("cert_pem",)
    CERT_PEM_FIELD_NUMBER: _ClassVar[int]
    cert_pem: bytes
    def __init__(self, cert_pem: _Optional[bytes] = ...) -> None: ...

class Heartbeat(_message.Message):
    __slots__ = ("node_id", "timestamp", "cpu_usage_pct", "memory_usage_pct", "uptime_seconds")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CPU_USAGE_PCT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_USAGE_PCT_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    node_id: str
    timestamp: _timestamp_pb2.Timestamp
    cpu_usage_pct: float
    memory_usage_pct: float
    uptime_seconds: int
    def __init__(self, node_id: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., cpu_usage_pct: _Optional[float] = ..., memory_usage_pct: _Optional[float] = ..., uptime_seconds: _Optional[int] = ...) -> None: ...

class ProbeResult(_message.Message):
    __slots__ = ("node_id", "probe_id", "timestamp", "probe_type", "probe_target", "latency_ms", "jitter_ms", "packet_loss_pct", "success", "error_message")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    PROBE_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    PROBE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PROBE_TARGET_FIELD_NUMBER: _ClassVar[int]
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    JITTER_MS_FIELD_NUMBER: _ClassVar[int]
    PACKET_LOSS_PCT_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    node_id: str
    probe_id: str
    timestamp: _timestamp_pb2.Timestamp
    probe_type: str
    probe_target: str
    latency_ms: float
    jitter_ms: float
    packet_loss_pct: float
    success: bool
    error_message: str
    def __init__(self, node_id: _Optional[str] = ..., probe_id: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., probe_type: _Optional[str] = ..., probe_target: _Optional[str] = ..., latency_ms: _Optional[float] = ..., jitter_ms: _Optional[float] = ..., packet_loss_pct: _Optional[float] = ..., success: _Optional[bool] = ..., error_message: _Optional[str] = ...) -> None: ...

class Ack(_message.Message):
    __slots__ = ("ok", "message", "server_timestamp_ms", "leader_epoch")
    OK_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SERVER_TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    LEADER_EPOCH_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    message: str
    server_timestamp_ms: int
    leader_epoch: int
    def __init__(self, ok: _Optional[bool] = ..., message: _Optional[str] = ..., server_timestamp_ms: _Optional[int] = ..., leader_epoch: _Optional[int] = ...) -> None: ...
