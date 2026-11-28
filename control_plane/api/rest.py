from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
import urllib.error
import urllib.request
import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
import psycopg
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.auth import check_credentials, hash_password, load_user
from control_plane.domain.link_history import CLOSE_FOR_NODE_SQL
from control_plane.domain.graph_engine import (
    DeclaredLink,
    ObservedLink,
    TopologyGraphEngine,
)

logger = logging.getLogger("netwatch.control_plane.rest")


UI_DIR = Path(__file__).resolve().parent.parent / "ui"
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
bearer_scheme = HTTPBearer(auto_error=False)

TOKEN_TTL = timedelta(hours=8)
FORWARDED_HEADER = "x-netwatch-forwarded"
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Writes that any replica may serve (they do not mutate control state).
LOCAL_WRITE_PATHS = {"/auth/token"}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(pattern="^(viewer|operator|admin)$")


class UserPatch(BaseModel):
    role: str | None = Field(default=None, pattern="^(viewer|operator|admin)$")
    password: str | None = Field(default=None, min_length=8, max_length=256)
    disabled: bool | None = None


class DesiredLinkIn(BaseModel):
    src_node_id: str
    dst_node_id: str
    admin_cost: float = 1.0
    expected_latency_ms: float = 5.0


class DesiredTopologyRequest(BaseModel):
    links: list[DesiredLinkIn]
    replace: bool = True


class TraceRequest(BaseModel):
    src_node_id: str
    dst_node_id: str


class RecommendationPatchRequest(BaseModel):
    status: str = Field(pattern="^(applied|dismissed)$")


def create_rest_app(db_dsn: str, elector: LeaderElector) -> FastAPI:
    jwt_secret = os.environ.get("JWT_SECRET", "netwatch-dev-jwt-secret-2026-change-me-32b")
    graph_engine = TopologyGraphEngine()
    # Schema (incl. desired_topology_links) lives in db/init.sql. No DDL here: both
    # control-plane replicas start together and concurrent CREATE ... IF NOT EXISTS races.

    app = FastAPI(title="NetWatch Control Plane API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(UI_DIR / "index.html")
    peer_rest_url = (os.environ.get("PEER_REST_URL") or "").rstrip("/")
    peer_host = urlparse(peer_rest_url).hostname if peer_rest_url else None

    def _client_ip(request: Request) -> str:
        """Caller IP for the audit log. A write forwarded by the standby carries the original
        client in X-Forwarded-For, trusted only when it really comes from the peer replica."""
        host = unquote(request.client.host) if request.client and request.client.host else "127.0.0.1"
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for and request.headers.get(FORWARDED_HEADER) and peer_host and host == peer_host:
            return forwarded_for.split(",")[0].strip()
        return host

    def require_role(min_role: str):
        def _dep(
            creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
        ) -> dict[str, Any]:
            if creds is None or not creds.credentials:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing Bearer token",
                )
            try:
                payload = jwt.decode(creds.credentials, jwt_secret, algorithms=["HS256"])
            except jwt.PyJWTError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token: {exc}",
                ) from exc

            # The token only proves who the caller is. Their role, and whether they may still
            # sign in, come from the database, so demotions and disabling apply immediately.
            with psycopg.connect(db_dsn) as conn:
                user = load_user(conn, str(payload.get("sub", "")))
            if user is None or user[2]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User no longer exists or is disabled",
                )
            role = user[1]
            if ROLE_RANK.get(role, 0) < ROLE_RANK[min_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' lacks required '{min_role}' permission",
                )
            return {**payload, "role": role}

        return _dep

    @app.middleware("http")
    async def forward_writes_to_leader(request: Request, call_next):
        """A standby forwards state-changing requests to the leader over MGMT_NET, so clients
        (the UI included) can use either replica. A request is never forwarded twice."""
        if (
            request.method not in WRITE_METHODS
            or request.url.path in LOCAL_WRITE_PATHS
            or elector.is_leader
        ):
            return await call_next(request)
        if request.headers.get(FORWARDED_HEADER) or not peer_rest_url:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": f"{elector.instance_id} is a standby and no leader is reachable; retry shortly"},
            )

        body = await request.body()
        target = peer_rest_url + request.url.path + (f"?{request.url.query}" if request.url.query else "")
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() in ("authorization", "content-type", "accept")
        }
        headers[FORWARDED_HEADER] = elector.instance_id
        headers["X-Forwarded-For"] = _client_ip(request)

        def _forward() -> tuple[int, bytes, str]:
            req = urllib.request.Request(target, data=body or None, method=request.method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read(), resp.headers.get("content-type", "application/json")
            except urllib.error.HTTPError as err:
                return err.code, err.read(), err.headers.get("content-type", "application/json")

        try:
            code, content, ctype = await run_in_threadpool(_forward)
        except (urllib.error.URLError, OSError) as exc:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": f"Leader unreachable from standby {elector.instance_id}: {exc}"},
            )
        return Response(content=content, status_code=code, media_type=ctype)

    def _parse_uuid(value: str, what: str) -> str:
        try:
            return str(uuid.UUID(value))
        except ValueError:
            raise HTTPException(status_code=404, detail=f"{what} not found") from None

    def _require_leader(conn: psycopg.Connection[Any]) -> None:
        """Epoch-fences a REST write: only the active leader may mutate control state.

        Takes a FOR SHARE lock on this instance's active epoch row, so a concurrent
        promotion of the peer (which revokes that row) waits for this transaction.
        """
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM leader_epoch WHERE leader_id = %s AND status = 'active' FOR SHARE;",
                (elector.instance_id,),
            )
            if cur.fetchone() is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"{elector.instance_id} is a standby; send writes to the active leader",
                )

    def _require_nodes(cur: psycopg.Cursor, node_ids: list[str]) -> dict[str, str]:
        """Returns {node_id: health_status}; 404 if any node is unknown."""
        ids = sorted(set(node_ids))
        cur.execute("SELECT node_id, health_status FROM nodes WHERE node_id = ANY(%s);", (ids,))
        found = {row[0]: row[1] for row in cur.fetchall()}
        missing = [n for n in ids if n not in found]
        if missing:
            raise HTTPException(status_code=404, detail=f"Unknown node(s): {', '.join(missing)}")
        return found

    def _write_audit(
        conn: psycopg.Connection[Any],
        actor_id: str,
        action_type: str,
        target_entity: str,
        details: dict[str, Any],
        ip_addr: str,
    ) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_log (actor_id, action_type, target_entity, details, ip_address)
                VALUES (%s, %s, %s, %s::jsonb, %s::inet);
                """,
                (actor_id, action_type, target_entity, json.dumps(details), ip_addr),
            )

    @app.get("/health")
    def health() -> dict[str, Any]:
        is_ldr, epoch = elector.current_term()
        return {
            "status": "ok",
            "instance_id": elector.instance_id,
            "is_leader": is_ldr,
            "leader_epoch": epoch,
        }

    @app.post("/auth/token")
    def issue_token(body: LoginRequest) -> dict[str, str]:
        with psycopg.connect(db_dsn) as conn:
            user = load_user(conn, body.username)
        if not check_credentials(user[0] if user else None, body.password) or user is None or user[2]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": body.username,
                "role": user[1],
                "iat": int(now.timestamp()),
                "exp": int((now + TOKEN_TTL).timestamp()),
            },
            jwt_secret,
            algorithm="HS256",
        )
        return {"access_token": token, "token_type": "bearer", "role": user[1], "username": body.username}

    @app.get("/auth/me")
    def whoami(user: dict[str, Any] = Depends(require_role("viewer"))) -> dict[str, Any]:
        return {"username": user.get("sub"), "role": user.get("role")}

    @app.get("/users")
    def list_users(_user: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT username, role, disabled, created_at FROM users ORDER BY username;")
                return [
                    {"username": r[0], "role": r[1], "disabled": r[2], "created_at": r[3].isoformat()}
                    for r in cur.fetchall()
                ]

    @app.post("/users", status_code=status.HTTP_201_CREATED)
    def create_user(
        body: UserCreate, request: Request, user: dict[str, Any] = Depends(require_role("admin"))
    ) -> dict[str, Any]:
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) "
                    "ON CONFLICT (username) DO NOTHING;",
                    (body.username, hash_password(body.password), body.role),
                )
                if cur.rowcount == 0:
                    raise HTTPException(status_code=409, detail=f"User {body.username!r} already exists")
            _write_audit(conn, str(user.get("sub")), "CREATE_USER", body.username, {"role": body.role}, _client_ip(request))
            conn.commit()
        return {"username": body.username, "role": body.role, "disabled": False}

    @app.patch("/users/{username}")
    def update_user(
        username: str, body: UserPatch, request: Request, user: dict[str, Any] = Depends(require_role("admin"))
    ) -> dict[str, Any]:
        if username == user.get("sub") and (body.disabled or (body.role and body.role != "admin")):
            raise HTTPException(status_code=400, detail="Admins cannot disable or demote themselves")
        sets: list[str] = []
        params: list[Any] = []
        changed: dict[str, Any] = {}
        if body.role is not None:
            sets.append("role = %s")
            params.append(body.role)
            changed["role"] = body.role
        if body.disabled is not None:
            sets.append("disabled = %s")
            params.append(body.disabled)
            changed["disabled"] = body.disabled
        if body.password is not None:
            sets.append("password_hash = %s")
            params.append(hash_password(body.password))
            changed["password"] = "changed"
        if not sets:
            raise HTTPException(status_code=422, detail="Nothing to update")
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE users SET {', '.join(sets)}, updated_at = NOW() WHERE username = %s "
                    "RETURNING username, role, disabled;",
                    (*params, username),
                )
                row = cur.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="User not found")
            _write_audit(conn, str(user.get("sub")), "UPDATE_USER", username, changed, _client_ip(request))
            conn.commit()
        return {"username": row[0], "role": row[1], "disabled": row[2]}

    @app.post("/nodes/{node_id}/reinstate")
    def reinstate_node(
        node_id: str, request: Request, user: dict[str, Any] = Depends(require_role("admin"))
    ) -> dict[str, Any]:
        """Lifts a revocation. The node goes to 'offline' and becomes healthy again once it
        re-enrolls and heartbeats; its links reopen from fresh probes."""
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE nodes SET health_status = 'offline' WHERE node_id = %s AND health_status = 'revoked' "
                    "RETURNING node_id;",
                    (node_id,),
                )
                if cur.fetchone() is None:
                    cur.execute("SELECT 1 FROM nodes WHERE node_id = %s;", (node_id,))
                    if cur.fetchone() is None:
                        raise HTTPException(status_code=404, detail="Node not found")
                    raise HTTPException(status_code=409, detail=f"Node {node_id} is not revoked")
            _write_audit(conn, str(user.get("sub")), "REINSTATE_NODE", node_id, {}, _client_ip(request))
            conn.commit()
        return {"node_id": node_id, "health_status": "offline"}

    @app.post("/alerts/{alert_id}/ack")
    def acknowledge_alert(
        alert_id: str, request: Request, user: dict[str, Any] = Depends(require_role("operator"))
    ) -> dict[str, Any]:
        alert_id = _parse_uuid(alert_id, "Alert")
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE alerts SET status = 'acknowledged' WHERE alert_id = %s::uuid AND status = 'new' "
                    "RETURNING alert_id::text;",
                    (alert_id,),
                )
                if cur.fetchone() is None:
                    cur.execute("SELECT status FROM alerts WHERE alert_id = %s::uuid;", (alert_id,))
                    row = cur.fetchone()
                    if row is None:
                        raise HTTPException(status_code=404, detail="Alert not found")
                    raise HTTPException(status_code=409, detail=f"Alert is already {row[0]}")
            _write_audit(conn, str(user.get("sub")), "ACK_ALERT", alert_id, {}, _client_ip(request))
            conn.commit()
        return {"alert_id": alert_id, "status": "acknowledged"}

    @app.get("/nodes")
    def list_nodes(_user: dict[str, Any] = Depends(require_role("viewer"))) -> list[dict[str, Any]]:
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT node_id, ip_address, health_status, last_heartbeat
                    FROM nodes
                    ORDER BY node_id;
                    """
                )
                return [
                    {
                        "node_id": r[0],
                        "ip_address": r[1],
                        "health_status": r[2],
                        "last_heartbeat": r[3].isoformat() if r[3] else None,
                    }
                    for r in cur.fetchall()
                ]

    @app.get("/nodes/{node_id}/metrics")
    def node_metrics(
        node_id: str,
        minutes: int = Query(default=15, ge=1, le=1440),
        _user: dict[str, Any] = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        """CPU, memory and DATA_NET throughput for one node, bucketed to ~120 points.

        Throughput is the delta of the byte counters between buckets; a gap or a counter reset
        (agent reboot) yields null instead of a fake dip or spike.
        """
        bucket_s = max(5, (minutes * 60) // 120)
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                _require_nodes(cur, [node_id])
                cur.execute(
                    """
                    WITH b AS (
                        SELECT time_bucket(make_interval(secs => %(bucket)s), time) AS t,
                               AVG(cpu_usage_pct) AS cpu,
                               AVG(memory_usage_pct) AS mem,
                               MAX(rx_bytes) AS rx,
                               MAX(tx_bytes) AS tx
                        FROM node_metrics
                        WHERE node_id = %(node)s AND time > NOW() - make_interval(mins => %(minutes)s)
                        GROUP BY 1
                    ), d AS (
                        SELECT t, cpu, mem,
                               rx - LAG(rx) OVER w AS drx,
                               tx - LAG(tx) OVER w AS dtx,
                               EXTRACT(EPOCH FROM t - LAG(t) OVER w) AS dt
                        FROM b WINDOW w AS (ORDER BY t)
                    )
                    SELECT t, cpu, mem,
                           CASE WHEN drx >= 0 AND dt > 0 AND dt <= 2 * %(bucket)s THEN drx / dt END,
                           CASE WHEN dtx >= 0 AND dt > 0 AND dt <= 2 * %(bucket)s THEN dtx / dt END
                    FROM d ORDER BY t;
                    """,
                    {"bucket": bucket_s, "node": node_id, "minutes": minutes},
                )
                rows = cur.fetchall()

        def _num(v: Any) -> float | None:
            return None if v is None else round(float(v), 2)

        return {
            "node_id": node_id,
            "minutes": minutes,
            "bucket_seconds": bucket_s,
            "points": [
                {"t": r[0].isoformat(), "cpu_pct": _num(r[1]), "mem_pct": _num(r[2]),
                 "rx_bps": _num(r[3]), "tx_bps": _num(r[4])}
                for r in rows
            ],
        }

    @app.post("/topology/desired")
    def set_desired_topology(
        body: DesiredTopologyRequest,
        request: Request,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        self_links = [f"{l.src_node_id}->{l.dst_node_id}" for l in body.links if l.src_node_id == l.dst_node_id]
        if self_links:
            raise HTTPException(status_code=422, detail=f"Self-links are not allowed: {', '.join(self_links)}")

        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                _require_nodes(cur, [n for l in body.links for n in (l.src_node_id, l.dst_node_id)])
                if body.replace:
                    cur.execute("DELETE FROM desired_topology_links;")
                for link in body.links:
                    cur.execute(
                        """
                        INSERT INTO desired_topology_links (
                            src_node_id, dst_node_id, admin_cost, expected_latency_ms, updated_at
                        )
                        VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (src_node_id, dst_node_id) DO UPDATE SET
                            admin_cost = EXCLUDED.admin_cost,
                            expected_latency_ms = EXCLUDED.expected_latency_ms,
                            updated_at = NOW();
                        """,
                        (link.src_node_id, link.dst_node_id, link.admin_cost, link.expected_latency_ms),
                    )
            _write_audit(
                conn,
                actor_id=str(user.get("sub", "unknown")),
                action_type="SET_DESIRED_TOPOLOGY",
                target_entity="desired_topology_links",
                details={"count": len(body.links), "replace": body.replace},
                ip_addr=_client_ip(request),
            )
            conn.commit()
        return {"stored": len(body.links), "replace": body.replace}

    @app.get("/topology")
    def get_topology(
        at: datetime | None = Query(default=None),
        known_at: datetime | None = Query(default=None),
        _user: dict[str, Any] = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        at_ts = at if at is not None else datetime.now(timezone.utc)
        known_at_ts = known_at if known_at is not None else datetime.now(timezone.utc)

        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT node_id, ip_address, health_status, last_heartbeat FROM nodes ORDER BY node_id;"
                )
                nodes = [
                    {
                        "node_id": row[0],
                        "ip_address": row[1],
                        "health_status": row[2],
                        "last_heartbeat": row[3].isoformat() if row[3] else None,
                    }
                    for row in cur.fetchall()
                ]

                cur.execute(
                    """
                    SELECT src_node_id, dst_node_id, admin_cost, expected_latency_ms
                    FROM desired_topology_links
                    ORDER BY src_node_id, dst_node_id;
                    """
                )
                declared_rows = cur.fetchall()
                declared_links = [
                    {
                        "src_node_id": row[0],
                        "dst_node_id": row[1],
                        "admin_cost": float(row[2]),
                        "expected_latency_ms": float(row[3]),
                    }
                    for row in declared_rows
                ]
                declared_dc = [
                    DeclaredLink(row[0], row[1], float(row[2])) for row in declared_rows
                ]

                # Links as they were at `at`, as NetWatch believed at `known_at`. Their quality is
                # measured from the raw probe series in the 30s before `at`, limited to the link's
                # own segment and to samples already known at `known_at`.
                cur.execute(
                    """
                    SELECT tl.link_id::text, tl.src_node_id, tl.dst_node_id, tl.status,
                           COALESCE(AVG(pr.latency_ms) FILTER (WHERE pr.success), tl.latency_ms, 0.0),
                           COALESCE(AVG(pr.packet_loss_pct), tl.packet_loss_pct, 0.0)
                    FROM topology_links tl
                    LEFT JOIN probe_results pr
                      ON pr.src_node_id = tl.src_node_id
                     AND pr.dst_node_id = tl.dst_node_id
                     AND pr.time > GREATEST(%(at)s::timestamptz - interval '30 seconds', lower(tl.valid_during))
                     AND pr.time <= LEAST(%(at)s::timestamptz, %(known)s::timestamptz)
                    WHERE tl.valid_during @> %(at)s::timestamptz
                      AND tl.recorded_during @> %(known)s::timestamptz
                    GROUP BY tl.link_id, tl.src_node_id, tl.dst_node_id, tl.status,
                             tl.latency_ms, tl.packet_loss_pct;
                    """,
                    {"at": at_ts, "known": known_at_ts},
                )
                observed_rows = [
                    (r[0], r[1], r[2], r[3], float(r[4]), float(r[5])) for r in cur.fetchall()
                ]
                observed_links = [
                    {
                        "link_id": row[0],
                        "src_node_id": row[1],
                        "dst_node_id": row[2],
                        "status": row[3],
                        "latency_ms": row[4],
                        "packet_loss_pct": row[5],
                    }
                    for row in observed_rows
                ]
                observed_dc = [
                    ObservedLink(
                        src_node_id=row[1],
                        dst_node_id=row[2],
                        status=row[3],
                        latency_ms=float(row[4] or 0.0),
                        packet_loss_pct=float(row[5] or 0.0),
                    )
                    for row in observed_rows
                ]

        drift = [
            {
                "drift_type": d.drift_type,
                "src_node_id": d.src_node_id,
                "dst_node_id": d.dst_node_id,
                "details": d.details,
                "severity": d.severity,
            }
            for d in graph_engine.compute_drift(declared_dc, observed_dc)
        ]

        return {
            "at": at_ts.isoformat(),
            "known_at": known_at_ts.isoformat(),
            "nodes": nodes,
            "declared_links": declared_links,
            "observed_links": observed_links,
            "drift": drift,
        }
        
    def _queue_trace(cur: psycopg.Cursor, src: str, dst: str) -> dict[str, Any]:
        """Creates a PENDING path trace and queues the run_trace command for the source node."""
        if src == dst:
            raise HTTPException(status_code=400, detail="src_node_id and dst_node_id must differ")
        statuses = _require_nodes(cur, [src, dst])
        if statuses[src] in ("offline", "revoked"):
            raise HTTPException(
                status_code=409,
                detail=f"Source node {src} is {statuses[src]} and cannot run a trace",
            )
        cur.execute("SELECT data_ip FROM nodes WHERE node_id = %s;", (dst,))
        dst_data_ip = (cur.fetchone() or [None])[0]
        cur.execute("SELECT src_node_id, dst_node_id, admin_cost FROM desired_topology_links;")
        declared = [DeclaredLink(r[0], r[1], float(r[2])) for r in cur.fetchall()]
        nominal_cost, nominal_path = graph_engine.shortest_path(declared, src, dst)

        trace_id = str(uuid.uuid4())
        initial_hops = [
            {
                "status": "PENDING",
                "nominal_path": nominal_path,
                "nominal_cost": None if nominal_cost == float("inf") else nominal_cost,
            }
        ]
        cur.execute(
            """
            INSERT INTO path_traces (trace_id, src_node_id, dst_node_id, hops, captured_at)
            VALUES (%s::uuid, %s, %s, %s::jsonb, NOW());
            """,
            (trace_id, src, dst, json.dumps(initial_hops)),
        )
        cur.execute(
            """
            INSERT INTO node_commands (target_node_id, command_type, payload, leader_epoch, status)
            VALUES (%s, 'run_trace', %s::jsonb, %s, 'queued');
            """,
            (src, json.dumps({"trace_id": trace_id, "dst_node_id": dst, "dst_data_ip": dst_data_ip}), elector.epoch),
        )
        return {"trace_id": trace_id, "nominal_path": nominal_path}

    @app.post("/paths/trace", status_code=status.HTTP_202_ACCEPTED)
    def start_trace(
        body: TraceRequest,
        request: Request,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                queued = _queue_trace(cur, body.src_node_id, body.dst_node_id)
            _write_audit(
                conn,
                actor_id=str(user.get("sub", "unknown")),
                action_type="START_PATH_TRACE",
                target_entity=queued["trace_id"],
                details={"src": body.src_node_id, "dst": body.dst_node_id},
                ip_addr=_client_ip(request),
            )
            conn.commit()

        return {
            "trace_id": queued["trace_id"],
            "status": "PENDING",
            "src_node_id": body.src_node_id,
            "dst_node_id": body.dst_node_id,
            "nominal_path": queued["nominal_path"],
        }

    @app.get("/paths/trace/{trace_id}")
    def get_trace(
        trace_id: str,
        _user: dict[str, Any] = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        trace_id = _parse_uuid(trace_id, "Trace")
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT trace_id::text, src_node_id, dst_node_id, hops,
                           packet_loss_pct, avg_latency_ms, captured_at
                    FROM path_traces
                    WHERE trace_id = %s::uuid;
                    """,
                    (trace_id,),
                )
                row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Trace not found")

        hops = row[3] or []
        trace_status = "DONE"
        if hops and isinstance(hops, list) and isinstance(hops[0], dict):
            first_status = hops[0].get("status")
            if first_status in ("PENDING", "TIMEOUT", "DONE"):
                trace_status = first_status

        if trace_status == "PENDING" and row[6] is not None:
            age_s = (datetime.now(timezone.utc) - row[6]).total_seconds()
            if age_s > 15.0:
                trace_status = "TIMEOUT"

        return {
            "trace_id": row[0],
            "status": trace_status,
            "src_node_id": row[1],
            "dst_node_id": row[2],
            "hops": hops,
            "packet_loss_pct": float(row[4]) if row[4] is not None else None,
            "avg_latency_ms": float(row[5]) if row[5] is not None else None,
            "captured_at": row[6].isoformat() if row[6] else None,
        }


    @app.post("/nodes/{node_id}/revoke")
    def revoke_node(
        node_id: str,
        request: Request,
        user: dict[str, Any] = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE nodes SET health_status = 'revoked' WHERE node_id = %s RETURNING node_id;",
                    (node_id,),
                )
                if cur.fetchone() is None:
                    raise HTTPException(status_code=404, detail="Node not found")

                # Close its links as a new bitemporal version (history is kept).
                cur.execute(CLOSE_FOR_NODE_SQL, (node_id, node_id))

            _write_audit(
                conn,
                str(user.get("sub", "unknown")),
                "REVOKE_NODE",
                node_id,
                {"reason": "admin_revoked"},
                _client_ip(request),
            )
            conn.commit()

        return {"node_id": node_id, "health_status": "revoked"}

    @app.patch("/recommendations/{recommendation_id}")
    def patch_recommendation(
        recommendation_id: str,
        body: RecommendationPatchRequest,
        request: Request,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        """Applying a recommendation executes its action (declare the link, or run an evidence
        trace) in the same transaction; dismissing only records the decision."""
        recommendation_id = _parse_uuid(recommendation_id, "Recommendation")
        result: dict[str, Any] = {}
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, action FROM recommendations WHERE recommendation_id = %s::uuid FOR UPDATE;",
                    (recommendation_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Recommendation not found")
                if row[0] != "pending":
                    raise HTTPException(status_code=409, detail=f"Recommendation is already {row[0]}")

                action = row[1] or {}
                if body.status == "applied" and action.get("type") == "declare_link":
                    _require_nodes(cur, [action["src"], action["dst"]])
                    cur.execute(
                        """
                        INSERT INTO desired_topology_links (src_node_id, dst_node_id, updated_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (src_node_id, dst_node_id) DO NOTHING;
                        """,
                        (action["src"], action["dst"]),
                    )
                    result = {"declared_link": f"{action['src']}->{action['dst']}"}
                elif body.status == "applied" and action.get("type") == "run_trace":
                    result = {"trace_id": _queue_trace(cur, action["src"], action["dst"])["trace_id"]}

                cur.execute(
                    """
                    UPDATE recommendations
                    SET status = %s,
                        applied_at = CASE WHEN %s = 'applied' THEN NOW() ELSE applied_at END
                    WHERE recommendation_id = %s::uuid
                    RETURNING recommendation_id::text, status;
                    """,
                    (body.status, body.status, recommendation_id),
                )
                row = cur.fetchone()

            _write_audit(
                conn,
                str(user.get("sub", "unknown")),
                "PATCH_RECOMMENDATION",
                recommendation_id,
                {"status": body.status, **result},
                _client_ip(request),
            )
            conn.commit()

        return {"recommendation_id": row[0], "status": row[1], "result": result}

    @app.get("/alerts")
    def list_alerts(_user: dict[str, Any] = Depends(require_role("viewer"))) -> list[dict[str, Any]]:
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT alert_id::text, affected_node_id, severity, status, message, created_at
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT 50;
                    """
                )
                return [
                    {
                        "alert_id": r[0],
                        "affected_node_id": r[1],
                        "severity": r[2],
                        "status": r[3],
                        "message": r[4],
                        "created_at": r[5].isoformat() if r[5] else None,
                    }
                    for r in cur.fetchall()
                ]

    @app.get("/recommendations")
    def list_recommendations(_user: dict[str, Any] = Depends(require_role("viewer"))) -> list[dict[str, Any]]:
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT recommendation_id::text, alert_id::text, diagnosis, suggested_fix, status, created_at, action
                    FROM recommendations
                    ORDER BY created_at DESC
                    LIMIT 50;
                    """
                )
                return [
                    {
                        "recommendation_id": r[0],
                        "alert_id": r[1],
                        "diagnosis": r[2],
                        "suggested_fix": r[3],
                        "status": r[4],
                        "created_at": r[5].isoformat() if r[5] else None,
                        "action": r[6],
                    }
                    for r in cur.fetchall()
                ]

    @app.post("/diagnose")
    def run_diagnosis(
        request: Request,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        """Generates actionable recommendations for active drift items."""
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT src_node_id, dst_node_id, admin_cost FROM desired_topology_links;")
                declared = [DeclaredLink(r[0], r[1], float(r[2])) for r in cur.fetchall()]
            observed = graph_engine.load_observed_from_db(conn, window_seconds=30)
            drifts = graph_engine.compute_drift(declared, observed)
            created = 0
            with conn.cursor() as cur:
                for d in drifts:
                    diag = f"[{d.drift_type}] {d.src_node_id} -> {d.dst_node_id}: {d.details}"
                    if d.drift_type == "extra_observed":
                        fix = (
                            f"Declare {d.src_node_id}->{d.dst_node_id} in the desired topology "
                            "(or block the unauthorized peer)"
                        )
                        action = {"type": "declare_link", "src": d.src_node_id, "dst": d.dst_node_id}
                    else:
                        fix = (
                            f"Run a path trace {d.src_node_id}->{d.dst_node_id} to locate the failing hop, "
                            "then check DATA_NET interface/routing"
                        )
                        action = {"type": "run_trace", "src": d.src_node_id, "dst": d.dst_node_id}
                    # Re-running Diagnose must not stack duplicates of a still-pending fix.
                    cur.execute(
                        """
                        INSERT INTO recommendations (diagnosis, suggested_fix, status, action)
                        SELECT %s, %s, 'pending', %s::jsonb
                        WHERE NOT EXISTS (
                            SELECT 1 FROM recommendations
                            WHERE diagnosis = %s AND status = 'pending'
                        );
                        """,
                        (diag, fix, json.dumps(action), diag),
                    )
                    created += cur.rowcount
            _write_audit(
                conn,
                actor_id=str(user.get("sub", "unknown")),
                action_type="RUN_DIAGNOSIS",
                target_entity="topology",
                details={"recommendations_created": created},
                ip_addr=_client_ip(request),
            )
            conn.commit()
        return {"recommendations_created": created, "drift_count": len(drifts)}

    @app.get("/audit")
    def list_audit(_user: dict[str, Any] = Depends(require_role("viewer"))) -> list[dict[str, Any]]:
        with psycopg.connect(db_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT log_id::text, actor_id, action_type, target_entity, details, host(ip_address), created_at
                    FROM audit_log
                    ORDER BY created_at DESC
                    LIMIT 50;
                    """
                )
                return [
                    {
                        "log_id": r[0],
                        "actor_id": r[1],
                        "action_type": r[2],
                        "target_entity": r[3],
                        "details": r[4],
                        "ip_address": r[5],
                        "created_at": r[6].isoformat() if r[6] else None,
                    }
                    for r in cur.fetchall()
                ]

    @app.get("/", response_class=HTMLResponse)
    def serve_ui() -> HTMLResponse:
        ui_path = Path(__file__).resolve().parent.parent / "ui" / "index.html"
        if ui_path.exists():
            return HTMLResponse(ui_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>NetWatch UI pending Sprint 3</h1>")

    return app