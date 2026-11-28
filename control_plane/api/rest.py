from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import unquote
import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse,FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
import psycopg
from pydantic import BaseModel, Field

from control_plane.adapters.elector import LeaderElector
from control_plane.domain.graph_engine import (
    DeclaredLink,
    ObservedLink,
    TopologyGraphEngine,
)

logger = logging.getLogger("netwatch.control_plane.rest")


UI_DIR = Path(__file__).resolve().parent.parent / "ui"
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
bearer_scheme = HTTPBearer(auto_error=False)

class TokenRequest(BaseModel):
    subject: str = Field(default="dev-operator", min_length=1)
    role: str = Field(default="admin", pattern="^(viewer|operator|admin)$")


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


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return unquote(request.client.host)
    return "127.0.0.1"


def create_rest_app(db_dsn: str, elector: LeaderElector) -> FastAPI:
    jwt_secret = os.environ.get("JWT_SECRET", "netwatch-dev-jwt-secret-2026")
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

            role = str(payload.get("role", ""))
            if ROLE_RANK.get(role, 0) < ROLE_RANK[min_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' lacks required '{min_role}' permission",
                )
            return payload

        return _dep

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
                (actor_id, action_type, target_entity, jwt.utils.force_bytes(
                    __import__("json").dumps(details)
                ).decode("utf-8"), ip_addr),
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
    def issue_token(body: TokenRequest) -> dict[str, str]:
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": body.subject,
                "role": body.role,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=12)).timestamp()),
            },
            jwt_secret,
            algorithm="HS256",
        )
        return {"access_token": token, "token_type": "bearer", "role": body.role}

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

                cur.execute(
                    """
                    SELECT link_id::text, src_node_id, dst_node_id, status, latency_ms, packet_loss_pct
                    FROM topology_links
                    WHERE valid_during @> %s::timestamptz AND recorded_during @> %s::timestamptz;
                    """,
                    (at_ts, known_at_ts),
                )
                observed_rows = cur.fetchall()
                observed_links = [
                    {
                        "link_id": row[0],
                        "src_node_id": row[1],
                        "dst_node_id": row[2],
                        "status": row[3],
                        "latency_ms": float(row[4] or 0.0),
                        "packet_loss_pct": float(row[5] or 0.0),
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
        
    @app.post("/paths/trace", status_code=status.HTTP_202_ACCEPTED)
    def start_trace(
        body: TraceRequest,
        request: Request,
        user: dict[str, Any] = Depends(require_role("operator")),
    ) -> dict[str, Any]:
        if body.src_node_id == body.dst_node_id:
            raise HTTPException(status_code=400, detail="src_node_id and dst_node_id must differ")

        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                statuses = _require_nodes(cur, [body.src_node_id, body.dst_node_id])
                if statuses[body.src_node_id] in ("offline", "revoked"):
                    raise HTTPException(
                        status_code=409,
                        detail=f"Source node {body.src_node_id} is {statuses[body.src_node_id]} and cannot run a trace",
                    )
                cur.execute("SELECT data_ip FROM nodes WHERE node_id = %s;", (body.dst_node_id,))
                dst_data_ip = (cur.fetchone() or [None])[0]
                cur.execute("SELECT src_node_id, dst_node_id, admin_cost FROM desired_topology_links;")
                declared = [DeclaredLink(r[0], r[1], float(r[2])) for r in cur.fetchall()]
                nominal_cost, nominal_path = graph_engine.shortest_path(
                    declared, body.src_node_id, body.dst_node_id
                )

                cur.execute(
                    """
                    SELECT epoch FROM leader_epoch
                    WHERE status = 'active'
                    ORDER BY epoch DESC LIMIT 1;
                    """
                )
                ep_row = cur.fetchone()
                active_epoch = int(ep_row[0]) if ep_row else 1

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
                    (trace_id, body.src_node_id, body.dst_node_id, __import__("json").dumps(initial_hops)),
                )
                cur.execute(
                    """
                    INSERT INTO node_commands (target_node_id, command_type, payload, leader_epoch, status)
                    VALUES (%s, 'run_trace', %s::jsonb, %s, 'queued');
                    """,
                    (
                        body.src_node_id,
                        __import__("json").dumps(
                            {
                                "trace_id": trace_id,
                                "dst_node_id": body.dst_node_id,
                                "dst_data_ip": dst_data_ip,
                            }
                        ),
                        active_epoch,
                    ),
                )
            _write_audit(
                conn,
                actor_id=str(user.get("sub", "unknown")),
                action_type="START_PATH_TRACE",
                target_entity=trace_id,
                details={"src": body.src_node_id, "dst": body.dst_node_id},
                ip_addr=_client_ip(request),
            )
            conn.commit()

        return {
            "trace_id": trace_id,
            "status": "PENDING",
            "src_node_id": body.src_node_id,
            "dst_node_id": body.dst_node_id,
            "nominal_path": nominal_path,
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

                cur.execute(
                    "UPDATE topology_links "
                    "SET status = 'down', "
                    "valid_during = tstzrange(lower(valid_during), NOW(), '[)') "
                    "WHERE (src_node_id = %s OR dst_node_id = %s) "
                    "AND upper_inf(valid_during);",
                    (node_id, node_id),
                )

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
        recommendation_id = _parse_uuid(recommendation_id, "Recommendation")
        with psycopg.connect(db_dsn) as conn:
            _require_leader(conn)
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE recommendations
                    SET status = %s, 
                    applied_at = CASE WHEN %s = 'applied' THEN NOW() ELSE applied_at END 
                    WHERE recommendation_id = %s::uuid 
                    RETURNING recommendation_id::text, status;
                    """,
                    (body.status, body.status, recommendation_id),
                )
                row = cur.fetchone()
                if row is None :
                    raise HTTPException(status_code=404, detail="Recommendation not found")

            _write_audit(
                conn,
                str(user.get("sub","unknonw")),
                "PATCH_RECOMMENDATION",
                recommendation_id,
                {"status": body.status},
                _client_ip(request),
            )
            conn.commit()

        return {"recommendation_id": row[0], "status": row[1]}

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
                    SELECT recommendation_id::text, alert_id::text, diagnosis, suggested_fix, status, created_at
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
                    fix = (
                        f"Verify DATA_NET interface/routing between {d.src_node_id} and {d.dst_node_id}"
                        if d.drift_type != "extra_observed"
                        else f"Add {d.src_node_id}->{d.dst_node_id} to desired topology or block unauthorized peer"
                    )
                    # Re-running Diagnose must not stack duplicates of a still-pending fix.
                    cur.execute(
                        """
                        INSERT INTO recommendations (diagnosis, suggested_fix, status)
                        SELECT %s, %s, 'pending'
                        WHERE NOT EXISTS (
                            SELECT 1 FROM recommendations
                            WHERE diagnosis = %s AND status = 'pending'
                        );
                        """,
                        (diag, fix, diag),
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
                    SELECT log_id::text, actor_id, action_type, target_entity, details, ip_address::text, created_at
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