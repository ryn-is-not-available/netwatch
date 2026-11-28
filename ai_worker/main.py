"""Read-only AI diagnosis service (internal; called by the control plane).

Sandboxing:
- connects to TimescaleDB as `netwatch_ai`, a role with SELECT on a handful of columns and
  default_transaction_read_only, so it cannot change anything even if compromised;
- runs as a non-root user on a read-only filesystem with all capabilities dropped (compose);
- answers only requests carrying the shared AI_WORKER_TOKEN (nodes share MGMT_NET with it);
- returns verified findings; the control plane decides what to store.
"""
import hmac
import logging
import os
import threading
from typing import Any

import anthropic
from fastapi import FastAPI, Header, HTTPException
import psycopg

from ai_worker.diagnose import DiagnosisError, MODEL, ask_claude, credentials_configured
from ai_worker.evidence import build_evidence, verify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("netwatch.ai_worker")

app = FastAPI(title="NetWatch AI diagnostic worker", version="1.0.0")
_one_at_a_time = threading.Lock()  # bounds API spend: concurrent requests are refused, not queued


def _db_dsn() -> str:
    dsn = (os.environ.get("AI_DB_DSN") or "").strip()
    if not dsn:
        raise HTTPException(status_code=500, detail="AI_DB_DSN is not configured")
    return dsn


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "model": MODEL, "credentials": credentials_configured()}


@app.post("/diagnose")
def diagnose(x_ai_worker_token: str = Header(default="")) -> dict[str, Any]:
    expected = os.environ.get("AI_WORKER_TOKEN", "")
    if not expected or not hmac.compare_digest(x_ai_worker_token, expected):
        raise HTTPException(status_code=401, detail="Invalid worker token")
    if not credentials_configured():
        raise HTTPException(
            status_code=503,
            detail="AI diagnosis is not configured: set ANTHROPIC_API_KEY for the ai-worker service (see .env.example)",
        )
    if not _one_at_a_time.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A diagnosis is already running; try again shortly")
    try:
        with psycopg.connect(_db_dsn()) as conn:
            ev = build_evidence(conn)
        try:
            report, meta = ask_claude(anthropic.Anthropic(), ev)
        except DiagnosisError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except anthropic.AuthenticationError as exc:
            raise HTTPException(status_code=503, detail="The Anthropic API rejected the configured credentials") from exc
        except anthropic.RateLimitError as exc:
            raise HTTPException(status_code=429, detail="Anthropic API rate limit reached; try again later") from exc
        except anthropic.APIStatusError as exc:
            raise HTTPException(status_code=502, detail=f"Anthropic API error ({exc.status_code})") from exc
        except anthropic.APIConnectionError as exc:
            raise HTTPException(status_code=502, detail="Could not reach the Anthropic API") from exc

        findings, notes = verify(report, ev)
        logger.info(
            "Diagnosis: %d finding(s) accepted, %d note(s), %d evidence items, %s in/%s out tokens",
            len(findings), len(notes), len(ev.items), meta["input_tokens"], meta["output_tokens"],
        )
        return {
            "summary": str(report.get("summary", ""))[:2000],
            "findings": findings,
            "verification_notes": notes,
            "evidence_items": len(ev.items),
            **meta,
        }
    finally:
        _one_at_a_time.release()
