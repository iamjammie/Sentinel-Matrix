#!/usr/bin/env python3
"""
SENTINEL MATRIX — Local SIEM Audit Agent
========================================
A small, read-only FastAPI service that runs INSIDE the enterprise network and brokers
SIEM REST APIs on behalf of the Sentinel Matrix standalone HTML application.

Why an agent?
  The standalone HTML app is offline-first and cannot (and should not) talk directly to
  enterprise SIEM APIs from a browser. This agent keeps credentials inside the network,
  enforces read-only access, and returns normalised data to the local app only.

Security posture (see also docs/security-hardening.md):
  * Binds to 127.0.0.1 by default. Never expose to the LAN without deliberate config.
  * CORS is restricted to local origins (file:// shows up as 'null', plus localhost).
  * READ-ONLY: only GET-style SIEM calls are made. No rule/offense mutation endpoints.
  * Credentials are taken per-request or from an OS-protected store; never logged.
  * No shell execution, no arbitrary proxy, no eval.

Usage:
  pip install -r requirements.txt
  python sentinel_matrix_agent.py --host 127.0.0.1 --port 8787
"""
from __future__ import annotations
import os, sys, time, json, logging, argparse, ipaddress
from typing import Any, Optional
from contextlib import asynccontextmanager

try:
    import httpx
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, field_validator
    import uvicorn
except ImportError as e:  # pragma: no cover
    print("Missing dependency: %s\nRun: pip install -r requirements.txt" % e, file=sys.stderr)
    sys.exit(1)

from siem_adapters import get_adapter, ADAPTERS, SiemError
from credential_store import CredentialStore

VERSION = "1.0.0"
LOG = logging.getLogger("sentinel-agent")

# ------------------------------- Redaction-aware logging -------------------------------
class RedactFilter(logging.Filter):
    SECRETS = ("token", "password", "secret", "authorization", "sec", "api_key", "apikey")
    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.getMessage())
        low = msg.lower()
        for s in self.SECRETS:
            if s in low:
                record.msg = "[redacted log line containing a potential secret]"
                record.args = ()
                break
        return True

def configure_logging(verbose: bool) -> None:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    h.addFilter(RedactFilter())
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[h])

# ------------------------------- Request models -------------------------------
class ConnectRequest(BaseModel):
    platform: str = Field(..., description="qradar | splunk | sentinel | elastic")
    host: Optional[str] = ""
    ip: Optional[str] = ""
    port: int = 443
    api_version: Optional[str] = ""
    auth_method: str = "token"
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    tls_verify: bool = True
    read_only: bool = True

    @field_validator("platform")
    @classmethod
    def _plat(cls, v: str) -> str:
        if v not in ADAPTERS:
            raise ValueError("unsupported platform %r; supported: %s" % (v, ", ".join(ADAPTERS)))
        return v

    def target(self) -> str:
        base = (self.host or self.ip or "").strip()
        if not base:
            raise ValueError("host or ip is required")
        return base

class AuditRequest(ConnectRequest):
    include: list[str] = Field(default_factory=lambda: ["rules", "log_sources", "offenses", "alerts"])
    max_rules: int = 5000
    max_offenses: int = 2000

# ------------------------------- App -------------------------------
STATE: dict[str, Any] = {"started": time.time(), "cred_store": None, "config": {}}

@asynccontextmanager
async def lifespan(app: FastAPI):
    LOG.info("Sentinel Matrix audit agent v%s starting (read-only)", VERSION)
    STATE["cred_store"] = CredentialStore(STATE["config"].get("cred_path"))
    yield
    LOG.info("agent shutting down")

app = FastAPI(title="Sentinel Matrix Audit Agent", version=VERSION, lifespan=lifespan,
             docs_url=None, redoc_url=None, openapi_url=None)  # no public API docs surface

# Restrict origins: file:// pages report Origin 'null'; also allow localhost dev servers.
ALLOWED_ORIGINS = ["null", "http://localhost", "http://127.0.0.1",
                   "http://localhost:8787", "http://127.0.0.1:8787"]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

@app.middleware("http")
async def _bind_guard(request: Request, call_next):
    # Defense in depth: reject non-local clients even if mistakenly bound to 0.0.0.0,
    # unless explicitly allowed via SENTINEL_ALLOW_REMOTE.
    if not STATE["config"].get("allow_remote"):
        client = request.client.host if request.client else "?"
        try:
            if not ipaddress.ip_address(client).is_loopback:
                return JSONResponse(status_code=403, content={"error": "remote clients are not permitted (localhost only)"})
        except ValueError:
            return JSONResponse(status_code=403, content={"error": "unresolved client address"})
    return await call_next(request)

def _resolve_secret(req: ConnectRequest) -> str:
    if req.token:
        return req.token
    store: CredentialStore = STATE["cred_store"]
    saved = store.get(req.platform, req.target())
    if saved:
        return saved
    raise HTTPException(status_code=400, detail="no credential provided and none stored for this target")

# ------------------------------- Endpoints -------------------------------
@app.get("/health")
async def health():
    return {"status": "healthy", "version": VERSION, "uptime_s": round(time.time() - STATE["started"]),
            "read_only": True, "supported_platforms": list(ADAPTERS)}

@app.post("/api/siem/connect")
async def connect(req: ConnectRequest):
    try:
        secret = _resolve_secret(req)
        adapter = get_adapter(req.platform, req.target(), req.port, secret,
                              tls_verify=req.tls_verify, api_version=req.api_version,
                              auth_method=req.auth_method, username=req.username)
        info = await adapter.connect()
        return {"status": "connected", "platform": req.platform, **info}
    except SiemError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:  # pragma: no cover
        LOG.exception("connect failed")
        raise HTTPException(status_code=500, detail="connect failed: %s" % type(e).__name__)

@app.post("/api/siem/audit")
async def audit(req: AuditRequest):
    secret = _resolve_secret(req)
    adapter = get_adapter(req.platform, req.target(), req.port, secret,
                          tls_verify=req.tls_verify, api_version=req.api_version,
                          auth_method=req.auth_method, username=req.username)
    out: dict[str, Any] = {"platform": req.platform}
    try:
        info = await adapter.connect()
        out.update({"api_version": info.get("api_version"), "deployment": info.get("deployment"),
                    "capabilities": info.get("capabilities", {})})
        if "rules" in req.include:
            out["rules"] = await adapter.get_rules(limit=req.max_rules)
        if "log_sources" in req.include:
            out["log_sources"] = await adapter.get_log_sources()
        if "offenses" in req.include:
            out["offenses"] = await adapter.get_offenses(limit=req.max_offenses)
        if "alerts" in req.include:
            out["alerts"] = await adapter.get_alerts()
    except SiemError as e:
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        await adapter.close()
    out["retrieved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return out

@app.post("/api/siem/rules")
async def get_rules(req: ConnectRequest):
    return await _single(req, "get_rules")

@app.post("/api/siem/offenses")
async def get_offenses(req: ConnectRequest):
    return await _single(req, "get_offenses")

@app.post("/api/siem/logsources")
async def get_logsources(req: ConnectRequest):
    return await _single(req, "get_log_sources")

async def _single(req: ConnectRequest, method: str):
    secret = _resolve_secret(req)
    adapter = get_adapter(req.platform, req.target(), req.port, secret,
                          tls_verify=req.tls_verify, api_version=req.api_version,
                          auth_method=req.auth_method, username=req.username)
    try:
        await adapter.connect()
        data = await getattr(adapter, method)()
        return {"platform": req.platform, "data": data}
    except SiemError as e:
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        await adapter.close()

# ----- credential management (optional, OS-protected) -----
class CredSave(BaseModel):
    platform: str
    target: str
    token: str

@app.post("/api/creds/save")
async def creds_save(c: CredSave):
    STATE["cred_store"].save(c.platform, c.target, c.token)
    return {"status": "saved", "platform": c.platform, "target": c.target}

@app.post("/api/creds/remove")
async def creds_remove(c: CredSave):
    STATE["cred_store"].remove(c.platform, c.target)
    return {"status": "removed"}

@app.get("/api/siem/audit/status")
async def audit_status():
    return {"status": "idle", "note": "audits are synchronous in this build; POST /api/siem/audit to run one"}

@app.get("/api/siem/audit/results")
async def audit_results():
    return {"note": "results are returned directly by POST /api/siem/audit; nothing is cached server-side by default"}

# ------------------------------- Entrypoint -------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Sentinel Matrix local SIEM audit agent (read-only)")
    p.add_argument("--host", default=os.environ.get("SENTINEL_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SENTINEL_PORT", "8787")))
    p.add_argument("--config", default=os.environ.get("SENTINEL_CONFIG", "config.yaml"))
    p.add_argument("--allow-remote", action="store_true", help="DANGEROUS: allow non-localhost clients")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    configure_logging(args.verbose)
    cfg = {}
    if os.path.exists(args.config):
        try:
            import yaml
            with open(args.config) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as e:
            LOG.warning("could not read config %s: %s", args.config, e)
    STATE["config"] = {"allow_remote": args.allow_remote or cfg.get("allow_remote", False),
                       "cred_path": cfg.get("cred_path")}
    if args.host not in ("127.0.0.1", "localhost", "::1") and not STATE["config"]["allow_remote"]:
        LOG.warning("Binding to %s but remote clients are blocked by the loopback guard. "
                    "Use --allow-remote only if you understand the risk.", args.host)
    LOG.info("listening on http://%s:%d  (read-only, platforms: %s)", args.host, args.port, ", ".join(ADAPTERS))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
