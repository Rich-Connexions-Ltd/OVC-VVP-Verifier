# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""FastAPI application with integrated SIP UDP transport.

This module defines the VVP Verifier's HTTP API and manages the
lifecycle of both the HTTP server and the SIP UDP transport.  The
application provides:

**HTTP Endpoints**

* ``POST /verify`` — Accept a :class:`VerifyRequest` body containing
  a PASSporT JWT (and optional VVP-Identity / dossier URL overrides),
  run the 9-phase verification pipeline, and return a
  :class:`VerifyResponse` with the claim tree, errors, and metadata.

* ``GET /healthz`` — Lightweight health-check endpoint returning
  service status, capabilities, and cache statistics.  Suitable for
  container orchestrator liveness/readiness probes.

* ``GET /`` — Serve the web UI via Jinja2 template rendering.  The
  template directory is ``app/templates/``.

**SIP Transport**

On startup, the application binds a UDP socket on the configured
``SIP_HOST:SIP_PORT`` and begins listening for SIP messages.  Inbound
INVITE requests carrying PASSporT (Identity) and VVP-Identity
(P-VVP-Identity) headers are processed through the same verification
pipeline, and the result is returned as a 302 redirect with X-VVP-*
headers that the PBX uses for rich call data display.

**Background Services**

* **Revocation checker** — A background asyncio task periodically
  re-checks the revocation status of credentials cached in the
  verification result cache, ensuring stale revocation data is
  refreshed without blocking request processing.

**Logging**

Structured JSON logging is configured at startup using the
``LOG_LEVEL`` setting.  All request/response cycles are logged with
correlation IDs for traceability.

**CORS**

Cross-Origin Resource Sharing middleware is configured permissively
(all origins, methods, and headers) to support standalone deployment
where the web UI may be served from a different origin.

Architecture
------------
The async lifespan context manager handles ordered startup and shutdown
of all subsystems:

1. Start background revocation checker.
2. Bind SIP UDP transport.
3. Yield (application serves requests).
4. Stop SIP transport.
5. Stop revocation checker.

References
----------
- VVP Verifier Specification v1.5 §4.1 — API request format
- VVP Verifier Specification v1.5 §4.3 — API response format
- FastAPI documentation — Lifespan events
"""

from __future__ import annotations

import logging
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.core.config import HTTP_HOST, HTTP_PORT, SIP_HOST, SIP_PORT, LOG_LEVEL, VVP_ADMIN_ENABLED, get_trusted_roots_current
from app.vvp.api_models import CAPABILITIES, VerifyRequest, VerifyResponse
from app.vvp.verify import verify
from app.vvp.verification_cache import get_verification_cache
from app.vvp.revocation_checker import get_revocation_checker
from app.sip.transport import SIPTransport
from app.sip.handler import handle_invite
from app.admin import router as admin_router


# ======================================================================
# Structured JSON logging
# ======================================================================


class _JSONFormatter(logging.Formatter):
    """Structured JSON log formatter.

    Produces one JSON object per log line with fields:

    * ``timestamp`` — ISO 8601 UTC timestamp.
    * ``level`` — Log level name (INFO, WARNING, ERROR, etc.).
    * ``logger`` — Logger name.
    * ``message`` — The formatted log message.
    * ``module`` — Source module name.
    * ``funcName`` — Source function name.

    If the log record carries an exception, it is serialized as an
    ``exception`` field containing the formatted traceback string.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
        }
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def _configure_logging() -> None:
    """Configure structured JSON logging for the application.

    Sets up the root logger with a single stream handler writing
    JSON-formatted lines to stdout.  The log level is controlled by
    the ``LOG_LEVEL`` configuration setting.

    All existing handlers are removed first to prevent duplicate output
    when running under uvicorn or other frameworks that configure their
    own handlers.
    """
    root = logging.getLogger()

    # Remove existing handlers to avoid duplicates.
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())

    root.addHandler(handler)
    root.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    # Suppress noisy third-party loggers.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


# ======================================================================
# SIP transport singleton
# ======================================================================

_sip_transport: SIPTransport | None = None


# ======================================================================
# Application lifespan
# ======================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Async lifespan context manager for ordered startup and shutdown.

    Startup sequence:

    1. Configure structured logging.
    2. Start the background revocation checker.
    3. Bind the SIP UDP transport on ``SIP_HOST:SIP_PORT``.

    Shutdown sequence (reverse order):

    4. Stop the SIP UDP transport.
    5. Stop the background revocation checker.

    The ``yield`` between startup and shutdown is where the application
    serves HTTP requests.

    Yields
    ------
    None
        Control returns to FastAPI to begin serving requests.
    """
    global _sip_transport

    logger = logging.getLogger("vvp.main")

    # --- Startup ---
    _configure_logging()
    logger.info(
        "VVP Verifier starting: HTTP=%s:%d, SIP=%s:%d, log_level=%s",
        HTTP_HOST, HTTP_PORT, SIP_HOST, SIP_PORT, LOG_LEVEL,
    )

    # Start background revocation checker.
    revocation_checker = get_revocation_checker()
    await revocation_checker.start()
    logger.info("Background revocation checker started")

    # Start SIP UDP transport.
    _sip_transport = SIPTransport(SIP_HOST, SIP_PORT, handle_invite)
    try:
        await _sip_transport.start()
        logger.info("SIP transport listening on %s:%d", SIP_HOST, SIP_PORT)
    except OSError as exc:
        logger.error(
            "Failed to bind SIP transport on %s:%d: %s",
            SIP_HOST, SIP_PORT, exc,
        )
        _sip_transport = None

    yield

    # --- Shutdown ---
    logger.info("VVP Verifier shutting down")

    if _sip_transport is not None:
        await _sip_transport.stop()
        _sip_transport = None
        logger.info("SIP transport stopped")

    await revocation_checker.stop()
    logger.info("Background revocation checker stopped")

    logger.info("VVP Verifier shutdown complete")


# ======================================================================
# FastAPI application
# ======================================================================

app = FastAPI(
    title="VVP Verifier",
    description=(
        "Verified Voice Protocol (VVP) verification service. "
        "Validates PASSporT JWTs, ACDC credential chains, and "
        "caller authorization for telephony brand authentication."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# --- CORS middleware ---
# Permissive for standalone deployment; restrict origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Vary header middleware (Sprint 88) ---
@app.middleware("http")
async def admin_headers(request: Request, call_next):
    """Add Vary and security headers to /admin/* responses."""
    resp = await call_next(request)
    if request.url.path.startswith("/admin"):
        resp.headers["Vary"] = "Origin, Authorization"
    return resp

# --- Templates ---
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# --- Admin router (Sprint 83: trusted roots management) ---
# Gated behind VVP_ADMIN_ENABLED (fail-closed: disabled by default).
if VVP_ADMIN_ENABLED:
    app.include_router(admin_router, prefix="/admin")

# Module-level logger (configured properly after lifespan runs).
logger = logging.getLogger("vvp.main")


# ======================================================================
# Endpoints
# ======================================================================


@app.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Verify a PASSporT JWT",
    description=(
        "Submit a PASSporT JWT (and optional VVP-Identity header / "
        "dossier URL) for verification through the 9-phase pipeline. "
        "Returns a structured claim tree with overall status, errors, "
        "and metadata including brand information and signer AID."
    ),
    tags=["verification"],
)
async def verify_endpoint(request: VerifyRequest) -> VerifyResponse:
    """Execute the VVP verification pipeline.

    Accepts a JSON body conforming to :class:`VerifyRequest` and
    returns a :class:`VerifyResponse` with the full verification
    result including the hierarchical claim tree.

    Parameters
    ----------
    request : VerifyRequest
        The verification request body.  Required field: ``passport_jwt``.
        Optional fields: ``vvp_identity``, ``dossier_url``.

    Returns
    -------
    VerifyResponse
        The verification result.
    """
    logger.info("POST /verify received")

    try:
        response = await verify(request)
    except Exception:
        logger.exception("Unhandled exception in verification pipeline")
        return VerifyResponse(
            request_id="error",
            overall_status="INVALID",
            errors=[{
                "code": "INTERNAL_ERROR",
                "message": "Unexpected server error during verification",
                "recoverable": True,
            }],
            capabilities=dict(CAPABILITIES),
        )

    logger.info(
        "POST /verify complete: request_id=%s status=%s cache_hit=%s",
        response.request_id,
        response.overall_status,
        response.cache_hit,
    )
    return response


@app.get(
    "/healthz",
    summary="Health check",
    description=(
        "Returns service health status, capabilities map, and cache "
        "statistics.  Suitable for container orchestrator probes."
    ),
    tags=["health"],
)
async def healthz() -> JSONResponse:
    """Health check endpoint.

    Returns a JSON object with:

    * ``status`` — Always ``"ok"`` if the service is running.
    * ``capabilities`` — The capabilities map from the VVP spec.
    * ``cache`` — Verification result cache statistics (hits, misses,
      size, etc.).
    * ``sip`` — SIP transport status (running/stopped and bound address).

    Returns
    -------
    JSONResponse
        Health check response with 200 status code.
    """
    cache = get_verification_cache()

    sip_status: Dict[str, Any] = {"running": False}
    if _sip_transport is not None and _sip_transport.is_running:
        sip_status["running"] = True
        addr = _sip_transport.local_address
        if addr:
            sip_status["address"] = f"{addr[0]}:{addr[1]}"

    return JSONResponse(
        content={
            "status": "ok",
            "capabilities": dict(CAPABILITIES),
            "cache": cache.stats(),
            "sip": sip_status,
        },
        status_code=200,
    )


@app.get(
    "/",
    response_class=HTMLResponse,
    summary="Web UI",
    description="Serve the VVP Verifier web interface.",
    tags=["ui"],
)
async def index(request: Request) -> HTMLResponse:
    """Serve the VVP Verifier web UI.

    Renders the ``index.html`` Jinja2 template from the
    ``app/templates/`` directory.  If the template directory or file
    does not exist, returns a minimal fallback HTML page.

    Parameters
    ----------
    request : Request
        The inbound HTTP request (required by Jinja2 for URL generation).

    Returns
    -------
    HTMLResponse
        The rendered HTML page.
    """
    template_path = _TEMPLATES_DIR / "index.html"
    if template_path.exists():
        return templates.TemplateResponse("index.html", {"request": request})

    # Fallback: return a minimal status page when no template is deployed.
    cache = get_verification_cache()
    cache_stats = cache.stats()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VVP Verifier</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                         Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 640px;
            margin: 2rem auto;
            padding: 0 1rem;
            color: #333;
            line-height: 1.6;
        }}
        h1 {{ color: #1a73e8; }}
        .status {{ color: #0d904f; font-weight: bold; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 1rem 0;
        }}
        th, td {{
            text-align: left;
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{ background: #f8f9fa; }}
        code {{
            background: #f1f3f4;
            padding: 0.15rem 0.35rem;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .section {{ margin: 1.5rem 0; }}
    </style>
</head>
<body>
    <h1>VVP Verifier</h1>
    <p>Verified Voice Protocol verification service.</p>
    <p>Status: <span class="status">Running</span></p>

    <div class="section">
        <h2>API</h2>
        <table>
            <tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>
            <tr>
                <td><code>/verify</code></td>
                <td>POST</td>
                <td>Verify a PASSporT JWT</td>
            </tr>
            <tr>
                <td><code>/healthz</code></td>
                <td>GET</td>
                <td>Health check</td>
            </tr>
            <tr>
                <td><code>/docs</code></td>
                <td>GET</td>
                <td>OpenAPI documentation</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2>Cache</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Size</td><td>{cache_stats.get('size', 0)}</td></tr>
            <tr><td>Hits</td><td>{cache_stats.get('hits', 0)}</td></tr>
            <tr><td>Misses</td><td>{cache_stats.get('misses', 0)}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>SIP Transport</h2>
        <p>Listening on <code>{SIP_HOST}:{SIP_PORT}</code></p>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get(
    "/admin/ui",
    response_class=HTMLResponse,
    summary="Admin UI",
    description="Serve the VVP Verifier admin dashboard.",
    tags=["admin"],
)
async def admin_ui(request: Request) -> HTMLResponse:
    """Serve the admin dashboard page."""
    if not VVP_ADMIN_ENABLED:
        return HTMLResponse(content="<h1>Admin UI not available</h1>", status_code=404)
    template_path = _TEMPLATES_DIR / "admin.html"
    if template_path.exists():
        roots = get_trusted_roots_current()
        from app.core.config import KNOWN_ROOT_LABELS
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "trusted_roots": sorted(roots),
                "known_root_labels": KNOWN_ROOT_LABELS,
                "empty_set_active": len(roots) == 0,
            },
        )
    return HTMLResponse(content="<h1>Admin UI not available</h1>", status_code=404)


# ======================================================================
# Application runner (for direct invocation)
# ======================================================================


def main() -> None:
    """Run the VVP Verifier using uvicorn.

    This entry point is intended for direct invocation during
    development::

        python -m app.main

    For production deployments, use uvicorn directly::

        uvicorn app.main:app --host 0.0.0.0 --port 8000
    """
    import uvicorn

    _configure_logging()

    logger.info(
        "Starting VVP Verifier: HTTP=%s:%d, SIP=%s:%d",
        HTTP_HOST, HTTP_PORT, SIP_HOST, SIP_PORT,
    )

    uvicorn.run(
        "app.main:app",
        host=HTTP_HOST,
        port=HTTP_PORT,
        log_level=LOG_LEVEL.lower(),
        reload=False,
    )


if __name__ == "__main__":
    main()
