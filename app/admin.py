# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Admin API router for runtime configuration management.

Sprint 83: Provides runtime-mutable trusted roots management with
fail-closed security model. All mutation endpoints require
VVP_ADMIN_TOKEN to be configured; returns 503 when not set.

Endpoints
---------
GET  /admin                     — Full configuration + metrics (JSON)
GET  /admin/trusted-roots       — List current trusted root AIDs
POST /admin/trusted-roots/add   — Add a trusted root AID
POST /admin/trusted-roots/remove — Remove a trusted root AID
POST /admin/trusted-roots/replace — Replace entire trusted roots set
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import app.core.config as _cfg
from app.core.config import (
    KNOWN_ROOT_LABELS,
    _trusted_roots_store,
    get_trusted_roots_current,
)

logger = logging.getLogger("vvp.admin")

router = APIRouter(tags=["admin"])

# Rate limiting: one mutation per 30 seconds
_MUTATION_RATE_LIMIT_SECONDS: float = 30.0
_LAST_MUTATION_TS: float = 0.0

_MUTATION_WARNING = (
    "Changes are in-memory and apply to this instance only. "
    "Update VVP_TRUSTED_ROOT_AIDS and restart all instances to persist."
)
_SCOPE = "single-instance only — changes are not propagated to other replicas"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _security_headers(response: JSONResponse) -> JSONResponse:
    response.headers["Cache-Control"] = "no-store, no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _build_trusted_roots_response(
    roots: frozenset[str],
    include_mutation_warning: bool = False,
) -> dict:
    empty = len(roots) == 0
    resp: dict = {
        "trusted_roots": sorted(roots),
        "count": len(roots),
        "env_source": "VVP_TRUSTED_ROOT_AIDS",
        "known_roots": {aid: KNOWN_ROOT_LABELS[aid] for aid in roots if aid in KNOWN_ROOT_LABELS},
        "empty_set_active": empty,
        "_scope": _SCOPE,
    }
    if empty:
        resp["_warning"] = (
            "No trusted roots configured — verifier is in fail-closed mode. "
            "All ACDC chain validation will fail."
        )
    if include_mutation_warning:
        resp["_mutation_warning"] = _MUTATION_WARNING
    return resp


def _check_same_origin(request: Request) -> None:
    from urllib.parse import urlparse
    origin = request.headers.get("origin")
    if origin:
        origin_host = urlparse(origin).netloc
        request_host = request.headers.get("host", "")
        if origin_host != request_host:
            raise HTTPException(status_code=403, detail="Cross-origin admin access not allowed")


def _require_read_auth(request: Request) -> None:
    _check_same_origin(request)
    token = _cfg.ADMIN_TOKEN
    if token is not None:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != token:
            raise HTTPException(status_code=401, detail="Unauthorized")


def _require_write_auth(request: Request) -> None:
    """Fail-closed: returns 503 when VVP_ADMIN_TOKEN is not configured.

    Sprint 88: Also enforces HTTPS when VVP_ADMIN_TOKEN is configured,
    unless TEL_ALLOW_HTTP=true (dev override).
    """
    _check_same_origin(request)
    token = _cfg.ADMIN_TOKEN
    if token is None:
        raise HTTPException(
            status_code=503,
            detail="Admin mutations require VVP_ADMIN_TOKEN to be configured",
        )
    # HTTPS enforcement: reject plaintext admin when token is configured
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto != "https" and not _cfg.TEL_ALLOW_HTTP:
        raise HTTPException(
            status_code=403,
            detail="Admin mutations require HTTPS",
        )
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    global _LAST_MUTATION_TS
    now = time.monotonic()
    if now - _LAST_MUTATION_TS < _MUTATION_RATE_LIMIT_SECONDS:
        remaining = int(_MUTATION_RATE_LIMIT_SECONDS - (now - _LAST_MUTATION_TS))
        raise HTTPException(
            status_code=503,
            detail=f"Rate limited — wait {remaining}s before next mutation",
        )
    _LAST_MUTATION_TS = now


def _validate_aid(aid: str) -> bool:
    """Basic syntactic validation of a KERI identifier prefix."""
    import re
    return bool(re.match(r'^[A-Z0-9][A-Za-z0-9_-]{43}$', aid))


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TrustedRootRequest(BaseModel):
    aid: str


class TrustedRootReplaceRequest(BaseModel):
    aids: list[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/trusted-roots")
async def get_trusted_roots(request: Request):
    """List current trusted root AIDs."""
    _require_read_auth(request)
    roots = get_trusted_roots_current()
    return _security_headers(JSONResponse(content=_build_trusted_roots_response(roots)))


@router.post("/trusted-roots/add")
async def add_trusted_root(req: TrustedRootRequest, request: Request):
    """Add a trusted root AID at runtime."""
    _require_write_auth(request)
    if not _validate_aid(req.aid):
        raise HTTPException(status_code=422, detail="Invalid AID: not a valid KERI identifier prefix")
    new_roots = await _trusted_roots_store.add(req.aid)
    _invalidate_cache()
    logger.info("admin: trusted root added: %s", req.aid)
    return _security_headers(
        JSONResponse(content=_build_trusted_roots_response(new_roots, include_mutation_warning=True))
    )


@router.post("/trusted-roots/remove")
async def remove_trusted_root(req: TrustedRootRequest, request: Request):
    """Remove a trusted root AID at runtime."""
    _require_write_auth(request)
    try:
        new_roots = await _trusted_roots_store.remove(req.aid)
    except KeyError:
        raise HTTPException(status_code=404, detail="AID not found in trusted roots")
    _invalidate_cache()
    logger.info("admin: trusted root removed: %s", req.aid)
    return _security_headers(
        JSONResponse(content=_build_trusted_roots_response(new_roots, include_mutation_warning=True))
    )


@router.post("/trusted-roots/replace")
async def replace_trusted_roots(req: TrustedRootReplaceRequest, request: Request):
    """Replace entire trusted roots set atomically. Empty list sets fail-closed state."""
    _require_write_auth(request)
    for i, aid in enumerate(req.aids):
        if not _validate_aid(aid):
            raise HTTPException(status_code=422, detail=f"Invalid AID at index {i}: not a valid KERI identifier prefix")
    new_roots = await _trusted_roots_store.replace(set(req.aids))
    _invalidate_cache()
    logger.info("admin: trusted roots replaced: count=%d", len(new_roots))
    return _security_headers(
        JSONResponse(content=_build_trusted_roots_response(new_roots, include_mutation_warning=True))
    )


def _invalidate_cache() -> None:
    """Clear verification cache after trusted roots mutation."""
    try:
        from app.vvp.verification_cache import reset_verification_cache
        reset_verification_cache()
    except Exception:
        pass
