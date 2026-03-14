# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""VVP Verifier configuration.

Normative constants are fixed by spec. Configurable defaults may be
overridden via environment variables.
"""

import asyncio as _asyncio
import hashlib
import json
import os
from typing import FrozenSet

# =============================================================================
# NORMATIVE CONSTANTS (fixed by spec)
# =============================================================================

MAX_IAT_DRIFT_SECONDS: int = 5
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"EdDSA"})
FORBIDDEN_ALGORITHMS: frozenset[str] = frozenset({
    "ES256", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "none",
})

# =============================================================================
# CONFIGURABLE DEFAULTS (per spec, may be overridden)
# =============================================================================

CLOCK_SKEW_SECONDS: int = int(os.getenv("VVP_CLOCK_SKEW_SECONDS", "300"))
MAX_TOKEN_AGE_SECONDS: int = int(os.getenv("VVP_MAX_TOKEN_AGE_SECONDS", "300"))
MAX_PASSPORT_VALIDITY_SECONDS: int = int(os.getenv("VVP_MAX_PASSPORT_VALIDITY_SECONDS", "300"))
ALLOW_PASSPORT_EXP_OMISSION: bool = os.getenv("VVP_ALLOW_PASSPORT_EXP_OMISSION", "false").lower() == "true"

# =============================================================================
# POLICY CONSTANTS
# =============================================================================

DOSSIER_FETCH_TIMEOUT_SECONDS: int = int(os.getenv("VVP_DOSSIER_FETCH_TIMEOUT", "5"))
DOSSIER_MAX_SIZE_BYTES: int = int(os.getenv("VVP_DOSSIER_MAX_SIZE_BYTES", "1048576"))

# Whether to allow HTTP (non-TLS) for external fetches. Dev/test only.
ALLOW_HTTP: bool = os.getenv("VVP_ALLOW_HTTP", "false").lower() == "true"

# Maximum response body size for all external HTTP fetches (default 10 MB).
FETCH_MAX_SIZE_BYTES: int = int(os.getenv("VVP_FETCH_MAX_SIZE_BYTES", "10485760"))

# Timeout for all external HTTP fetches (seconds).
FETCH_TIMEOUT_SECONDS: float = float(os.getenv("VVP_FETCH_TIMEOUT", "10.0"))

# TEL data source strategy: "witness-direct" (default) or "dossier-only".
TEL_SOURCE: str = os.getenv("VVP_TEL_SOURCE", "witness-direct")


def _parse_trusted_roots() -> frozenset[str]:
    env_value = os.getenv("VVP_TRUSTED_ROOT_AIDS", "")
    if env_value:
        return frozenset(aid.strip() for aid in env_value.split(",") if aid.strip())
    return frozenset({"EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2"})


# Advisory labels for well-known root AIDs (for operator UX only).
KNOWN_ROOT_LABELS: dict[str, str] = {
    "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2": "GLEIF Root (vLEI chain)",
}

# Admin token for mutation endpoints. None = mutations disabled (fail-closed).
ADMIN_TOKEN: str | None = os.getenv("VVP_ADMIN_TOKEN")


class _TrustedRootsStore:
    """Thread-safe, asyncio-aware mutable store for trusted root AIDs.

    Provides request-scoped immutable snapshots via ``snapshot()`` so that
    in-flight verifications are never affected by concurrent admin mutations.
    """

    def __init__(self, initial: frozenset[str]) -> None:
        self._roots: set[str] = set(initial)
        self._lock: _asyncio.Lock = _asyncio.Lock()

    async def snapshot(self) -> frozenset[str]:
        """Return an immutable snapshot for use within a single request."""
        async with self._lock:
            return frozenset(self._roots)

    async def add(self, aid: str) -> frozenset[str]:
        """Add an AID (idempotent). Returns new snapshot."""
        async with self._lock:
            self._roots.add(aid)
            return frozenset(self._roots)

    async def remove(self, aid: str) -> frozenset[str]:
        """Remove an AID. Raises KeyError if not present. Returns new snapshot."""
        async with self._lock:
            if aid not in self._roots:
                raise KeyError(aid)
            self._roots.discard(aid)
            return frozenset(self._roots)

    async def replace(self, new_roots: set[str]) -> frozenset[str]:
        """Atomically replace the entire set. Returns new snapshot."""
        async with self._lock:
            self._roots = set(new_roots)
            return frozenset(self._roots)

    def current_sync(self) -> frozenset[str]:
        """Synchronous snapshot for non-async display paths (UI only)."""
        return frozenset(self._roots)


_trusted_roots_store = _TrustedRootsStore(_parse_trusted_roots())


async def get_trusted_roots_snapshot() -> frozenset[str]:
    """Return an immutable snapshot for use in security-critical verification paths."""
    return await _trusted_roots_store.snapshot()


def get_trusted_roots_current() -> frozenset[str]:
    """Return the current trusted roots set (sync, for display paths only)."""
    return _trusted_roots_store.current_sync()

# =============================================================================
# NETWORK
# =============================================================================

HTTP_HOST: str = os.getenv("VVP_HTTP_HOST", "0.0.0.0")
HTTP_PORT: int = int(os.getenv("VVP_HTTP_PORT", "8000"))
SIP_HOST: str = os.getenv("VVP_SIP_HOST", "0.0.0.0")
SIP_PORT: int = int(os.getenv("VVP_SIP_PORT", "5060"))

# =============================================================================
# CACHING
# =============================================================================

DOSSIER_CACHE_TTL_SECONDS: float = float(os.getenv("VVP_DOSSIER_CACHE_TTL", "300.0"))
DOSSIER_CACHE_MAX_ENTRIES: int = int(os.getenv("VVP_DOSSIER_CACHE_MAX_ENTRIES", "100"))
VERIFICATION_CACHE_ENABLED: bool = os.getenv("VVP_VERIFICATION_CACHE_ENABLED", "true").lower() == "true"
VERIFICATION_CACHE_MAX_ENTRIES: int = int(os.getenv("VVP_VERIFICATION_CACHE_MAX_ENTRIES", "200"))
VERIFICATION_CACHE_TTL: float = float(os.getenv("VVP_VERIFICATION_CACHE_TTL", "3600"))
REVOCATION_RECHECK_INTERVAL: float = float(os.getenv("VVP_REVOCATION_RECHECK_INTERVAL", "300"))
REVOCATION_CHECK_CONCURRENCY: int = int(os.getenv("VVP_REVOCATION_CHECK_CONCURRENCY", "1"))

# =============================================================================
# WITNESS CONFIGURATION
# =============================================================================


def _parse_witness_urls() -> list[str]:
    env = os.getenv("VVP_WITNESS_URLS", "")
    if env:
        return [u.strip() for u in env.split(",") if u.strip()]
    return [
        "http://witness4.stage.provenant.net:5631",
        "http://witness5.stage.provenant.net:5631",
        "http://witness6.stage.provenant.net:5631",
    ]


WITNESS_URLS: list[str] = _parse_witness_urls()
TEL_CLIENT_TIMEOUT_SECONDS: float = float(os.getenv("VVP_TEL_CLIENT_TIMEOUT", "10.0"))

# =============================================================================
# LOGGING
# =============================================================================

LOG_LEVEL: str = os.getenv("VVP_LOG_LEVEL", "INFO")
LOG_FORMAT: str = os.getenv("VVP_LOG_FORMAT", "json")

# =============================================================================
# TIER 2 KEL RESOLUTION (Sprint 85)
# =============================================================================

# Feature gate: set to true to enable Tier 2 (transferable AID) verification.
VVP_TIER2_KEL_ENABLED: bool = os.getenv("VVP_TIER2_KEL_ENABLED", "true").lower() == "true"

# Key state cache freshness window (seconds). Unbounded cache entries older
# than this are considered stale and force an OOBI re-fetch.
VVP_KEY_STATE_FRESHNESS_SECONDS: float = float(
    os.getenv("VVP_KEY_STATE_FRESHNESS_SECONDS", "120.0")
)

# OOBI fetch timeout (seconds). Passed to safe_get() for OOBI requests.
VVP_OOBI_TIMEOUT_SECONDS: float = float(
    os.getenv("VVP_OOBI_TIMEOUT_SECONDS", "5.0")
)

# Admin endpoints enabled (fail-closed: disabled by default).
VVP_ADMIN_ENABLED: bool = os.getenv("VVP_ADMIN_ENABLED", "false").lower() == "true"


def _parse_allowed_fetch_origins() -> frozenset[str]:
    """Parse VVP_ALLOWED_FETCH_ORIGINS into a frozenset of 'host:port' entries.

    Empty default = fail-closed (all fetches rejected until configured).
    """
    env = os.getenv("VVP_ALLOWED_FETCH_ORIGINS", "")
    if not env.strip():
        return frozenset()
    return frozenset(o.strip().lower() for o in env.split(",") if o.strip())


# Destination allowlist for outbound fetches (OOBI, dossier).
# Format: comma-separated "host:port" entries.
# Empty = fail-closed (all fetches rejected).
VVP_ALLOWED_FETCH_ORIGINS: frozenset[str] = _parse_allowed_fetch_origins()


# =============================================================================
# CONFIG FINGERPRINT (for cache invalidation)
# =============================================================================

def config_fingerprint(trusted_roots: FrozenSet[str] | None = None) -> str:
    """SHA256 of validation-affecting settings for cache invalidation.

    Pass ``trusted_roots`` explicitly from a request-scoped snapshot to ensure
    cache entries are bound to the exact root set used during verification.
    Falls back to the current store value when called from legacy sync paths.
    """
    roots = trusted_roots if trusted_roots is not None else get_trusted_roots_current()
    data = json.dumps({
        "clock_skew": CLOCK_SKEW_SECONDS,
        "max_token_age": MAX_TOKEN_AGE_SECONDS,
        "max_validity": MAX_PASSPORT_VALIDITY_SECONDS,
        "trusted_roots": sorted(roots),
    }, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:16]
