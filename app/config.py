# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""VVP Verifier configuration.

Normative constants are fixed by spec. Configurable defaults may be
overridden via environment variables.
"""

import hashlib
import json
import os

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


TRUSTED_ROOT_AIDS: frozenset[str] = _parse_trusted_roots()

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
# CONFIG FINGERPRINT (for cache invalidation)
# =============================================================================

def config_fingerprint() -> str:
    """SHA256 of validation-affecting settings for cache invalidation."""
    data = json.dumps({
        "clock_skew": CLOCK_SKEW_SECONDS,
        "max_token_age": MAX_TOKEN_AGE_SECONDS,
        "max_validity": MAX_PASSPORT_VALIDITY_SECONDS,
        "trusted_roots": sorted(TRUSTED_ROOT_AIDS),
    }, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:16]
