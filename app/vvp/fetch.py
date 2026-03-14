# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""SSRF-safe HTTP fetch layer for all external URL requests.

All external HTTP/HTTPS requests in the VVP Verifier MUST use
:func:`safe_get` rather than constructing their own httpx clients.
This centralises SSRF protection, size limits, and timeout policy.

SSRF mitigations applied
------------------------
- HTTPS-only by default (configurable via :data:`ALLOW_HTTP`)
- No proxy injection (``trust_env=False``)
- Hard 10 MB response body cap
- ``follow_redirects=False`` — redirects are never followed

References
----------
- OWASP SSRF Prevention Cheat Sheet
- VVP Verifier Specification §7.2 — Dossier fetch requirements
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.config import (
    ALLOW_HTTP,
    FETCH_MAX_SIZE_BYTES,
    FETCH_TIMEOUT_SECONDS,
    VVP_ALLOWED_FETCH_ORIGINS,
)

logger = logging.getLogger(__name__)

__all__ = [
    "FetchError",
    "authorize_destination",
    "safe_get",
    "validate_url",
]


class FetchError(Exception):
    """Raised when a safe_get() call fails."""


def validate_url(url: str) -> None:
    """Validate that *url* is safe to fetch.

    Raises :class:`FetchError` if the URL fails policy checks.

    Policy
    ------
    - Must be a non-empty string.
    - Scheme must be ``https`` (or ``http`` if ``ALLOW_HTTP`` is set).
    - Must have a non-empty host.
    - No userinfo component (prevents credential injection).
    """
    if not url or not url.strip():
        raise FetchError("URL is empty")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"Unsupported URL scheme: {parsed.scheme!r} — must be http/https")

    if parsed.scheme == "http" and not ALLOW_HTTP:
        raise FetchError(
            f"HTTP URLs are not permitted (ALLOW_HTTP=false): {url}"
        )

    if not parsed.hostname:
        raise FetchError(f"URL has no host: {url}")

    if parsed.username or parsed.password:
        raise FetchError(f"URL must not contain credentials: {url}")


def authorize_destination(url: str) -> None:
    """Reject URLs whose origin is not in the operator-controlled allowlist.

    This is NOT an SSRF check — it is destination authorization. SSRF
    protection is handled separately by ``validate_url()`` and the
    transport layer.

    Raises :class:`FetchError` if origin is not in
    ``VVP_ALLOWED_FETCH_ORIGINS``.

    Normalization:
    - Hostname is lowercased
    - Port defaults to 443 for https, 80 for http (scheme-default)
    - Comparison is exact ``host:port`` match after normalization
    """
    if not VVP_ALLOWED_FETCH_ORIGINS:
        raise FetchError("No allowed fetch origins configured (fail-closed)")

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = f"{hostname}:{port}"

    if origin not in VVP_ALLOWED_FETCH_ORIGINS:
        raise FetchError(f"Destination not authorized: {origin}")


async def safe_get(
    url: str,
    *,
    timeout: Optional[float] = None,
    max_size: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> bytes:
    """Fetch *url* via HTTPS GET with SSRF protection.

    Parameters
    ----------
    url : str
        Target URL.  Must pass :func:`validate_url` policy.
    timeout : float or None
        Request timeout in seconds.  Defaults to
        :data:`~app.config.FETCH_TIMEOUT_SECONDS`.
    max_size : int or None
        Maximum response body in bytes.  Defaults to
        :data:`~app.config.FETCH_MAX_SIZE_BYTES`.
    client : httpx.AsyncClient or None
        Optional pre-created client (for connection reuse).  When
        provided, the caller is responsible for the client lifecycle.

    Returns
    -------
    bytes
        The response body.

    Raises
    ------
    FetchError
        On URL policy violations, network errors, non-2xx status, or
        size-limit violations.
    """
    validate_url(url)
    authorize_destination(url)

    _timeout = timeout if timeout is not None else FETCH_TIMEOUT_SECONDS
    _max = max_size if max_size is not None else FETCH_MAX_SIZE_BYTES

    logger.debug("safe_get %s (timeout=%.1fs max=%d)", url, _timeout, _max)

    async def _do_get(c: httpx.AsyncClient) -> bytes:
        try:
            response = await c.get(url)
        except httpx.TimeoutException as exc:
            raise FetchError(f"Request timed out: {url}") from exc
        except httpx.HTTPError as exc:
            raise FetchError(f"HTTP error fetching {url}: {exc}") from exc
        except Exception as exc:
            raise FetchError(f"Unexpected error fetching {url}: {exc}") from exc

        if response.status_code < 200 or response.status_code >= 300:
            raise FetchError(
                f"HTTP {response.status_code} fetching {url}"
            )

        body = response.content
        if len(body) > _max:
            raise FetchError(
                f"Response exceeds maximum size ({len(body)} > {_max} bytes): {url}"
            )
        if len(body) == 0:
            raise FetchError(f"Empty response from {url}")

        return body

    if client is not None:
        return await _do_get(client)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_timeout),
        follow_redirects=False,
        trust_env=False,
    ) as c:
        return await _do_get(c)
