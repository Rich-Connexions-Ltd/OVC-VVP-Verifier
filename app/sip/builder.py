# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""SIP response builder.

Constructs SIP response messages from an inbound ``SIPRequest``, copying
the mandatory dialog-identifying headers (Via, From, To, Call-ID, CSeq)
as required by RFC 3261 §8.2.6.

Three builders are provided:

1. ``build_302_redirect`` — Used by the VVP verification handler to redirect
   the call with X-VVP-* headers attached.  The downstream proxy/PBX reads
   these headers to display brand information.

2. ``build_error_response`` — Generic 4xx/5xx error response.

3. ``build_vvp_headers`` — Extracts VVP-specific X-headers from a
   ``VerifyResponse`` for injection into the SIP redirect.

Header mapping from verification result to SIP headers:

    VerifyResponse.overall_status  ->  X-VVP-Status   (VALID|INVALID|INDETERMINATE)
    VerifyResponse.brand_name      ->  X-VVP-Brand-Name
    VerifyResponse.brand_logo_url  ->  X-VVP-Brand-Logo
    VerifyResponse.errors[0].code  ->  X-VVP-Error     (first error code, if any)

Only non-None values are included in the header dict.
"""

from __future__ import annotations

import re
from typing import Optional

from app.sip.models import SIPRequest, SIPResponse


_MAX_HEADER_VALUE_LEN = 256
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_sip_header_value(value: str) -> Optional[str]:
    """Strip ASCII control characters (0x00–0x1F and 0x7F) and truncate to 256 chars.

    Returns None if the result is empty — callers should omit the header in that case.
    """
    cleaned = _CONTROL_CHARS.sub("", value).strip()
    return cleaned[:_MAX_HEADER_VALUE_LEN] if cleaned else None


# =============================================================================
# Dialog-identifying headers that MUST be copied from request to response
# per RFC 3261 §8.2.6.
# =============================================================================

_DIALOG_HEADERS = ("Via", "From", "To", "Call-ID", "CSeq")


# =============================================================================
# Internal helper
# =============================================================================


def _copy_dialog_headers(request: SIPRequest) -> dict[str, str]:
    """Copy dialog-identifying headers from a request.

    Per RFC 3261 §8.2.6, responses MUST contain the Via, From, To,
    Call-ID, and CSeq headers from the corresponding request.

    Args:
        request: The inbound SIP request.

    Returns:
        A new dictionary containing the copied headers.  Headers that
        are absent from the request are silently omitted.
    """
    headers: dict[str, str] = {}
    for name in _DIALOG_HEADERS:
        value = request.headers.get(name)
        if value is not None:
            headers[name] = value
    return headers


# =============================================================================
# 302 Redirect builder
# =============================================================================


def build_302_redirect(
    request: SIPRequest,
    contact_uri: str,
    extra_headers: Optional[dict[str, str]] = None,
) -> SIPResponse:
    """Build a 302 Moved Temporarily response for a SIP redirect.

    This is the primary response type used in VVP verification.  The
    verifier intercepts an INVITE, verifies the PASSporT and VVP-Identity
    headers, then redirects the call to the original destination with
    X-VVP-* headers conveying the verification result.

    Args:
        request: The inbound SIP INVITE that triggered verification.
        contact_uri: The SIP URI to place in the Contact header.  This is
            typically extracted from the request's To header (the intended
            callee) so the redirected INVITE reaches the correct destination.
        extra_headers: Additional headers to include in the response.
            Used for X-VVP-Status, X-VVP-Brand-Name, etc.

    Returns:
        A ``SIPResponse`` with status 302 and all required headers.
    """
    headers = _copy_dialog_headers(request)
    headers["Contact"] = f"<{contact_uri}>"

    if extra_headers:
        headers.update(extra_headers)

    return SIPResponse(
        status_code=302,
        reason="Moved Temporarily",
        headers=headers,
    )


# =============================================================================
# Error response builder
# =============================================================================


def build_error_response(
    request: SIPRequest,
    status_code: int,
    reason: str,
) -> SIPResponse:
    """Build a 4xx or 5xx error response.

    Args:
        request: The inbound SIP request that caused the error.
        status_code: HTTP-style status code (400, 403, 500, etc.).
        reason: Human-readable reason phrase (e.g. "Bad Request").

    Returns:
        A ``SIPResponse`` with the given status code and dialog headers
        copied from the request.
    """
    headers = _copy_dialog_headers(request)

    return SIPResponse(
        status_code=status_code,
        reason=reason,
        headers=headers,
    )


# =============================================================================
# VVP header builder
# =============================================================================


def build_vvp_headers(verify_result) -> dict[str, str]:
    """Build X-VVP-* SIP headers from a ``VerifyResponse``.

    Inspects the verification result and produces a dictionary of SIP
    extension headers that convey the verification outcome to downstream
    SIP elements (proxies, PBXes, user agents).

    Headers produced (only when the source value is non-None):

    +-----------------------+---------------------------------------------+
    | SIP Header            | Source                                      |
    +=======================+=============================================+
    | X-VVP-Status          | verify_result.overall_status (always set)   |
    +-----------------------+---------------------------------------------+
    | X-VVP-Brand-Name      | verify_result.brand_name                    |
    +-----------------------+---------------------------------------------+
    | X-VVP-Brand-Logo      | verify_result.brand_logo_url                |
    +-----------------------+---------------------------------------------+
    | X-VVP-Error           | First error code from verify_result.errors  |
    +-----------------------+---------------------------------------------+

    Args:
        verify_result: A ``VerifyResponse`` instance (or any object with
            the attributes ``overall_status``, ``brand_name``,
            ``brand_logo_url``, and ``errors``).

    Returns:
        Dictionary of header name -> value strings.  Only includes headers
        whose values are non-None.
    """
    headers: dict[str, str] = {}

    # Overall verification status is always present.
    status = getattr(verify_result, "overall_status", None)
    if status is not None:
        # ClaimStatus is an enum; use its string value.
        headers["X-VVP-Status"] = str(status.value) if hasattr(status, "value") else str(status)

    # Certainty: enum-constrained, no sanitization needed.
    certainty = getattr(verify_result, "certainty", "none")
    if certainty not in ("full", "partial", "none"):
        certainty = "none"
    headers["X-VVP-Certainty"] = certainty

    # Brand name: sanitize before SIP header emission.
    brand_name = getattr(verify_result, "brand_name", None)
    if brand_name is not None:
        sanitized = _sanitize_sip_header_value(str(brand_name))
        if sanitized:
            headers["X-VVP-Brand-Name"] = sanitized

    # Brand logo URL (from PASSporT card claim).
    brand_logo_url = getattr(verify_result, "brand_logo_url", None)
    if brand_logo_url is not None:
        headers["X-VVP-Brand-Logo"] = brand_logo_url

    # First error code, if any errors were recorded.
    errors = getattr(verify_result, "errors", None)
    if errors and len(errors) > 0:
        first_error = errors[0]
        error_code = getattr(first_error, "code", None)
        if error_code is not None:
            # ErrorCode is an enum; use its string value.
            headers["X-VVP-Error"] = (
                str(error_code.value) if hasattr(error_code, "value") else str(error_code)
            )

    return headers


# =============================================================================
# Caller-ID extraction helpers
# =============================================================================


def extract_caller_id(request: SIPRequest) -> Optional[str]:
    """Extract a displayable caller ID from the SIP From header.

    Parses common From header formats:
    - ``"Display Name" <sip:user@host>`` -> ``"Display Name"``
    - ``<sip:user@host>`` -> ``"user"``
    - ``sip:user@host`` -> ``"user"``

    Args:
        request: The SIP request to extract caller ID from.

    Returns:
        A display-friendly caller ID string, or None if the From header
        is absent or unparseable.
    """
    from_hdr = request.from_header
    if not from_hdr:
        return None

    # Check for display name in quotes: "Name" <sip:...>
    if '"' in from_hdr:
        start = from_hdr.index('"') + 1
        end = from_hdr.index('"', start)
        display_name = from_hdr[start:end].strip()
        if display_name:
            return display_name

    # Extract user part from SIP URI: <sip:user@host> or sip:user@host
    uri_part = from_hdr
    if "<" in uri_part:
        uri_part = uri_part[uri_part.index("<") + 1:]
        if ">" in uri_part:
            uri_part = uri_part[:uri_part.index(">")]

    if uri_part.startswith("sip:"):
        uri_part = uri_part[4:]
    elif uri_part.startswith("sips:"):
        uri_part = uri_part[5:]

    if "@" in uri_part:
        return uri_part.split("@")[0]

    return uri_part if uri_part else None


def extract_contact_uri(request: SIPRequest) -> Optional[str]:
    """Extract the target URI from a SIP request's To header.

    Used to determine where to redirect the call in a 302 response.
    Strips angle brackets and tag parameters.

    Args:
        request: The SIP request to extract the contact URI from.

    Returns:
        The bare SIP URI from the To header, or None if absent.
    """
    to_hdr = request.to_header
    if not to_hdr:
        return None

    # Extract URI from angle brackets: <sip:user@host>;tag=xxx
    uri = to_hdr
    if "<" in uri:
        uri = uri[uri.index("<") + 1:]
        if ">" in uri:
            uri = uri[:uri.index(">")]

    return uri.strip() if uri.strip() else None
