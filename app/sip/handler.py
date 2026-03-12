# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""SIP INVITE handler for VVP verification.

This module is the bridge between the SIP transport layer and the VVP
verification engine.  When a SIP INVITE arrives carrying PASSporT (Identity)
and VVP-Identity (P-VVP-Identity) headers, the handler:

1. Extracts the credential material from SIP headers.
2. Constructs a ``VerifyRequest`` and calls the verification pipeline.
3. Translates the ``VerifyResponse`` into X-VVP-* SIP headers.
4. Returns a 302 redirect that the PBX uses to complete the call with
   brand information attached.

Only INVITE requests are processed; all other SIP methods are silently
ignored (returning None causes the transport to send nothing).

SIP header mapping (inbound):
    - ``Identity``       -> PASSporT JWT (RFC 8224)
    - ``P-VVP-Passport`` -> PASSporT JWT (VVP PBX extension, fallback)
    - ``P-VVP-Identity`` -> Base64url-encoded VVP-Identity JSON header

SIP header mapping (outbound, via 302 redirect):
    - ``X-VVP-Status``     -> Verification result (VALID/INVALID/INDETERMINATE)
    - ``X-VVP-Brand-Name`` -> Brand display name
    - ``X-VVP-Brand-Logo`` -> Brand logo URL
    - ``X-VVP-Error``      -> Error code (when verification fails)
"""

from __future__ import annotations

import logging
from typing import Optional

from app.sip.builder import (
    build_302_redirect,
    build_error_response,
    build_vvp_headers,
    extract_contact_uri,
)
from app.sip.models import SIPRequest, SIPResponse
from app.vvp.models import VerifyRequest

logger = logging.getLogger(__name__)


async def handle_invite(
    request: SIPRequest,
    addr: tuple[str, int],
) -> Optional[SIPResponse]:
    """Handle an inbound SIP request for VVP verification.

    Only processes INVITE methods.  For all other methods (ACK, BYE,
    CANCEL, OPTIONS, etc.), returns None — the transport layer will
    not send any response.

    Args:
        request: The parsed SIP request from the transport layer.
        addr: The (host, port) of the sender.

    Returns:
        A ``SIPResponse`` (302 redirect with VVP headers on success,
        or 4xx/5xx on error), or ``None`` if the method is not INVITE.
    """
    # Only handle INVITE requests.
    if request.method != "INVITE":
        logger.debug("Ignoring non-INVITE method: %s", request.method)
        return None

    logger.info(
        "Processing SIP INVITE from %s:%s, Call-ID=%s",
        addr[0], addr[1], request.call_id,
    )

    # ------------------------------------------------------------------
    # Extract credential headers
    # ------------------------------------------------------------------

    # PASSporT JWT is carried in the standard SIP Identity header (RFC 8224).
    # Some PBX configurations forward the PASSporT as P-VVP-Passport instead;
    # accept either header name.
    passport_jwt = request.headers.get("Identity") or request.headers.get("P-VVP-Passport")
    if not passport_jwt:
        logger.warning("INVITE missing Identity/P-VVP-Passport header (PASSporT JWT)")
        return build_error_response(
            request, 400, "Bad Request - Missing Identity/P-VVP-Passport header"
        )

    # VVP-Identity is a private extension header carrying the base64url
    # encoded VVP identity JSON object.
    vvp_identity = request.headers.get("P-VVP-Identity")
    if not vvp_identity:
        logger.warning("INVITE missing P-VVP-Identity header")
        return build_error_response(
            request, 400, "Bad Request - Missing P-VVP-Identity header"
        )

    # ------------------------------------------------------------------
    # Build verification request
    # ------------------------------------------------------------------

    call_id = request.call_id or "unknown"

    verify_request = VerifyRequest(
        passport_jwt=passport_jwt,
        vvp_identity=vvp_identity,
    )

    # ------------------------------------------------------------------
    # Run verification
    # ------------------------------------------------------------------

    try:
        # Import here to avoid circular dependency at module load time.
        # The verify module has heavy dependencies (KERI, HTTP clients, etc.)
        # that should not be imported until actually needed.
        from app.vvp.verify import verify

        verify_result = await verify(verify_request)
    except Exception:
        logger.exception(
            "Verification failed for Call-ID=%s from %s:%s",
            call_id, addr[0], addr[1],
        )
        return build_error_response(request, 500, "Server Internal Error")

    # ------------------------------------------------------------------
    # Build redirect response with VVP headers
    # ------------------------------------------------------------------

    vvp_headers = build_vvp_headers(verify_result)

    # Determine where to redirect the call.  Use the To URI from the
    # original INVITE — this is the intended callee.
    contact_uri = extract_contact_uri(request)
    if not contact_uri:
        logger.error("Cannot extract contact URI from To header: %s", request.to_header)
        return build_error_response(request, 400, "Bad Request - Invalid To header")

    response = build_302_redirect(
        request=request,
        contact_uri=contact_uri,
        extra_headers=vvp_headers,
    )

    logger.info(
        "Returning 302 for Call-ID=%s: status=%s, brand=%s",
        call_id,
        vvp_headers.get("X-VVP-Status", "?"),
        vvp_headers.get("X-VVP-Brand-Name", "(none)"),
    )

    return response
