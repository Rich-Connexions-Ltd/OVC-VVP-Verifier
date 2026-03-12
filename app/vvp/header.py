# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""VVP-Identity header parser per §4.1A.

Parses and validates the base64url-encoded JSON VVP-Identity header
carried in SIP signalling. The header conveys the binding between a
PASSporT JWT and the KERI/ACDC evidence dossier that underpins it.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from app.config import CLOCK_SKEW_SECONDS, MAX_TOKEN_AGE_SECONDS
from app.vvp.exceptions import VVPIdentityError


@dataclass(frozen=True)
class VVPIdentity:
    """Parsed VVP-Identity header fields.

    Attributes:
        ppt:  PASSporT type (must be ``"vvp"``).
        kid:  Key identifier for the signing key.
        evd:  Evidence URL pointing to the ACDC dossier.
        iat:  Issued-at timestamp (UNIX epoch seconds).
        exp:  Expiry timestamp (UNIX epoch seconds).
        exp_provided:  Whether *exp* was explicitly present in the header
            (``False`` when defaulted to ``iat + MAX_TOKEN_AGE_SECONDS``).
    """

    ppt: str
    kid: str
    evd: str
    iat: int
    exp: int
    exp_provided: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _base64url_decode(encoded: str) -> bytes:
    """Decode a base64url string, adding any required ``=`` padding."""
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise VVPIdentityError.malformed(
            f"Base64url decoding failed: {exc}"
        ) from exc


def _parse_json(raw: bytes) -> Dict[str, Any]:
    """Decode *raw* bytes as a JSON object (must be a ``dict``)."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VVPIdentityError.malformed(
            f"JSON decoding failed: {exc}"
        ) from exc

    if not isinstance(obj, dict):
        raise VVPIdentityError.malformed(
            f"Expected JSON object, got {type(obj).__name__}"
        )
    return obj


def _require_non_empty_string(data: Dict[str, Any], field: str) -> str:
    """Return *field* from *data* as a non-empty ``str``, or raise."""
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise VVPIdentityError.invalid_field(
            field, f"must be a non-empty string, got {value!r}"
        )
    return value


def _require_integer(data: Dict[str, Any], field: str) -> int:
    """Return *field* from *data* as an ``int``.

    Accepts a ``float`` only when it represents a whole number (e.g. ``1.0``).
    Booleans are explicitly rejected even though ``bool`` is a subclass of
    ``int`` in Python.
    """
    value = data.get(field)

    # Reject booleans before the int check (bool is a subclass of int).
    if isinstance(value, bool):
        raise VVPIdentityError.invalid_field(
            field, f"must be an integer, got boolean {value!r}"
        )

    if isinstance(value, int):
        return value

    if isinstance(value, float) and value == int(value):
        return int(value)

    raise VVPIdentityError.invalid_field(
        field, f"must be an integer, got {type(value).__name__} {value!r}"
    )


def _validate_iat_not_future(iat: int) -> None:
    """Reject *iat* values that lie more than CLOCK_SKEW_SECONDS in the future."""
    now = int(time.time())
    if iat > now + CLOCK_SKEW_SECONDS:
        raise VVPIdentityError.iat_future(iat, now, CLOCK_SKEW_SECONDS)


def _get_optional_exp(
    data: Dict[str, Any],
    iat: int,
) -> Tuple[int, bool]:
    """Return ``(exp, exp_provided)`` from *data*.

    If *exp* is absent the default is ``iat + MAX_TOKEN_AGE_SECONDS`` and
    ``exp_provided`` is ``False``.
    """
    raw = data.get("exp")
    if raw is None:
        return iat + MAX_TOKEN_AGE_SECONDS, False

    # Re-use the integer validator for consistency.
    exp = _require_integer(data, "exp")
    return exp, True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_vvp_identity(header: Optional[str]) -> VVPIdentity:
    """Parse and validate a VVP-Identity header value.

    Parameters:
        header: The raw header value (base64url-encoded JSON).

    Returns:
        A validated :class:`VVPIdentity` instance.

    Raises:
        VVPIdentityError: On any validation failure.
    """
    if not header or not header.strip():
        raise VVPIdentityError.missing()

    raw_bytes = _base64url_decode(header.strip())
    data = _parse_json(raw_bytes)

    ppt = _require_non_empty_string(data, "ppt")
    kid = _require_non_empty_string(data, "kid")
    evd = _require_non_empty_string(data, "evd")
    iat = _require_integer(data, "iat")

    _validate_iat_not_future(iat)

    exp, exp_provided = _get_optional_exp(data, iat)

    return VVPIdentity(
        ppt=ppt,
        kid=kid,
        evd=evd,
        iat=iat,
        exp=exp,
        exp_provided=exp_provided,
    )
