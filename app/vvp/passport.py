# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""PASSporT JWT parser and validator per §5.0-§5.4.

Handles the VVP-specific PASSporT profile carried in SIP signalling:
decodes the compact-serialised JWT, validates header claims (algorithm,
passport type), extracts payload fields (telephone numbers, evidence URL,
card branding), decodes the CESR or base64url signature, and performs
binding checks against the companion VVP-Identity header.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from app.config import (
    ALLOW_PASSPORT_EXP_OMISSION,
    ALLOWED_ALGORITHMS,
    CLOCK_SKEW_SECONDS,
    FORBIDDEN_ALGORITHMS,
    MAX_IAT_DRIFT_SECONDS,
    MAX_PASSPORT_VALIDITY_SECONDS,
    MAX_TOKEN_AGE_SECONDS,
)
from app.vvp.exceptions import PassportError
from app.vvp.header import VVPIdentity

# ---------------------------------------------------------------------------
# E.164 telephone number pattern  (+<country><subscriber>, 2-15 digits)
# ---------------------------------------------------------------------------
E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PassportHeader:
    """Decoded JOSE header of the PASSporT JWT.

    Attributes:
        alg:  Signature algorithm (e.g. ``"EdDSA"``).
        ppt:  PASSporT type (must be ``"vvp"``).
        kid:  Key identifier matching the VVP-Identity ``kid``.
        typ:  Optional ``typ`` claim (e.g. ``"passport"``).
    """

    alg: str
    ppt: str
    kid: str
    typ: Optional[str] = None


@dataclass(frozen=True)
class PassportPayload:
    """Decoded payload of the PASSporT JWT.

    Attributes:
        iat:      Issued-at timestamp (UNIX epoch seconds).
        orig:     Originating identity (dict with ``tn`` list).
        dest:     Destination identity (dict with ``tn`` list).
        evd:      Evidence URL (from top-level or ``attest.creds``).
        exp:      Optional expiry timestamp.
        card:     Optional RFC 6350 vCard property array
                  (e.g. ``["FN:Acme Corp", "TEL:+12025551234"]``).
        call_id:  Optional SIP Call-ID from PASSporT claims.
        cseq:     Optional SIP CSeq from PASSporT claims.
    """

    iat: int
    orig: Optional[Dict[str, Any]] = None
    dest: Optional[Dict[str, Any]] = None
    evd: Optional[str] = None
    exp: Optional[int] = None
    card: Optional[List[str]] = None
    call_id: Optional[str] = None
    cseq: Optional[str] = None


@dataclass(frozen=True)
class Passport:
    """Fully parsed PASSporT JWT.

    Attributes:
        header:       Decoded JOSE header.
        payload:      Decoded payload.
        signature:    Raw signature bytes.
        raw_header:   The original base64url header segment (for signature
                      verification).
        raw_payload:  The original base64url payload segment.
        warnings:     Non-fatal issues (e.g. non-E.164 telephone numbers).
    """

    header: PassportHeader
    payload: PassportPayload
    signature: bytes
    raw_header: str
    raw_payload: str
    warnings: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Internal helpers — base64url / JSON
# ---------------------------------------------------------------------------

def _b64url_decode(segment: str, label: str) -> bytes:
    """Base64url-decode *segment*, raising :class:`PassportError` on failure."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise PassportError.malformed(
            f"Base64url decoding of {label} failed: {exc}"
        ) from exc


def _decode_json(raw: bytes, label: str) -> Dict[str, Any]:
    """JSON-decode *raw* bytes, requiring a ``dict`` result."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PassportError.malformed(
            f"JSON decoding of {label} failed: {exc}"
        ) from exc
    if not isinstance(obj, dict):
        raise PassportError.malformed(
            f"Expected JSON object for {label}, got {type(obj).__name__}"
        )
    return obj


# ---------------------------------------------------------------------------
# Internal helpers — header validation
# ---------------------------------------------------------------------------

def _extract_header(data: Dict[str, Any]) -> PassportHeader:
    """Extract and validate JOSE header claims."""
    alg = data.get("alg")
    if not isinstance(alg, str) or not alg:
        raise PassportError.malformed("JOSE header missing 'alg' claim")

    # Algorithm gate: reject forbidden before checking allowed.
    if alg in FORBIDDEN_ALGORITHMS:
        raise PassportError.forbidden_algorithm(alg)
    if alg not in ALLOWED_ALGORITHMS:
        raise PassportError.unsupported_algorithm(alg)

    ppt = data.get("ppt")
    if not isinstance(ppt, str) or not ppt:
        raise PassportError.malformed("JOSE header missing 'ppt' claim")
    if ppt != "vvp":
        raise PassportError.invalid_ppt(ppt)

    kid = data.get("kid")
    if not isinstance(kid, str) or not kid:
        raise PassportError.malformed("JOSE header missing 'kid' claim")

    typ = data.get("typ")  # optional
    if typ is not None and not isinstance(typ, str):
        typ = None

    return PassportHeader(alg=alg, ppt=ppt, kid=kid, typ=typ)


# ---------------------------------------------------------------------------
# Internal helpers — payload validation
# ---------------------------------------------------------------------------

def _require_int(data: Dict[str, Any], field: str) -> int:
    """Return *field* as ``int``; accept whole floats, reject booleans."""
    value = data.get(field)
    if isinstance(value, bool):
        raise PassportError.invalid_field(
            field, f"must be an integer, got boolean {value!r}"
        )
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    raise PassportError.invalid_field(
        field, f"must be an integer, got {type(value).__name__} {value!r}"
    )


def _validate_tn_array(
    data: Dict[str, Any],
    field: str,
    *,
    require_single: bool = False,
) -> Tuple[List[str], List[str]]:
    """Validate a ``{"tn": [...]}`` structure, returning ``(tns, warnings)``.

    Parameters:
        data:  The ``orig`` or ``dest`` dict.
        field: ``"orig"`` or ``"dest"`` (for error messages).
        require_single:  If ``True``, the ``tn`` array must contain exactly
            one element (used for ``orig``).

    Returns:
        A tuple of (telephone number list, list of warning strings).
    """
    warnings: List[str] = []

    if not isinstance(data, dict):
        raise PassportError.invalid_field(field, "must be a JSON object")

    tn_list = data.get("tn")
    if not isinstance(tn_list, list) or len(tn_list) == 0:
        raise PassportError.invalid_field(
            f"{field}.tn", "must be a non-empty array"
        )

    if require_single and len(tn_list) != 1:
        raise PassportError.invalid_field(
            f"{field}.tn",
            f"originating TN array must contain exactly one element, got {len(tn_list)}",
        )

    for tn in tn_list:
        if not isinstance(tn, str) or not tn.strip():
            raise PassportError.invalid_field(
                f"{field}.tn", f"each element must be a non-empty string, got {tn!r}"
            )
        if not E164_PATTERN.match(tn):
            warnings.append(
                f"{field}.tn value {tn!r} is not in E.164 format"
            )

    return tn_list, warnings


def _extract_evd(data: Dict[str, Any]) -> Optional[str]:
    """Extract the evidence URL from the payload.

    Checks for a top-level ``evd`` string first; falls back to the first
    entry in ``attest.creds`` that carries an ``"evd:"`` prefix.
    """
    # Top-level evd
    evd = data.get("evd")
    if isinstance(evd, str) and evd.strip():
        return evd.strip()

    # Fallback: attest.creds[0] with "evd:" prefix
    attest = data.get("attest")
    if isinstance(attest, dict):
        creds = attest.get("creds")
        if isinstance(creds, list) and len(creds) > 0:
            first = creds[0]
            if isinstance(first, str) and first.startswith("evd:"):
                return first[4:].strip() or None

    return None


def _extract_payload(data: Dict[str, Any]) -> Tuple[PassportPayload, List[str]]:
    """Extract and validate payload claims, returning warnings."""
    warnings: List[str] = []

    iat = _require_int(data, "iat")

    # orig (required)
    orig_raw = data.get("orig")
    if orig_raw is None:
        raise PassportError.invalid_field("orig", "required field is missing")
    _, orig_warnings = _validate_tn_array(orig_raw, "orig", require_single=True)
    warnings.extend(orig_warnings)

    # dest (required)
    dest_raw = data.get("dest")
    if dest_raw is None:
        raise PassportError.invalid_field("dest", "required field is missing")
    _, dest_warnings = _validate_tn_array(dest_raw, "dest", require_single=False)
    warnings.extend(dest_warnings)

    # evd
    evd = _extract_evd(data)

    # exp (optional)
    exp: Optional[int] = None
    if "exp" in data:
        exp = _require_int(data, "exp")

    # card: RFC 6350 vCard property array
    raw_card = data.get("card")
    card: Optional[List[str]] = None
    if isinstance(raw_card, list):
        card = [str(item) for item in raw_card if isinstance(item, str)]
    elif isinstance(raw_card, dict):
        # Legacy dict format - convert to vCard array format
        card = None  # Cannot reliably convert, discard

    # call_id (optional)
    call_id_raw = data.get("call-id") or data.get("call_id")
    call_id = str(call_id_raw)[:256] if call_id_raw and isinstance(call_id_raw, str) else None

    # cseq (optional)
    cseq_raw = data.get("cseq")
    cseq = str(cseq_raw)[:64] if cseq_raw and isinstance(cseq_raw, str) else None

    payload = PassportPayload(
        iat=iat,
        orig=orig_raw,
        dest=dest_raw,
        evd=evd,
        exp=exp,
        card=card,
        call_id=call_id,
        cseq=cseq,
    )
    return payload, warnings


# ---------------------------------------------------------------------------
# Internal helpers — signature decoding
# ---------------------------------------------------------------------------

# CESR 2-character codes for Ed25519 / secp256k1 / secp256r1 signatures
# that produce 88-character base64url strings (66 raw bytes).
_CESR_SIGNATURE_CODES = {"0A", "0B", "0C", "0D", "AA"}


def _decode_signature(segment: str) -> bytes:
    """Decode the signature segment.

    First attempts CESR decoding for known 88-character signature codes;
    falls back to standard base64url decoding.
    """
    if len(segment) == 88 and segment[:2] in _CESR_SIGNATURE_CODES:
        try:
            from app.vvp.cesr import decode_pss_signature

            return decode_pss_signature(segment)
        except (ImportError, Exception):
            # Fall through to standard base64url if CESR module unavailable
            pass

    return _b64url_decode(segment, "signature")


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def parse_passport(jwt: Optional[str]) -> Passport:
    """Parse a compact-serialised PASSporT JWT.

    Parameters:
        jwt: The raw JWT string (``header.payload.signature``).

    Returns:
        A validated :class:`Passport` instance.

    Raises:
        PassportError: On any structural or validation failure.
    """
    if not jwt or not jwt.strip():
        raise PassportError.missing()

    parts = jwt.strip().split(".")
    if len(parts) != 3:
        raise PassportError.malformed(
            f"JWT must have 3 dot-separated parts, got {len(parts)}"
        )

    raw_header, raw_payload, raw_signature = parts

    # --- Header ---
    header_bytes = _b64url_decode(raw_header, "header")
    header_data = _decode_json(header_bytes, "header")
    header = _extract_header(header_data)

    # --- Payload ---
    payload_bytes = _b64url_decode(raw_payload, "payload")
    payload_data = _decode_json(payload_bytes, "payload")
    payload, warnings = _extract_payload(payload_data)

    # --- Signature ---
    signature = _decode_signature(raw_signature)

    return Passport(
        header=header,
        payload=payload,
        signature=signature,
        raw_header=raw_header,
        raw_payload=raw_payload,
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# Public API — binding validation
# ---------------------------------------------------------------------------

def validate_passport_binding(
    passport: Passport,
    vvp_identity: VVPIdentity,
    now: Optional[int] = None,
) -> None:
    """Validate that *passport* is correctly bound to *vvp_identity*.

    Checks performed (per §5.2-§5.4):

    1. ``ppt`` match
    2. ``kid`` match (strict string equality)
    3. ``iat`` drift within ``MAX_IAT_DRIFT_SECONDS``
    4. ``exp > iat`` when exp present
    5. ``exp`` consistency between passport and identity
    6. ``exp`` omission rules
    7. Expiry / token-age checks

    Parameters:
        passport:      The parsed PASSporT.
        vvp_identity:  The parsed VVP-Identity header.
        now:           Override for current time (testing).

    Raises:
        PassportError: On any binding validation failure.
    """
    if now is None:
        now = int(time.time())

    hdr = passport.header
    pay = passport.payload

    # 1. ppt match
    if hdr.ppt != vvp_identity.ppt:
        raise PassportError.binding_mismatch(
            "ppt", hdr.ppt, vvp_identity.ppt
        )

    # 2. kid match (strict equality)
    if hdr.kid != vvp_identity.kid:
        raise PassportError.binding_mismatch(
            "kid", hdr.kid, vvp_identity.kid
        )

    # 3. iat drift (§5.2A — MUST be <= 5 seconds)
    iat_drift = abs(pay.iat - vvp_identity.iat)
    if iat_drift > MAX_IAT_DRIFT_SECONDS:
        raise PassportError.iat_drift(
            pay.iat, vvp_identity.iat, MAX_IAT_DRIFT_SECONDS
        )

    # 4. exp > iat when exp present
    if pay.exp is not None and pay.exp <= pay.iat:
        raise PassportError.invalid_field(
            "exp",
            f"must be greater than iat ({pay.iat}), got {pay.exp}",
        )

    # 5. exp consistency: drift between passport exp and identity exp
    if pay.exp is not None and vvp_identity.exp_provided:
        exp_drift = abs(pay.exp - vvp_identity.exp)
        if exp_drift > MAX_IAT_DRIFT_SECONDS:
            raise PassportError.exp_inconsistency(
                pay.exp, vvp_identity.exp, MAX_IAT_DRIFT_SECONDS
            )

    # 6. exp omission: if passport lacks exp but identity provides it,
    #    reject unless the configuration explicitly allows omission.
    if pay.exp is None and vvp_identity.exp_provided:
        if not ALLOW_PASSPORT_EXP_OMISSION:
            raise PassportError.exp_omission()

    # 7. Expiry / token-age checks
    if pay.exp is not None:
        # §5.2B — exp - iat must not exceed MAX_PASSPORT_VALIDITY_SECONDS
        validity = pay.exp - pay.iat
        if validity > MAX_PASSPORT_VALIDITY_SECONDS:
            raise PassportError.excessive_validity(
                validity, MAX_PASSPORT_VALIDITY_SECONDS
            )
        # Token must not have expired (with clock-skew grace).
        if now > pay.exp + CLOCK_SKEW_SECONDS:
            raise PassportError.expired(pay.exp, now, CLOCK_SKEW_SECONDS)
    else:
        # No exp: fall back to iat + MAX_TOKEN_AGE + clock-skew
        deadline = pay.iat + MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS
        if now > deadline:
            raise PassportError.token_too_old(
                pay.iat, now, MAX_TOKEN_AGE_SECONDS, CLOCK_SKEW_SECONDS
            )
