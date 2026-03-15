# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""ACDC credential parsing and SAID computation."""

from __future__ import annotations

import base64
import json
import logging

from app.vvp.canonical import (
    FIELD_ORDER,
    CanonicalSerializationError,
    canonical_serialize,
    compute_acdc_said,
    most_compact_form,
)

from .models import ACDC, _SAID_B64_LEN, _SAID_PLACEHOLDER, _SAID_PREFIX, _SAID_TOTAL_LEN

# Lazy import: blake3 is required for SAID computation but may not
# be installed in lightweight environments.
try:
    import blake3
except ImportError:  # pragma: no cover
    blake3 = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def parse_acdc(data: dict) -> ACDC:
    """Parse a dictionary into an ACDC credential.

    Parameters
    ----------
    data : dict
        A dictionary representing a serialized ACDC credential.  Must
        contain at least ``d`` (SAID), ``i`` (issuer), ``s`` (schema),
        and ``a`` (attributes).

    Returns
    -------
    ACDC
        The parsed credential.

    Raises
    ------
    ValueError
        If required fields are missing or have unexpected types.
    """
    if not isinstance(data, dict):
        raise ValueError(f"ACDC data must be a dict, got {type(data).__name__}")

    said = data.get("d", "")
    if not said:
        raise ValueError("ACDC missing 'd' (SAID) field")

    issuer = data.get("i", "")
    if not issuer:
        raise ValueError("ACDC missing 'i' (issuer) field")

    # Schema may be a bare SAID string or a dict with {"d": "<said>", ...}.
    schema_raw = data.get("s")
    if schema_raw is None:
        raise ValueError("ACDC missing 's' (schema) field")
    if isinstance(schema_raw, str):
        schema = schema_raw
    elif isinstance(schema_raw, dict):
        schema = schema_raw.get("d", "")
        if not schema:
            raise ValueError("ACDC schema dict missing 'd' field")
    else:
        raise ValueError(
            f"ACDC 's' field must be str or dict, got {type(schema_raw).__name__}"
        )

    attributes = data.get("a", {})
    if not isinstance(attributes, dict):
        raise ValueError(
            f"ACDC 'a' field must be a dict, got {type(attributes).__name__}"
        )

    edges = data.get("e", {})
    if not isinstance(edges, dict):
        raise ValueError(
            f"ACDC 'e' field must be a dict, got {type(edges).__name__}"
        )

    return ACDC(
        said=said,
        issuer=issuer,
        schema=schema,
        attributes=attributes,
        edges=edges,
        raw=dict(data),
    )


def _base64url_encode_no_pad(data: bytes) -> str:
    """Base64url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compute_said(data: dict) -> str:
    """Compute the SAID (Self-Addressing IDentifier) for a KERI/ACDC dict.

    The SAID is computed by:
    1. Replacing the ``d`` field with a 44-char ``#`` placeholder.
    2. Serializing to compact JSON (using KERI field ordering if a ``t``
       field is present, otherwise key-sorted).
    3. Hashing the serialized bytes with Blake3-256.
    4. Encoding the first 32 bytes as ``"E" + base64url[:43]``.

    Parameters
    ----------
    data : dict
        The KERI event or ACDC credential dict.  Must contain a ``d``
        field (the existing SAID value is replaced for computation).

    Returns
    -------
    str
        The computed 44-character SAID, or ``""`` if the ``d`` field is
        absent or blake3 is unavailable.
    """
    if "d" not in data:
        return ""

    if blake3 is None:  # pragma: no cover
        logger.warning("blake3 not installed; SAID computation unavailable")
        return ""

    event_type = data.get("t")

    # If the event has a type and canonical serialization supports it,
    # use most_compact_form for deterministic placeholder insertion.
    if event_type and event_type in FIELD_ORDER:
        try:
            serialized = most_compact_form(data, said_field="d")
        except CanonicalSerializationError:
            # Fall back to manual placeholder approach.
            serialized = _placeholder_serialize(data)

        digest = blake3.blake3(serialized).digest()
        encoded = _base64url_encode_no_pad(digest[:32])

        # CESR E-prefix SAID: "E" + first 43 base64url characters.
        return _SAID_PREFIX + encoded[:_SAID_B64_LEN]
    else:
        # ACDC credential (no 't' field) - use ACDC canonical ordering
        result = compute_acdc_said(data)
        if result:
            return result
        # Fallback to simple placeholder if compute_acdc_said returns empty
        serialized = _placeholder_serialize(data)
        digest = blake3.blake3(serialized).digest()
        encoded = _base64url_encode_no_pad(digest[:32])
        return _SAID_PREFIX + encoded[:_SAID_B64_LEN]


def _placeholder_serialize(data: dict) -> bytes:
    """Serialize *data* with the ``d`` field replaced by a placeholder.

    For ACDC credentials that lack a ``t`` field (and therefore cannot
    use :func:`canonical_serialize`), we produce deterministic compact
    JSON by preserving the original key order and using compact
    separators.

    If the ``i`` field equals the ``d`` field (self-addressing inception
    pattern), both are replaced with the placeholder.
    """
    work = dict(data)
    original_said = work["d"]
    work["d"] = _SAID_PLACEHOLDER

    # Self-addressing: i == d (inception / delegation).
    if work.get("i") == original_said:
        work["i"] = _SAID_PLACEHOLDER

    return json.dumps(work, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_acdc_said(acdc: ACDC) -> bool:
    """Validate that an ACDC's ``d`` field matches its computed SAID.

    Parameters
    ----------
    acdc : ACDC
        The parsed ACDC credential.

    Returns
    -------
    bool
        ``True`` if the recomputed SAID matches ``acdc.said``.
    """
    recomputed = compute_said(acdc.raw)
    if not recomputed:
        logger.warning("SAID computation returned empty for ACDC %s", acdc.said)
        return False
    match = recomputed == acdc.said
    if not match:
        logger.debug(
            "SAID mismatch for ACDC: expected=%s, computed=%s",
            acdc.said,
            recomputed,
        )
    return match
