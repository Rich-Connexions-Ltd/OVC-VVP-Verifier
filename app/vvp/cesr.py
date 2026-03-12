# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""CESR (Composable Event Streaming Representation) decoding subset.

Implements only the primitives required by the VVP verifier:

- **AID prefix decoding** for non-transferable Ed25519 AIDs (``B`` prefix).
- **Signature decoding** for Ed25519 signatures (codes ``0A``, ``0B``,
  ``AA``, etc.).

This is intentionally *not* a full CESR codec.  Transferable AIDs
(``D`` prefix) require KEL resolution which is a Tier 2 feature.

References
----------
- CESR spec §3 — Encoding Tables
- CESR spec §10 — Indexed Signature Codes
- KID0001 — Prefix derivation
"""

from __future__ import annotations

import base64
from typing import Dict

__all__ = [
    "decode_aid_verkey",
    "decode_pss_signature",
    "CESRDecodeError",
]


class CESRDecodeError(Exception):
    """Raised when a CESR-encoded value cannot be decoded."""


# ---------------------------------------------------------------------------
# Base64url alphabet and lookup table
# ---------------------------------------------------------------------------

_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

_B64URL_LOOKUP: Dict[str, int] = {ch: idx for idx, ch in enumerate(_B64URL_ALPHABET)}


def _b64_to_int(chars: str) -> int:
    """Convert a string of base64url characters to an integer.

    Each character contributes 6 bits.  Characters are processed
    left-to-right (most significant first).

    Parameters
    ----------
    chars : str
        One or more base64url characters.

    Returns
    -------
    int
        The decoded integer value.

    Raises
    ------
    CESRDecodeError
        If any character is not in the base64url alphabet.
    """
    value = 0
    for ch in chars:
        idx = _B64URL_LOOKUP.get(ch)
        if idx is None:
            raise CESRDecodeError(
                f"Invalid base64url character: {ch!r}"
            )
        value = (value << 6) | idx
    return value


def _b64url_decode(encoded: str) -> bytes:
    """Decode a base64url string (no padding) to raw bytes.

    Adds ``=`` padding as needed for the standard library decoder.

    Parameters
    ----------
    encoded : str
        Base64url-encoded string (CESR uses no padding characters).

    Returns
    -------
    bytes
        The decoded raw bytes.

    Raises
    ------
    CESRDecodeError
        If the string contains invalid characters.
    """
    # Add padding to make length a multiple of 4
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise CESRDecodeError(f"Base64url decode failed: {exc}") from exc


# ---------------------------------------------------------------------------
# AID prefix decoding
# ---------------------------------------------------------------------------

# Non-transferable Ed25519 AID: 1-char code "B", total 44 chars, 32-byte key
_NON_TRANS_ED25519_CODE = "B"
_NON_TRANS_ED25519_LEN = 44
_ED25519_KEY_SIZE = 32

# Transferable Ed25519 AID: 1-char code "D", total 44 chars
_TRANS_ED25519_CODE = "D"
_TRANS_ED25519_LEN = 44


def decode_aid_verkey(aid: str) -> bytes:
    """Decode an AID prefix string to its raw Ed25519 verification key.

    Currently supports only non-transferable Ed25519 AIDs (``B`` prefix,
    44 characters total).  Transferable AIDs (``D`` prefix) require
    key-event-log resolution and are not supported in this standalone
    verifier.

    Parameters
    ----------
    aid : str
        The CESR-encoded AID prefix (e.g. ``"BIKKuvBwpmDXA..."``).

    Returns
    -------
    bytes
        The 32-byte Ed25519 public verification key.

    Raises
    ------
    CESRDecodeError
        If the AID format is unrecognized or has wrong length.
    ValueError
        If the AID is a transferable type requiring Tier 2 resolution.
    """
    if not aid:
        raise CESRDecodeError("Empty AID string")

    code = aid[0]

    if code == _TRANS_ED25519_CODE:
        if len(aid) != _TRANS_ED25519_LEN:
            raise CESRDecodeError(
                f"Transferable Ed25519 AID must be {_TRANS_ED25519_LEN} chars, "
                f"got {len(aid)}"
            )
        raise ValueError(
            "Transferable AID requires Tier 2 (KEL resolution). "
            "Only non-transferable (B prefix) AIDs are supported."
        )

    if code == _NON_TRANS_ED25519_CODE:
        if len(aid) != _NON_TRANS_ED25519_LEN:
            raise CESRDecodeError(
                f"Non-transferable Ed25519 AID must be "
                f"{_NON_TRANS_ED25519_LEN} chars, got {len(aid)}"
            )
        # The key material is the remaining 43 chars after the 1-char code.
        # Together with the code char, the full 44-char string encodes
        # 33 bytes (264 bits via 44 * 6 = 264 bits).  The first two bits
        # (from the code character 'B' = 1 = 0b000001) are derivation
        # code bits; the remaining 256 bits are the raw public key.
        #
        # Decoding the full 44-char string as base64url yields 33 bytes.
        # The first byte contains the code bits; bytes [1:] are the key.
        raw = _b64url_decode(aid)
        if len(raw) < _ED25519_KEY_SIZE:
            raise CESRDecodeError(
                f"Decoded AID too short: expected at least "
                f"{_ED25519_KEY_SIZE} key bytes, got {len(raw)} total bytes"
            )
        # Take the last 32 bytes as the public key (code bits are leading)
        verkey = raw[-_ED25519_KEY_SIZE:]
        return verkey

    # Check for two-character codes (e.g. "1A" for Ed448)
    if len(aid) >= 2:
        two_code = aid[:2]
        raise CESRDecodeError(
            f"Unsupported AID code: {two_code!r}. "
            f"Only non-transferable Ed25519 ('B' prefix) is supported."
        )

    raise CESRDecodeError(
        f"Unsupported AID code: {code!r}. "
        f"Only non-transferable Ed25519 ('B' prefix) is supported."
    )


# ---------------------------------------------------------------------------
# Signature decoding
# ---------------------------------------------------------------------------

# Ed25519 signature: 2-char code + 86 chars payload = 88 chars total
# Codes: "AA" (current only), "0A", "0B" (indexed variants)
_SIG_TOTAL_LEN = 88
_ED25519_SIG_SIZE = 64

# Known Ed25519 signature codes (both indexed and non-indexed)
_ED25519_SIG_CODES = frozenset({"AA", "AB", "0A", "0B"})


def decode_pss_signature(encoded: str) -> bytes:
    """Decode a CESR-encoded Ed25519 signature to raw bytes.

    Supports 88-character CESR-encoded signatures with Ed25519 codes
    (``AA``, ``AB``, ``0A``, ``0B``).  The full 88-character string is
    base64url-decoded and the last 64 bytes (the raw Ed25519 signature)
    are returned.

    Parameters
    ----------
    encoded : str
        The 88-character CESR-encoded signature.

    Returns
    -------
    bytes
        The 64-byte raw Ed25519 signature.

    Raises
    ------
    CESRDecodeError
        If the encoded string has the wrong length or an unsupported code.
    """
    if not encoded:
        raise CESRDecodeError("Empty signature string")

    if len(encoded) != _SIG_TOTAL_LEN:
        raise CESRDecodeError(
            f"Ed25519 signature must be {_SIG_TOTAL_LEN} chars, "
            f"got {len(encoded)}"
        )

    # Extract and validate the 2-character code
    code = encoded[:2]
    if code not in _ED25519_SIG_CODES:
        raise CESRDecodeError(
            f"Unsupported signature code: {code!r}. "
            f"Expected one of {sorted(_ED25519_SIG_CODES)}."
        )

    # Decode the full 88-char string.
    # 88 base64url chars = 66 bytes (88 * 6 / 8 = 66).
    # The first 2 bytes carry the code; the last 64 bytes are the
    # raw Ed25519 signature.
    raw = _b64url_decode(encoded)
    if len(raw) < _ED25519_SIG_SIZE:
        raise CESRDecodeError(
            f"Decoded signature too short: expected at least "
            f"{_ED25519_SIG_SIZE} bytes, got {len(raw)}"
        )

    return raw[-_ED25519_SIG_SIZE:]
