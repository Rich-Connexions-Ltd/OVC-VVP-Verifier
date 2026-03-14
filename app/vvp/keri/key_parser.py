# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/key_parser.py
# Source commit: 398d40d (2026-03-14)

"""Parse KERI identifiers to extract verification keys.

Strict Tier 1/Tier 2 separation:
- B-prefix (non-transferable): decode raw 32-byte Ed25519 key (Tier 1)
- D/E-prefix (transferable): raw=None, caller MUST use Tier 2 KEL resolution
"""

import base64
from dataclasses import dataclass
from typing import Optional

from .exceptions import ResolutionFailedError, StateInvalidError


ED25519_CODES = frozenset({"B", "D"})
TRANSFERABLE_CODES = frozenset({"D", "E"})


@dataclass(frozen=True)
class VerificationKey:
    """Extracted verification key from kid field.

    Attributes:
        raw: 32-byte Ed25519 public key for B-prefix; None for transferable.
        aid: Original AID string.
        code: KERI derivation code (e.g., "B", "D", "E").
        is_transferable: True for D/E prefix AIDs.
    """
    raw: Optional[bytes]
    aid: str
    code: str
    is_transferable: bool

    def require_raw(self) -> bytes:
        """Return raw key bytes, raising if this is a transferable AID.

        Raises:
            StateInvalidError: If raw is None (transferable AID).
        """
        if self.raw is None:
            raise StateInvalidError(
                f"Cannot use raw key for transferable AID {self.aid[:16]}... "
                f"— Tier 2 KEL resolution required"
            )
        return self.raw


def parse_kid_to_verkey(kid: str) -> VerificationKey:
    """Parse kid (KERI AID) to extract verification key info.

    For B-prefix (non-transferable): decodes raw 32-byte Ed25519 key.
    For D/E-prefix (transferable): returns raw=None. Caller must use
    Tier 2 KEL resolution to obtain the signing key.

    Args:
        kid: KERI AID string from PASSporT header kid field.

    Returns:
        VerificationKey with extracted key info.

    Raises:
        ResolutionFailedError: If format invalid or unsupported algorithm.
    """
    if not kid or len(kid) < 2:
        raise ResolutionFailedError(
            f"Invalid kid format: too short (len={len(kid) if kid else 0})"
        )

    code = kid[0]

    # Transferable AIDs — no raw key decode
    if code in TRANSFERABLE_CODES:
        return VerificationKey(raw=None, aid=kid, code=code, is_transferable=True)

    # Non-transferable Ed25519 (B-prefix) — decode raw key
    if code == "B":
        key_b64 = kid[1:]
        try:
            padded = key_b64 + "=" * (-len(key_b64) % 4)
            raw = base64.urlsafe_b64decode(padded)
        except Exception as e:
            raise ResolutionFailedError(f"Failed to decode kid base64: {e}")

        if len(raw) != 32:
            raise ResolutionFailedError(
                f"Invalid key length: {len(raw)} bytes, expected 32 for Ed25519"
            )

        return VerificationKey(raw=raw, aid=kid, code=code, is_transferable=False)

    raise ResolutionFailedError(
        f"Unsupported derivation code '{code}', expected B, D, or E"
    )


def extract_aid_from_oobi_url(url: str) -> str:
    """Extract AID from OOBI URL path (/oobi/<AID>/...).

    Args:
        url: OOBI URL string.

    Returns:
        AID string extracted from the URL path.

    Raises:
        ResolutionFailedError: If URL doesn't contain a valid OOBI path.
    """
    from urllib.parse import urlparse

    path_parts = urlparse(url).path.split("/")
    try:
        oobi_idx = path_parts.index("oobi")
        return path_parts[oobi_idx + 1]
    except (ValueError, IndexError):
        raise ResolutionFailedError(
            f"URL does not contain a recognisable OOBI path"
        )
