# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Ed25519 PASSporT signature verification (Tier 1 + Tier 2).

Tier 1: Verifies using the public key embedded in the KERI AID (B-prefix).
Tier 2: Resolves key state at reference time T via KEL/OOBI (D/E-prefix).

The ``verify_passport_signature`` function handles Tier 1 only (sync).
The ``verify_passport_signature_auto`` async function automatically routes
to Tier 1 or Tier 2 based on the AID prefix.

References
----------
- VVP Verifier Specification §5.0–§5.1  — EdDSA (Ed25519) mandate
- KERI spec §2.3.1 — Non-transferable prefix derivation codes
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.vvp.cesr import CESRDecodeError, decode_aid_verkey
from app.vvp.exceptions import SignatureInvalidError

if TYPE_CHECKING:
    from app.vvp.passport import Passport

# Lazy import: pysodium may not be available in all environments.
try:
    import pysodium
except ImportError:  # pragma: no cover
    pysodium = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

__all__ = ["verify_passport_signature", "verify_passport_signature_auto"]

# Expected length (characters) of a CESR-encoded Ed25519 AID.
_ED25519_AID_LEN = 44


def _extract_aid_from_kid(kid: str) -> str:
    """Extract bare AID from kid field, handling OOBI URLs."""
    if kid.startswith("http://") or kid.startswith("https://"):
        from urllib.parse import urlparse
        path_parts = urlparse(kid).path.split("/")
        try:
            oobi_idx = path_parts.index("oobi")
            return path_parts[oobi_idx + 1]
        except (ValueError, IndexError):
            raise SignatureInvalidError(
                f"kid is a URL but does not contain a recognisable OOBI path: '{kid}'"
            )
    return kid


def verify_passport_signature(passport: "Passport") -> None:
    """Verify the Ed25519 signature on a VVP PASSporT JWT (Tier 1 only).

    Non-transferable (``B``-prefix) AIDs are verified directly.
    Transferable (``D``/``E``-prefix) AIDs raise with code
    ``KERI_RESOLUTION_FAILED`` — use ``verify_passport_signature_auto``
    for automatic Tier 2 routing.

    Parameters
    ----------
    passport : Passport
        A parsed PASSporT containing ``header.kid``, ``raw_header``,
        ``raw_payload``, and ``signature`` (raw bytes).

    Raises
    ------
    SignatureInvalidError
        If the signature cannot be verified.
    """
    if pysodium is None:  # pragma: no cover
        raise SignatureInvalidError(
            "pysodium is not installed; Ed25519 verification unavailable"
        )

    kid = _extract_aid_from_kid(passport.header.kid)
    prefix = kid[0] if kid else ""

    if prefix == "B" and len(kid) == _ED25519_AID_LEN:
        try:
            verkey = decode_aid_verkey(kid)
        except CESRDecodeError as exc:
            raise SignatureInvalidError(
                f"Failed to decode Ed25519 verkey from AID: {exc}"
            ) from exc

    elif prefix in ("D", "E") and len(kid) == _ED25519_AID_LEN:
        err = SignatureInvalidError(
            "Transferable AID requires KEL resolution (Tier 2) "
            "— use verify_passport_signature_auto() instead"
        )
        err.code = "KERI_RESOLUTION_FAILED"  # type: ignore[attr-defined]
        raise err

    else:
        raise SignatureInvalidError(
            f"Unknown AID prefix '{prefix}' in kid '{kid}'"
        )

    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    try:
        pysodium.crypto_sign_verify_detached(
            passport.signature,
            signing_input,
            verkey,
        )
    except Exception as exc:
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed: {exc}"
        ) from exc

    logger.debug("PASSporT signature verified (Tier 1) for kid=%s", kid)


async def verify_passport_signature_auto(passport: "Passport") -> None:
    """Verify PASSporT signature, automatically routing Tier 1 or Tier 2.

    - B-prefix (non-transferable): Tier 1 direct key decode (sync)
    - D/E-prefix (transferable): Tier 2 KEL resolution via OOBI (async)

    Parameters
    ----------
    passport : Passport
        A parsed PASSporT containing ``header.kid``, ``raw_header``,
        ``raw_payload``, and ``signature`` (raw bytes).

    Raises
    ------
    SignatureInvalidError
        If the signature is cryptographically invalid (→ INVALID).
    app.vvp.keri.ResolutionFailedError
        If KEL resolution fails (→ INDETERMINATE).
    app.vvp.keri.KELChainInvalidError
        If KEL chain is invalid (→ INVALID).
    """
    kid = _extract_aid_from_kid(passport.header.kid)
    prefix = kid[0] if kid else ""

    if prefix == "B" and len(kid) == _ED25519_AID_LEN:
        # Tier 1: direct key decode
        verify_passport_signature(passport)
        return

    if prefix in ("D", "E") and len(kid) == _ED25519_AID_LEN:
        # Tier 2: KEL resolution
        from app.vvp.keri.signature import verify_passport_signature_tier2
        await verify_passport_signature_tier2(passport)
        logger.debug("PASSporT signature verified (Tier 2) for kid=%s", kid)
        return

    raise SignatureInvalidError(
        f"Unknown AID prefix '{prefix}' in kid '{kid}'"
    )
