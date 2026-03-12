# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Ed25519 PASSporT signature verification (Tier 1 only).

Verifies PASSporT JWT signatures using the public key embedded in the
PASSporT ``kid`` header field.  Only non-transferable Ed25519 AIDs
(``B`` prefix) are supported — transferable AIDs (``D`` prefix) require
KEL resolution which is a Tier 2 operation.

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

__all__ = ["verify_passport_signature"]

# Expected length (characters) of a CESR-encoded Ed25519 AID.
_ED25519_AID_LEN = 44


def verify_passport_signature(passport: "Passport") -> None:
    """Verify the Ed25519 signature on a VVP PASSporT JWT.

    The verification key is derived from the ``kid`` field in the PASSporT
    header.  Only non-transferable (``B``-prefix) Ed25519 AIDs are
    supported in Tier 1.

    Parameters
    ----------
    passport : Passport
        A parsed PASSporT containing ``header.kid``, ``raw_header``,
        ``raw_payload``, and ``signature`` (raw bytes).

    Raises
    ------
    SignatureInvalidError
        If the signature cannot be verified.  The exception carries a
        human-readable message; for transferable AIDs, the ``.code``
        attribute is set to ``"KERI_RESOLUTION_FAILED"``.
    """
    if pysodium is None:  # pragma: no cover
        raise SignatureInvalidError(
            "pysodium is not installed; Ed25519 verification unavailable"
        )

    kid: str = passport.header.kid

    # ------------------------------------------------------------------
    # Determine AID type from the CESR prefix character
    # ------------------------------------------------------------------
    prefix = kid[0] if kid else ""

    if prefix == "B" and len(kid) == _ED25519_AID_LEN:
        # Non-transferable Ed25519 — derive 32-byte verkey directly.
        try:
            verkey = decode_aid_verkey(kid)
        except CESRDecodeError as exc:
            raise SignatureInvalidError(
                f"Failed to decode Ed25519 verkey from AID: {exc}"
            ) from exc

    elif prefix == "D" and len(kid) == _ED25519_AID_LEN:
        # Transferable Ed25519 — requires KEL resolution (Tier 2).
        err = SignatureInvalidError(
            "Transferable AID requires KEL resolution (Tier 2) "
            "which is not supported by this verifier"
        )
        err.code = "KERI_RESOLUTION_FAILED"  # type: ignore[attr-defined]
        raise err

    else:
        raise SignatureInvalidError(
            f"Unknown AID prefix '{prefix}' in kid '{kid}'"
        )

    # ------------------------------------------------------------------
    # Reconstruct the JWT signing input and verify
    # ------------------------------------------------------------------
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

    logger.debug("PASSporT signature verified for kid=%s", kid)
