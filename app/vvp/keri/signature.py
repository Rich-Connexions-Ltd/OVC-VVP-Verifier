# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/signature.py
# Source commit: 398d40d (2026-03-14)

"""Ed25519 signature verification for VVP PASSporTs.

Tier 1 implementation: Direct verification using public key embedded in KERI AID.
Tier 2 implementation: Resolve key state at reference time T via KEL lookup.

Note: pysodium is imported lazily inside functions to:
1. Avoid import errors when libsodium is not available at module load time
2. Enable testing of code paths that don't require signature verification
"""

from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    import pysodium as _pysodium
except ImportError:
    _pysodium = None  # type: ignore[assignment]

from app.vvp.passport import Passport
from .key_parser import parse_kid_to_verkey
from .exceptions import SignatureInvalidError


def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT signature using Ed25519 (Tier 1).

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        ResolutionFailedError: Could not resolve/parse kid to key (→ INDETERMINATE).
    """
    verkey = parse_kid_to_verkey(passport.header.kid)

    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    if _pysodium is None:
        raise SignatureInvalidError("pysodium not available for signature verification")
    try:
        _pysodium.crypto_sign_verify_detached(
            passport.signature,
            signing_input,
            verkey.raw
        )
    except Exception:
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}..."
        )


async def _verify_passport_signature_tier2_impl(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> Tuple:
    """Internal Tier 2 implementation returning (KeyState, authorization_status).

    Both verify_passport_signature_tier2() and
    verify_passport_signature_tier2_with_key_state() use this.
    """
    from app.core.config import VVP_TIER2_KEL_ENABLED
    from .kel_resolver import resolve_key_state, resolve_key_state_with_kel, KeyState
    from .exceptions import ResolutionFailedError, KELChainInvalidError
    from .delegation import resolve_delegation_chain, validate_delegation_authorization
    from app.vvp.api_models import ClaimStatus

    if not VVP_TIER2_KEL_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled. "
            "Set VVP_TIER2_KEL_ENABLED=true to enable KERI-based "
            "key state resolution."
        )

    if reference_time is None:
        reference_time = datetime.fromtimestamp(passport.payload.iat, tz=timezone.utc)

    key_state = await resolve_key_state(
        kid=passport.header.kid,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )

    authorization_status = "VALID"

    if key_state.is_delegated and key_state.inception_event:
        async def oobi_resolver(aid: str, ref_time: datetime) -> KeyState:
            delegator_oobi = None
            if oobi_url:
                from urllib.parse import urlparse
                parsed = urlparse(oobi_url)
                delegator_oobi = f"{parsed.scheme}://{parsed.netloc}/oobi/{aid}"

            return await resolve_key_state(
                kid=aid,
                reference_time=ref_time,
                oobi_url=delegator_oobi,
                min_witnesses=min_witnesses,
                _allow_test_mode=_allow_test_mode
            )

        try:
            delegation_chain = await resolve_delegation_chain(
                delegated_aid=key_state.aid,
                inception_event=key_state.inception_event,
                reference_time=reference_time,
                oobi_resolver=oobi_resolver
            )

            key_state.delegation_chain = delegation_chain

            if not delegation_chain.valid:
                raise KELChainInvalidError(
                    f"Delegation chain invalid: {', '.join(delegation_chain.errors)}"
                )

            delegator_aid = key_state.delegator_aid
            if delegator_aid:
                delegator_oobi = None
                if oobi_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(oobi_url)
                    delegator_oobi = f"{parsed.scheme}://{parsed.netloc}/oobi/{delegator_aid}"

                delegator_key_state, delegator_kel = await resolve_key_state_with_kel(
                    kid=delegator_aid,
                    reference_time=reference_time,
                    oobi_url=delegator_oobi,
                    min_witnesses=min_witnesses,
                    _allow_test_mode=_allow_test_mode
                )

                is_authorized, auth_status, auth_errors = await validate_delegation_authorization(
                    delegation_event=key_state.inception_event,
                    delegator_kel=delegator_kel,
                    delegator_key_state=delegator_key_state
                )

                if not is_authorized:
                    if auth_status == ClaimStatus.INVALID:
                        authorization_status = "INVALID"
                        raise KELChainInvalidError(
                            f"Delegation not authorized: {'; '.join(auth_errors)}"
                        )
                    else:
                        authorization_status = "INDETERMINATE"
                        raise ResolutionFailedError(
                            f"Cannot verify delegation authorization: {'; '.join(auth_errors)}"
                        )

        except KELChainInvalidError:
            authorization_status = "INVALID"
            raise
        except ResolutionFailedError:
            authorization_status = "INDETERMINATE"
            raise
        except Exception as e:
            authorization_status = "INDETERMINATE"
            raise ResolutionFailedError(
                f"Delegation validation failed: {e}"
            )

    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    signature_valid = False
    for signing_key in key_state.signing_keys:
        try:
            _pysodium.crypto_sign_verify_detached(
                passport.signature,
                signing_input,
                signing_key
            )
            signature_valid = True
            break
        except Exception:
            continue

    if not signature_valid:
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}... "
            f"at reference time {reference_time.isoformat()} "
            f"(key state seq={key_state.sequence})"
        )

    return key_state, authorization_status


async def verify_passport_signature_tier2(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> None:
    """Verify PASSporT signature using historical key state (Tier 2).

    Per spec §5A Step 4: "Resolve issuer key state at reference time T"
    """
    await _verify_passport_signature_tier2_impl(
        passport=passport,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )


async def verify_passport_signature_tier2_with_key_state(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> Tuple:
    """Verify PASSporT signature and return KeyState with authorization status.

    Returns:
        Tuple of (KeyState, authorization_status) where:
        - KeyState: Resolved key state with delegation_chain populated if delegated
        - authorization_status: "VALID", "INVALID", or "INDETERMINATE"
    """
    return await _verify_passport_signature_tier2_impl(
        passport=passport,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )
