# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""9-phase VVP verification pipeline orchestrator.

Implements the core verification flow defined in the VVP Verifier
Specification §5A.  Each inbound verification request passes through
up to nine sequential phases that together establish whether a caller
is legitimately authorized to present the originating telephone number.

The nine phases are:

1. **Parse VVP-Identity** — Decode and validate the base64url-encoded
   VVP-Identity header carried alongside the PASSporT JWT.
2. **Parse PASSporT** — Decode the compact-serialised JWT and validate
   its JOSE header and payload claims.
3. **Bind PASSporT to Identity** — Cross-validate the PASSporT and
   VVP-Identity headers (kid, ppt, iat drift, expiry).
4. **Verify Signature** — Verify the Ed25519 signature on the PASSporT
   using the public key derived from the ``kid`` claim.
5. **Fetch Dossier** — Retrieve the ACDC evidence dossier from the
   ``evd`` URL, parse its contents, and validate the credential graph.
6. **Validate DAG** — (Performed as part of Phase 5.)
7. **Verify ACDC Chain** — Walk the credential graph verifying SAIDs
   and signatures for each chained ACDC credential.
8. **Check Revocation** — Query the Transaction Event Log (TEL) to
   confirm no credential in the chain has been revoked.
9. **Validate Authorization** — Verify party authorization (APE / DE
   chain) and telephone number rights (TNAlloc coverage).

The pipeline builds a hierarchical *claim tree* rooted at
``caller_authorised`` with required child claims that mirror the phase
structure.  The overall verification status is derived from the claim
tree: INVALID if any required claim is INVALID, INDETERMINATE if any
is INDETERMINATE, VALID only if all are VALID.

Caching is applied at two levels:

* **Dossier cache** — Avoids redundant HTTP fetches and re-parsing of
  recently seen dossiers (keyed by evidence URL, TTL-based expiry).
* **Verification result cache** — Caches the expensive chain-walk and
  ACDC-signature artifacts (keyed by dossier URL + passport kid).
  Only VALID results are cached; INVALID/INDETERMINATE results are
  never cached to avoid sticky failures from transient conditions.

Revocation checking has three modes depending on cache state:

* **No cache** — Full inline TEL check (blocking).
* **Fresh cache** — Use cached revocation status directly.
* **Stale cache** — Use cached status for the current request but
  enqueue a background re-check so the next request sees fresh data.

References
----------
- VVP Verifier Specification v1.5 §5A — Verification pipeline
- VVP Verifier Specification v1.5 §3.2-§4.3 — Claim tree schema
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import List, Optional, Tuple

from app.config import VERIFICATION_CACHE_ENABLED
from app.vvp.models import (
    CAPABILITIES,
    ChildLink,
    ClaimNode,
    ClaimStatus,
    ErrorCode,
    ErrorDetail,
    VerifyRequest,
    VerifyResponse,
    _status_to_certainty,
    make_error,
    derive_overall_status,
)
from app.vvp.exceptions import (
    DossierFetchError,
    DossierParseError,
    PassportError,
    SignatureInvalidError,
    VVPIdentityError,
)
from app.vvp.header import VVPIdentity, parse_vvp_identity
from app.vvp.passport import Passport, parse_passport, validate_passport_binding
from app.vvp.signature import verify_passport_signature, verify_passport_signature_auto
from app.vvp.dossier import (
    CachedDossier,
    build_and_validate_dossier,
    fetch_dossier,
    get_dossier_cache,
    parse_dossier,
)
from app.vvp.acdc import ACDC, DossierDAG, verify_chain
from app.vvp.tel import ChainRevocationResult, CredentialStatus, check_chain_revocation
from app.vvp.cache import (
    CachedDossierVerification,
    RevocationStatus,
    VerificationResultCache,
    get_verification_cache,
)
from app.vvp.revocation import get_revocation_checker
from app.vvp.authorization import AuthorizationContext, validate_authorization

logger = logging.getLogger("vvp.verify")

__all__ = ["verify"]


# ======================================================================
# Main entry point
# ======================================================================


async def verify(request: VerifyRequest) -> VerifyResponse:
    """Execute the 9-phase VVP verification pipeline.

    This is the single entry point for both the HTTP ``POST /verify``
    endpoint and the SIP INVITE handler.  It accepts a
    :class:`VerifyRequest` containing the PASSporT JWT and optional
    VVP-Identity / dossier URL overrides, and returns a fully populated
    :class:`VerifyResponse` with claim tree, errors, and metadata.

    Parameters
    ----------
    request : VerifyRequest
        The verification request containing at minimum a ``passport_jwt``.
        ``vvp_identity`` and ``dossier_url`` are optional overrides.

    Returns
    -------
    VerifyResponse
        The verification result including overall status, claim tree,
        error list, capabilities, and optional brand / signer metadata.
    """
    request_id = str(uuid.uuid4())
    errors: List[ErrorDetail] = []
    identity: Optional[VVPIdentity] = None
    passport: Optional[Passport] = None
    dag: Optional[DossierDAG] = None
    acdcs: Optional[List[ACDC]] = None
    brand_name: Optional[str] = None
    signer_aid: Optional[str] = None
    cache_hit = False
    revocation_pending = False

    # Claim nodes for each phase, assembled into the tree at the end.
    identity_claim: Optional[ClaimNode] = None
    signature_claim: Optional[ClaimNode] = None
    chain_claim: Optional[ClaimNode] = None
    revocation_claim: Optional[ClaimNode] = None
    party_claim: Optional[ClaimNode] = None
    tn_rights_claim: Optional[ClaimNode] = None

    # Track whether early termination is needed.
    early_terminate = False
    dossier_failed = False

    # ==================================================================
    # Phase 1: Parse VVP-Identity
    # ==================================================================

    identity_claim = _phase_1_parse_identity(request, errors)
    if identity_claim.status == ClaimStatus.VALID:
        identity = _extract_identity_from_claim(request)
    else:
        # Identity parsing failed; we may still recover kid from PASSporT.
        identity = None

    # ==================================================================
    # Phase 2: Parse PASSporT
    # ==================================================================

    passport, passport_claim_status, passport_errors = _phase_2_parse_passport(
        request
    )
    errors.extend(passport_errors)

    if passport is None:
        # Cannot proceed without a parsed PASSporT.
        early_terminate = True
    else:
        signer_aid = passport.header.kid

        # If identity was not provided, attempt to extract kid from PASSporT
        # for downstream use (Phase 5 dossier URL, Phase 9 authorization).
        if identity is None and passport is not None:
            logger.debug(
                "No VVP-Identity; using PASSporT kid=%s as fallback",
                passport.header.kid,
            )

    # ==================================================================
    # Phase 3: Bind PASSporT <-> Identity
    # ==================================================================

    binding_claim: Optional[ClaimNode] = None
    if not early_terminate and passport is not None and identity is not None:
        binding_claim = _phase_3_validate_binding(passport, identity, errors)
        if binding_claim.status == ClaimStatus.INVALID:
            early_terminate = True
    elif not early_terminate and identity is None:
        # No identity header; binding cannot be checked but is not fatal
        # if we still have a valid PASSporT.
        binding_claim = ClaimNode(
            name="binding_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=["VVP-Identity not provided; binding check skipped"],
        )

    # ==================================================================
    # Phase 4: Verify Signature
    # ==================================================================

    if not early_terminate and passport is not None:
        signature_claim = await _phase_4_verify_signature(passport, errors)
        if signature_claim.status == ClaimStatus.INVALID:
            early_terminate = True
    elif not early_terminate:
        signature_claim = ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INVALID,
            reasons=["Cannot verify signature without parsed PASSporT"],
        )
        early_terminate = True

    # ==================================================================
    # Phase 5 + 6: Fetch Dossier + Validate DAG
    # ==================================================================

    dossier_errors: List[ErrorDetail] = []
    cached_verification: Optional[CachedDossierVerification] = None

    if not early_terminate:
        (
            dag,
            acdcs,
            brand_name,
            dossier_errors,
            cached_verification,
            cache_hit,
        ) = await _phase_5_fetch_dossier(
            passport=passport,
            identity=identity,
            dossier_url_override=request.dossier_url,
        )
        errors.extend(dossier_errors)

        if dag is None:
            dossier_failed = True

    # ==================================================================
    # Phase 7: Verify ACDC Chain
    # ==================================================================

    if not early_terminate and not dossier_failed:
        if cached_verification is not None and cached_verification.chain_claim is not None:
            # Use cached chain verification result.
            chain_claim = cached_verification.chain_claim
            logger.debug("Using cached chain verification result")
        elif dag is not None:
            chain_claim = _phase_7_verify_chain(dag, errors)
            # Cache VALID chain results.
            if (
                chain_claim is not None
                and chain_claim.status == ClaimStatus.VALID
                and VERIFICATION_CACHE_ENABLED
                and passport is not None
            ):
                await _cache_verification_result(
                    passport=passport,
                    identity=identity,
                    dag=dag,
                    chain_claim=chain_claim,
                    brand_name=brand_name,
                    dossier_url_override=request.dossier_url,
                )
        else:
            chain_claim = ClaimNode(
                name="chain_verified",
                status=ClaimStatus.INVALID,
                reasons=["No credential graph available for chain verification"],
            )

    # ==================================================================
    # Phase 8: Check Revocation
    # ==================================================================

    if not early_terminate and not dossier_failed and dag is not None:
        revocation_claim, revocation_pending = await _phase_8_check_revocation(
            dag=dag,
            cached_verification=cached_verification,
            passport=passport,
            identity=identity,
            dossier_url_override=request.dossier_url,
            errors=errors,
        )
    elif not early_terminate and not dossier_failed:
        revocation_claim = ClaimNode(
            name="revocation_clear",
            status=ClaimStatus.INDETERMINATE,
            reasons=["No credential graph available for revocation check"],
        )

    # ==================================================================
    # Phase 9: Validate Authorization
    # ==================================================================

    if not early_terminate and not dossier_failed and acdcs is not None and passport is not None:
        party_claim, tn_rights_claim = _phase_9_validate_authorization(
            passport=passport,
            acdcs=acdcs,
            errors=errors,
        )

    # ==================================================================
    # Build Claim Tree
    # ==================================================================

    root_claim = _build_claim_tree(
        identity_claim=identity_claim,
        binding_claim=binding_claim,
        signature_claim=signature_claim,
        chain_claim=chain_claim,
        revocation_claim=revocation_claim,
        party_claim=party_claim,
        tn_rights_claim=tn_rights_claim,
        early_terminate=early_terminate,
        dossier_failed=dossier_failed,
        dossier_errors=dossier_errors,
    )

    claims = [root_claim]
    overall_status = derive_overall_status(claims, errors if errors else None)

    return VerifyResponse(
        request_id=request_id,
        overall_status=overall_status,
        claims=claims,
        errors=errors if errors else None,
        capabilities=dict(CAPABILITIES),
        brand_name=brand_name,
        signer_aid=signer_aid,
        certainty=_status_to_certainty(overall_status),
        revocation_pending=revocation_pending,
        cache_hit=cache_hit,
    )


# ======================================================================
# Phase implementations
# ======================================================================


def _phase_1_parse_identity(
    request: VerifyRequest,
    errors: List[ErrorDetail],
) -> ClaimNode:
    """Phase 1: Parse and validate the VVP-Identity header.

    Parameters
    ----------
    request : VerifyRequest
        The verification request.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    ClaimNode
        The ``identity_valid`` claim node.
    """
    if not request.vvp_identity:
        return ClaimNode(
            name="identity_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=["VVP-Identity header not provided"],
        )

    try:
        identity = parse_vvp_identity(request.vvp_identity)
        return ClaimNode(
            name="identity_valid",
            status=ClaimStatus.VALID,
            evidence=[
                f"kid={identity.kid[:20]}...",
                f"evd={identity.evd[:40]}...",
                f"iat={identity.iat}",
            ],
        )
    except VVPIdentityError as exc:
        errors.append(make_error(exc.code, exc.message))
        return ClaimNode(
            name="identity_valid",
            status=ClaimStatus.INVALID,
            reasons=[exc.message],
        )
    except Exception as exc:
        logger.exception("Unexpected error parsing VVP-Identity")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error parsing VVP-Identity: {exc}",
        ))
        return ClaimNode(
            name="identity_valid",
            status=ClaimStatus.INVALID,
            reasons=[f"Unexpected error: {exc}"],
        )


def _extract_identity_from_claim(
    request: VerifyRequest,
) -> Optional[VVPIdentity]:
    """Re-parse the VVP-Identity header to extract the dataclass.

    Called only when Phase 1 succeeded, so this should not raise.

    Parameters
    ----------
    request : VerifyRequest
        The verification request.

    Returns
    -------
    VVPIdentity or None
        The parsed identity, or None on unexpected failure.
    """
    try:
        return parse_vvp_identity(request.vvp_identity)
    except Exception:
        return None


def _phase_2_parse_passport(
    request: VerifyRequest,
) -> Tuple[Optional[Passport], ClaimStatus, List[ErrorDetail]]:
    """Phase 2: Parse and validate the PASSporT JWT.

    Parameters
    ----------
    request : VerifyRequest
        The verification request.

    Returns
    -------
    tuple[Passport | None, ClaimStatus, list[ErrorDetail]]
        The parsed passport (or None on failure), the claim status,
        and any errors encountered.
    """
    errors: List[ErrorDetail] = []

    try:
        passport = parse_passport(request.passport_jwt)
        return passport, ClaimStatus.VALID, errors
    except PassportError as exc:
        errors.append(make_error(exc.code, exc.message))
        return None, ClaimStatus.INVALID, errors
    except Exception as exc:
        logger.exception("Unexpected error parsing PASSporT")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error parsing PASSporT: {exc}",
        ))
        return None, ClaimStatus.INVALID, errors


def _phase_3_validate_binding(
    passport: Passport,
    identity: VVPIdentity,
    errors: List[ErrorDetail],
) -> ClaimNode:
    """Phase 3: Validate PASSporT <-> VVP-Identity binding.

    Parameters
    ----------
    passport : Passport
        The parsed PASSporT JWT.
    identity : VVPIdentity
        The parsed VVP-Identity header.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    ClaimNode
        The ``binding_valid`` claim node.
    """
    try:
        validate_passport_binding(passport, identity)
        return ClaimNode(
            name="binding_valid",
            status=ClaimStatus.VALID,
            evidence=[
                f"kid_match={passport.header.kid[:20]}...",
                f"ppt_match={passport.header.ppt}",
            ],
        )
    except PassportError as exc:
        errors.append(make_error(exc.code, exc.message))
        return ClaimNode(
            name="binding_valid",
            status=ClaimStatus.INVALID,
            reasons=[exc.message],
        )
    except Exception as exc:
        logger.exception("Unexpected error validating PASSporT binding")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error validating binding: {exc}",
        ))
        return ClaimNode(
            name="binding_valid",
            status=ClaimStatus.INVALID,
            reasons=[f"Unexpected error: {exc}"],
        )


async def _phase_4_verify_signature(
    passport: Passport,
    errors: List[ErrorDetail],
) -> ClaimNode:
    """Phase 4: Verify the Ed25519 signature on the PASSporT.

    Automatically routes to Tier 1 (B-prefix) or Tier 2 (D/E-prefix).
    Tier 2 resolves key state at reference time T via KEL/OOBI.

    Parameters
    ----------
    passport : Passport
        The parsed PASSporT with signature bytes.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    ClaimNode
        The ``signature_valid`` claim node.
    """
    from app.vvp.keri.exceptions import (
        KeriError,
        ResolutionFailedError as KeriResolutionError,
        KELChainInvalidError,
    )

    try:
        await verify_passport_signature_auto(passport)
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.VALID,
            evidence=[f"kid={passport.header.kid[:20]}..."],
        )
    except SignatureInvalidError as exc:
        code = getattr(exc, "code", None)
        if code == "KERI_RESOLUTION_FAILED":
            # Transferable AID — KEL resolution unavailable/disabled.
            errors.append(make_error(
                ErrorCode.KERI_RESOLUTION_FAILED,
                str(exc),
            ))
            return ClaimNode(
                name="signature_valid",
                status=ClaimStatus.INDETERMINATE,
                reasons=[str(exc)],
                evidence=[f"kid={passport.header.kid[:20]}..."],
            )
        else:
            errors.append(make_error(
                ErrorCode.PASSPORT_SIG_INVALID,
                str(exc),
            ))
            return ClaimNode(
                name="signature_valid",
                status=ClaimStatus.INVALID,
                reasons=[str(exc)],
                evidence=[f"kid={passport.header.kid[:20]}..."],
            )
    except KeriResolutionError as exc:
        # Tier 2 transient resolution failure → INDETERMINATE
        errors.append(make_error(
            ErrorCode.KERI_RESOLUTION_FAILED,
            str(exc),
        ))
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=[str(exc)],
            evidence=[f"kid={passport.header.kid[:20]}..."],
        )
    except KELChainInvalidError as exc:
        # Tier 2 chain validation failure → INVALID
        errors.append(make_error(
            ErrorCode.KERI_STATE_INVALID,
            str(exc),
        ))
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INVALID,
            reasons=[str(exc)],
            evidence=[f"kid={passport.header.kid[:20]}..."],
        )
    except KeriError as exc:
        # Other KERI errors → map by error code
        errors.append(make_error(exc.code, str(exc)))
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INVALID,
            reasons=[str(exc)],
            evidence=[f"kid={passport.header.kid[:20]}..."],
        )
    except Exception as exc:
        logger.exception("Unexpected error verifying PASSporT signature")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error verifying signature: {exc}",
        ))
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INVALID,
            reasons=[f"Unexpected error: {exc}"],
        )


async def _phase_5_fetch_dossier(
    passport: Optional[Passport],
    identity: Optional[VVPIdentity],
    dossier_url_override: Optional[str],
) -> Tuple[
    Optional[DossierDAG],
    Optional[List[ACDC]],
    Optional[str],
    List[ErrorDetail],
    Optional[CachedDossierVerification],
    bool,
]:
    """Phase 5 + 6: Fetch dossier, parse, build and validate DAG.

    Attempts to resolve the dossier URL from (in priority order):
    1. The explicit ``dossier_url`` override on the request.
    2. The ``evd`` field from the PASSporT payload.
    3. The ``evd`` field from the VVP-Identity header.

    Checks the dossier cache first.  On miss, performs an HTTP fetch,
    parses the response, builds the credential graph, and caches the
    result.

    Also checks the verification result cache for a prior VALID chain
    verification of this dossier + kid combination.

    Parameters
    ----------
    passport : Passport or None
        The parsed PASSporT (for evd URL and kid).
    identity : VVPIdentity or None
        The parsed VVP-Identity (for evd URL fallback).
    dossier_url_override : str or None
        Explicit dossier URL from the request.

    Returns
    -------
    tuple
        ``(dag, acdcs, brand_name, errors, cached_verification, cache_hit)``
        where ``dag`` and ``acdcs`` may be None on failure.
    """
    errors: List[ErrorDetail] = []
    brand_name: Optional[str] = None
    cached_verification: Optional[CachedDossierVerification] = None
    cache_hit = False

    # Resolve dossier URL.
    dossier_url = _resolve_dossier_url(
        dossier_url_override=dossier_url_override,
        passport=passport,
        identity=identity,
    )

    if not dossier_url:
        errors.append(make_error(
            ErrorCode.DOSSIER_URL_MISSING,
            "No dossier URL available from request, PASSporT, or VVP-Identity",
        ))
        return None, None, None, errors, None, False

    logger.debug("Dossier URL resolved: %s", dossier_url)

    # --- Check verification result cache ---
    kid = passport.header.kid if passport else ""
    if VERIFICATION_CACHE_ENABLED and kid:
        vcache = get_verification_cache()
        cached_verification = await vcache.get(dossier_url, kid)
        if cached_verification is not None:
            logger.info(
                "Verification cache hit for %s kid=%s",
                dossier_url[:60], kid[:20],
            )
            cache_hit = True
            # Reconstruct dag and acdcs from cached entry.
            dag = cached_verification.dag
            acdcs = list(dag.nodes.values()) if dag and dag.nodes else []
            brand_name = cached_verification.brand_name
            return dag, acdcs, brand_name, errors, cached_verification, cache_hit

    # --- Check dossier cache ---
    dossier_cache = get_dossier_cache()
    cached_dossier: Optional[CachedDossier] = await dossier_cache.get(dossier_url)

    if cached_dossier is not None:
        logger.debug("Dossier cache hit for %s", dossier_url[:60])
        dag = cached_dossier.dag
        acdcs = cached_dossier.acdcs
        brand_name = _extract_brand_name(acdcs)
        return dag, acdcs, brand_name, errors, None, False

    # --- Fetch, parse, build ---
    try:
        raw_bytes = await fetch_dossier(dossier_url)
    except DossierFetchError as exc:
        errors.append(make_error(ErrorCode.DOSSIER_FETCH_FAILED, str(exc)))
        return None, None, None, errors, None, False

    try:
        parse_result = parse_dossier(raw_bytes)
        acdcs = parse_result.acdcs
    except DossierParseError as exc:
        errors.append(make_error(ErrorCode.DOSSIER_PARSE_FAILED, str(exc)))
        return None, None, None, errors, None, False

    try:
        dag, dag_errors = build_and_validate_dossier(acdcs)
        errors.extend(dag_errors)
    except Exception as exc:
        logger.exception("Failed to build dossier DAG")
        errors.append(make_error(
            ErrorCode.DOSSIER_GRAPH_INVALID,
            f"Failed to build credential graph: {exc}",
        ))
        return None, acdcs, None, errors, None, False

    brand_name = _extract_brand_name(acdcs)

    # Cache the fetched dossier.
    import hashlib
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    cached_entry = CachedDossier(
        url=dossier_url,
        acdcs=acdcs,
        dag=dag,
        fetched_at=time.monotonic(),
        said=content_hash,
    )
    await dossier_cache.put(dossier_url, cached_entry)

    return dag, acdcs, brand_name, errors, None, False


def _phase_7_verify_chain(
    dag: DossierDAG,
    errors: List[ErrorDetail],
) -> ClaimNode:
    """Phase 7: Verify the ACDC credential chain.

    Walks the credential graph from root to leaves, verifying SAIDs
    and signatures at each node.

    Parameters
    ----------
    dag : DossierDAG
        The validated credential graph.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    ClaimNode
        The ``chain_verified`` claim node.
    """
    try:
        chain_claim = verify_chain(dag)
        return chain_claim
    except Exception as exc:
        logger.exception("Unexpected error during chain verification")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Chain verification error: {exc}",
        ))
        return ClaimNode(
            name="chain_verified",
            status=ClaimStatus.INVALID,
            reasons=[f"Chain verification error: {exc}"],
        )


async def _phase_8_check_revocation(
    dag: DossierDAG,
    cached_verification: Optional[CachedDossierVerification],
    passport: Optional[Passport],
    identity: Optional[VVPIdentity],
    dossier_url_override: Optional[str],
    errors: List[ErrorDetail],
) -> Tuple[ClaimNode, bool]:
    """Phase 8: Check credential revocation status.

    Three modes depending on cache state:

    1. **Fresh cached revocation** — Use the cached per-credential
       revocation status directly.  No network call.
    2. **Stale cached revocation** — Use the cached status for this
       request (avoiding latency) but enqueue a background re-check
       so the next request sees updated data.
    3. **No cache** — Enqueue a background TEL check and return
       INDETERMINATE immediately so the call is never blocked.

    Parameters
    ----------
    dag : DossierDAG
        The credential graph.
    cached_verification : CachedDossierVerification or None
        Cached verification entry (may contain revocation data).
    passport : Passport or None
        The parsed PASSporT.
    identity : VVPIdentity or None
        The parsed VVP-Identity.
    dossier_url_override : str or None
        Explicit dossier URL override.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    tuple[ClaimNode, bool]
        The ``revocation_clear`` claim node and a boolean indicating
        whether a background revocation re-check was enqueued.
    """
    revocation_pending = False

    # --- Mode 1 & 2: Cached revocation ---
    if cached_verification is not None:
        revocation_status = cached_verification.revocation_status
        last_checked = cached_verification.revocation_last_checked

        # Check if any credential is REVOKED.
        revoked_saids = [
            said for said, status in revocation_status.items()
            if status == RevocationStatus.REVOKED
        ]
        if revoked_saids:
            errors.append(make_error(
                ErrorCode.CREDENTIAL_REVOKED,
                f"Revoked credential(s): {', '.join(s[:16] for s in revoked_saids)}",
            ))
            return (
                ClaimNode(
                    name="revocation_clear",
                    status=ClaimStatus.INVALID,
                    reasons=[
                        f"Credential(s) revoked: {', '.join(s[:16] for s in revoked_saids)}"
                    ],
                ),
                False,
            )

        # Check freshness and potentially enqueue background re-check.
        checker = get_revocation_checker()
        if checker.needs_recheck(last_checked):
            # Stale — use cached status but enqueue background refresh.
            dossier_url = _resolve_dossier_url(
                dossier_url_override, passport, identity
            )
            if dossier_url:
                await checker.enqueue(dossier_url)
                revocation_pending = True
                logger.debug(
                    "Enqueued background revocation re-check for %s",
                    dossier_url[:60],
                )

        # All cached statuses are UNREVOKED or UNDEFINED — pass.
        has_undefined = any(
            s == RevocationStatus.UNDEFINED
            for s in revocation_status.values()
        )
        if has_undefined:
            return (
                ClaimNode(
                    name="revocation_clear",
                    status=ClaimStatus.INDETERMINATE,
                    reasons=["Revocation status not yet checked for all credentials"],
                ),
                revocation_pending,
            )

        return (
            ClaimNode(
                name="revocation_clear",
                status=ClaimStatus.VALID,
                evidence=["source=cache"],
            ),
            revocation_pending,
        )

    # --- Mode 3: No cache — enqueue background check, return INDETERMINATE ---
    # TEL checks are NOT in the critical path. The first call after a cache miss
    # always gets INDETERMINATE; subsequent calls see the result once the
    # background task has populated the cache.
    dossier_url = _resolve_dossier_url(dossier_url_override, passport, identity)
    if dossier_url:
        checker = get_revocation_checker()
        await checker.enqueue(dossier_url)
        logger.debug(
            "No revocation cache — enqueued background TEL check for %s",
            dossier_url[:60],
        )
    else:
        logger.debug("No revocation cache and no dossier URL — skipping TEL enqueue")

    return (
        ClaimNode(
            name="revocation_clear",
            status=ClaimStatus.INDETERMINATE,
            reasons=["Revocation not yet checked — background check enqueued"],
        ),
        bool(dossier_url),
    )


def _phase_9_validate_authorization(
    passport: Passport,
    acdcs: List[ACDC],
    errors: List[ErrorDetail],
) -> Tuple[ClaimNode, ClaimNode]:
    """Phase 9: Validate party authorization and TN rights.

    Parameters
    ----------
    passport : Passport
        The parsed PASSporT (for kid and orig TN).
    acdcs : list[ACDC]
        All ACDC credentials from the dossier.
    errors : list[ErrorDetail]
        Mutable error accumulator.

    Returns
    -------
    tuple[ClaimNode, ClaimNode]
        ``(party_authorized, tn_rights_valid)`` claim nodes.
    """
    # Extract originating TN from PASSporT payload.
    orig_tn = _extract_orig_tn(passport)

    ctx = AuthorizationContext(
        pss_signer_aid=passport.header.kid,
        orig_tn=orig_tn,
        dossier_acdcs=acdcs,
    )

    try:
        party_claim, tn_rights_claim = validate_authorization(ctx)

        # Propagate errors for INVALID results.
        if party_claim.status == ClaimStatus.INVALID:
            errors.append(make_error(
                ErrorCode.AUTHORIZATION_FAILED,
                party_claim.reasons[0] if party_claim.reasons else "Party authorization failed",
            ))
        if tn_rights_claim.status == ClaimStatus.INVALID:
            errors.append(make_error(
                ErrorCode.TN_RIGHTS_INVALID,
                tn_rights_claim.reasons[0] if tn_rights_claim.reasons else "TN rights invalid",
            ))

        return party_claim, tn_rights_claim

    except Exception as exc:
        logger.exception("Unexpected error during authorization validation")
        errors.append(make_error(
            ErrorCode.INTERNAL_ERROR,
            f"Authorization validation error: {exc}",
        ))
        return (
            ClaimNode(
                name="party_authorized",
                status=ClaimStatus.INVALID,
                reasons=[f"Authorization error: {exc}"],
            ),
            ClaimNode(
                name="tn_rights_valid",
                status=ClaimStatus.INVALID,
                reasons=[f"Authorization error: {exc}"],
            ),
        )


# ======================================================================
# Claim tree assembly
# ======================================================================


def _build_claim_tree(
    identity_claim: Optional[ClaimNode],
    binding_claim: Optional[ClaimNode],
    signature_claim: Optional[ClaimNode],
    chain_claim: Optional[ClaimNode],
    revocation_claim: Optional[ClaimNode],
    party_claim: Optional[ClaimNode],
    tn_rights_claim: Optional[ClaimNode],
    early_terminate: bool,
    dossier_failed: bool,
    dossier_errors: List[ErrorDetail],
) -> ClaimNode:
    """Assemble the hierarchical claim tree.

    The tree structure mirrors the verification phases::

        caller_authorised
        +-- passport_verified (REQUIRED)
        |   +-- identity_valid (REQUIRED)
        |   +-- binding_valid (REQUIRED)
        |   +-- signature_valid (REQUIRED)
        +-- dossier_verified (REQUIRED)
        |   +-- chain_verified (REQUIRED)
        |   +-- revocation_clear (REQUIRED)
        +-- authorization_valid (REQUIRED)
            +-- party_authorized (REQUIRED)
            +-- tn_rights_valid (REQUIRED)

    Parameters
    ----------
    identity_claim : ClaimNode or None
        Phase 1 result.
    binding_claim : ClaimNode or None
        Phase 3 result.
    signature_claim : ClaimNode or None
        Phase 4 result.
    chain_claim : ClaimNode or None
        Phase 7 result.
    revocation_claim : ClaimNode or None
        Phase 8 result.
    party_claim : ClaimNode or None
        Phase 9a result.
    tn_rights_claim : ClaimNode or None
        Phase 9b result.
    early_terminate : bool
        Whether Phases 1-4 caused early termination.
    dossier_failed : bool
        Whether Phase 5-6 failed.
    dossier_errors : list[ErrorDetail]
        Errors from Phase 5-6.

    Returns
    -------
    ClaimNode
        The root ``caller_authorised`` claim node.
    """
    # --- passport_verified subtree ---
    passport_children: List[ChildLink] = []

    if identity_claim is not None:
        passport_children.append(ChildLink(required=True, node=identity_claim))

    if binding_claim is not None:
        passport_children.append(ChildLink(required=True, node=binding_claim))

    if signature_claim is not None:
        passport_children.append(ChildLink(required=True, node=signature_claim))

    passport_status = _worst_status(
        c.node.status for c in passport_children
    ) if passport_children else ClaimStatus.INVALID

    passport_reasons: List[str] = []
    if early_terminate:
        passport_reasons.append("Early termination due to PASSporT validation failure")

    passport_verified = ClaimNode(
        name="passport_verified",
        status=passport_status,
        reasons=passport_reasons,
        children=passport_children,
    )

    # --- dossier_verified subtree ---
    dossier_children: List[ChildLink] = []

    if chain_claim is not None:
        dossier_children.append(ChildLink(required=True, node=chain_claim))

    if revocation_claim is not None:
        dossier_children.append(ChildLink(required=True, node=revocation_claim))

    if dossier_failed or (not dossier_children):
        dossier_status = ClaimStatus.INVALID
        dossier_reasons = [
            e.message for e in dossier_errors
        ] if dossier_errors else ["Dossier validation failed"]
    elif early_terminate:
        dossier_status = ClaimStatus.INVALID
        dossier_reasons = ["Skipped due to PASSporT validation failure"]
    else:
        child_status = _worst_status(
            c.node.status for c in dossier_children
        )
        # DAG validation errors (e.g. DOSSIER_GRAPH_INVALID) must drive
        # the dossier claim status even when chain/revocation succeed.
        has_non_recoverable = any(not e.recoverable for e in dossier_errors)
        if has_non_recoverable:
            dossier_status = ClaimStatus.INVALID
            dossier_reasons = [e.message for e in dossier_errors if not e.recoverable]
        elif dossier_errors:
            # Recoverable dossier errors → at least INDETERMINATE.
            _severity = [ClaimStatus.VALID, ClaimStatus.INDETERMINATE, ClaimStatus.INVALID]
            dossier_status = max(child_status, ClaimStatus.INDETERMINATE, key=_severity.index)
            dossier_reasons = [e.message for e in dossier_errors]
        else:
            dossier_status = child_status
            dossier_reasons = []

    dossier_verified = ClaimNode(
        name="dossier_verified",
        status=dossier_status,
        reasons=dossier_reasons,
        children=dossier_children,
    )

    # --- authorization_valid subtree ---
    auth_children: List[ChildLink] = []

    if party_claim is not None:
        auth_children.append(ChildLink(required=True, node=party_claim))

    if tn_rights_claim is not None:
        auth_children.append(ChildLink(required=True, node=tn_rights_claim))

    if auth_children:
        auth_status = _worst_status(c.node.status for c in auth_children)
        auth_reasons: List[str] = []
    elif early_terminate or dossier_failed:
        auth_status = ClaimStatus.INVALID
        auth_reasons = ["Skipped due to earlier validation failure"]
    else:
        auth_status = ClaimStatus.INVALID
        auth_reasons = ["Authorization validation not performed"]

    authorization_valid = ClaimNode(
        name="authorization_valid",
        status=auth_status,
        reasons=auth_reasons,
        children=auth_children,
    )

    # --- caller_authorised root ---
    root_children = [
        ChildLink(required=True, node=passport_verified),
        ChildLink(required=True, node=dossier_verified),
        ChildLink(required=True, node=authorization_valid),
    ]

    root_status = _worst_status(c.node.status for c in root_children)

    return ClaimNode(
        name="caller_authorised",
        status=root_status,
        children=root_children,
    )


# ======================================================================
# Helper functions
# ======================================================================


def _resolve_dossier_url(
    dossier_url_override: Optional[str],
    passport: Optional[Passport],
    identity: Optional[VVPIdentity],
) -> Optional[str]:
    """Resolve the dossier evidence URL from available sources.

    Priority order:
    1. Explicit override from the request.
    2. ``evd`` field from the PASSporT payload.
    3. ``evd`` field from the VVP-Identity header.

    Parameters
    ----------
    dossier_url_override : str or None
        Explicit URL from the verification request.
    passport : Passport or None
        The parsed PASSporT.
    identity : VVPIdentity or None
        The parsed VVP-Identity header.

    Returns
    -------
    str or None
        The resolved URL, or None if no source provides one.
    """
    if dossier_url_override and dossier_url_override.strip():
        return dossier_url_override.strip()

    if passport and passport.payload.evd:
        return passport.payload.evd

    if identity and identity.evd:
        return identity.evd

    return None


def _extract_orig_tn(passport: Passport) -> str:
    """Extract the originating telephone number from the PASSporT.

    Returns the first TN from ``orig.tn``, or an empty string if
    the originating identity is not available.

    Parameters
    ----------
    passport : Passport
        The parsed PASSporT.

    Returns
    -------
    str
        The originating TN in E.164 format, or ``""``.
    """
    orig = passport.payload.orig
    if isinstance(orig, dict):
        tn_list = orig.get("tn")
        if isinstance(tn_list, list) and tn_list:
            return str(tn_list[0])
    return ""


def _extract_brand_name(acdcs: Optional[List[ACDC]]) -> Optional[str]:
    """Extract brand name from dossier credentials.

    Scans credentials for a ``card`` or ``brand`` attribute containing
    a display name.

    Parameters
    ----------
    acdcs : list[ACDC] or None
        The parsed ACDC credentials.

    Returns
    -------
    str or None
        The brand display name, or None if not found.
    """
    if not acdcs:
        return None

    for acdc in acdcs:
        attrs = acdc.attributes
        if not attrs:
            continue

        # Check for brand/card attributes.
        for key in ("brand", "card", "brandCard", "brand_card"):
            brand_data = attrs.get(key)
            if isinstance(brand_data, dict):
                name = brand_data.get("name") or brand_data.get("displayName")
                if name and isinstance(name, str):
                    return name
            elif isinstance(brand_data, str) and brand_data:
                return brand_data

    return None


def _build_chain_info(
    dag: DossierDAG,
) -> List[Tuple[str, str]]:
    """Build the chain info list for revocation checking.

    Extracts ``(credential_said, registry_said)`` tuples from the DAG
    for each credential node.

    Parameters
    ----------
    dag : DossierDAG
        The credential graph.

    Returns
    -------
    list[tuple[str, str]]
        Credential SAIDs paired with their registry SAIDs.
    """
    chain_info: List[Tuple[str, str]] = []
    for said, acdc in dag.nodes.items():
        registry_said = ""
        if hasattr(acdc, "raw") and isinstance(acdc.raw, dict):
            registry_said = acdc.raw.get("ri", "")
        chain_info.append((said, registry_said))
    return chain_info


async def _cache_verification_result(
    passport: Passport,
    identity: Optional[VVPIdentity],
    dag: DossierDAG,
    chain_claim: ClaimNode,
    brand_name: Optional[str],
    dossier_url_override: Optional[str],
) -> None:
    """Store a VALID chain verification result in the cache.

    Parameters
    ----------
    passport : Passport
        The parsed PASSporT (for kid).
    identity : VVPIdentity or None
        The parsed VVP-Identity (for evd URL).
    dag : DossierDAG
        The credential graph.
    chain_claim : ClaimNode
        The chain verification claim tree.
    brand_name : str or None
        Brand display name from the dossier.
    dossier_url_override : str or None
        Explicit dossier URL override.
    """
    dossier_url = _resolve_dossier_url(dossier_url_override, passport, identity)
    if not dossier_url:
        return

    kid = passport.header.kid
    contained_saids = list(dag.nodes.keys())

    # Initialize revocation status as UNDEFINED for all credentials.
    revocation_status = {
        said: RevocationStatus.UNDEFINED for said in contained_saids
    }

    entry = CachedDossierVerification(
        dossier_url=dossier_url,
        passport_kid=kid,
        dag=dag,
        chain_claim=chain_claim,
        contained_saids=contained_saids,
        revocation_status=revocation_status,
        revocation_last_checked=None,
        cached_at=time.time(),
        config_hash="",  # Will be set by cache.put().
        brand_name=brand_name,
    )

    vcache = get_verification_cache()
    await vcache.put(dossier_url, kid, entry)

    logger.debug(
        "Cached verification result for %s kid=%s (%d credentials)",
        dossier_url[:60], kid[:20], len(contained_saids),
    )


def _worst_status(statuses) -> ClaimStatus:
    """Return the worst status from an iterable: INVALID > INDETERMINATE > VALID.

    Parameters
    ----------
    statuses : iterable of ClaimStatus
        The claim statuses to compare.

    Returns
    -------
    ClaimStatus
        The worst (most severe) status found.
    """
    worst = ClaimStatus.VALID
    for s in statuses:
        if s == ClaimStatus.INVALID:
            return ClaimStatus.INVALID
        if s == ClaimStatus.INDETERMINATE:
            worst = ClaimStatus.INDETERMINATE
    return worst
