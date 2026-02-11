# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Party authorization and telephone number rights validation.

Implements VVP Specification §5A Steps 10-11:

* **Step 10 — Party Authorization**: Verifies that the originating
  party (the AID that signed the PASSporT) is authorized to do so,
  either directly via an Authorized Party Entity (APE) credential
  (Case A — no delegation) or indirectly via a Delegation Entity (DE)
  chain that terminates at an APE (Case B — with delegation).

* **Step 11 — TN Rights Validation**: Verifies that the accountable
  party (the APE issuee identified in Step 10) holds a Telephone
  Number Allocation (TNAlloc) credential whose allocation range covers
  the originating telephone number from the PASSporT payload.

The two steps are coupled: the accountable party AID produced by
Step 10 (APE issuee) is the binding key for Step 11 (TNAlloc issuee
must match).

References
----------
- VVP Verifier Specification v1.5 §5A Steps 10-11
- Sprint 15 — Authorization chain validation
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.vvp.acdc import ACDC
from app.vvp.models import (
    ChildLink,
    ClaimNode,
    ClaimStatus,
    ErrorCode,
    ErrorDetail,
    make_error,
)
from app.vvp.schema import get_credential_type

logger = logging.getLogger("vvp.authorization")

__all__ = [
    "AuthorizationContext",
    "normalize_e164",
    "parse_tn_ranges",
    "tn_in_ranges",
    "validate_authorization",
    "verify_party_authorization",
    "verify_tn_rights",
]


# ======================================================================
# AuthorizationContext
# ======================================================================


@dataclass
class AuthorizationContext:
    """Context for authorization and TN-rights validation.

    Aggregates the data required by Steps 10-11 into a single object
    that can be threaded through the validation functions.

    Attributes
    ----------
    pss_signer_aid : str
        The AID extracted from the PASSporT ``kid`` header.  This is
        the originating party (OP) whose authorization we need to
        verify.
    orig_tn : str
        The originating telephone number (E.164 format) from the
        PASSporT ``orig.tn`` claim.
    dossier_acdcs : list[ACDC]
        All ACDC credentials parsed from the dossier.
    """

    pss_signer_aid: str
    orig_tn: str
    dossier_acdcs: List[ACDC]


# ======================================================================
# Main entry point
# ======================================================================


def validate_authorization(
    ctx: AuthorizationContext,
) -> Tuple[ClaimNode, ClaimNode]:
    """Validate party authorization and TN rights (§5A Steps 10-11).

    Orchestrates both steps in sequence:

    1. :func:`verify_party_authorization` (Step 10) — identifies the
       accountable party by walking the APE / DE credential chain.
    2. :func:`verify_tn_rights` (Step 11) — validates that the
       accountable party's TNAlloc covers ``orig_tn``.

    Parameters
    ----------
    ctx : AuthorizationContext
        The authorization context with signer AID, originating TN, and
        dossier credentials.

    Returns
    -------
    tuple[ClaimNode, ClaimNode]
        ``(party_authorized_claim, tn_rights_claim)``
    """
    party_claim = verify_party_authorization(ctx)

    # Extract the authorized AID from the party claim evidence (the
    # accountable party AID recorded during Step 10).
    authorized_aid = _extract_authorized_aid(party_claim)

    tn_rights_claim = verify_tn_rights(
        authorized_aid=authorized_aid,
        orig_tn=ctx.orig_tn,
        dossier_acdcs=ctx.dossier_acdcs,
    )

    return party_claim, tn_rights_claim


# ======================================================================
# Step 10: Party Authorization
# ======================================================================


def verify_party_authorization(ctx: AuthorizationContext) -> ClaimNode:
    """Verify the originating party is authorized to sign the PASSporT.

    Per §5A Step 10:

    * **Case A** (no delegation): Find an APE credential whose issuee
      equals ``pss_signer_aid``.  If found the signer *is* the
      accountable party.

    * **Case B** (with delegation): Find a DE credential whose issuee
      equals ``pss_signer_aid``, then walk the delegation chain (via
      edges) until an APE is reached.  The APE issuee is the
      accountable party.

    Case B is only attempted when there is at least one DE credential
    whose issuee matches the signer.  Unrelated DEs (issuee != signer)
    are ignored.

    Parameters
    ----------
    ctx : AuthorizationContext
        The authorization context.

    Returns
    -------
    ClaimNode
        A ``party_authorized`` claim with status VALID, INVALID, or
        INDETERMINATE.
    """
    ape_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "APE")
    de_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "DE")

    # Find DEs where issuee == signer (matching DEs for Case B).
    matching_des = [
        de for de in de_credentials
        if _get_issuee(de) == ctx.pss_signer_aid
    ]

    # --- Case B: Delegation ---
    if matching_des:
        return _verify_via_delegation(ctx, matching_des)

    # --- Case A: Direct APE match ---
    if not ape_credentials:
        return ClaimNode(
            name="party_authorized",
            status=ClaimStatus.INVALID,
            reasons=["No APE credential found in dossier"],
            evidence=[f"signer:{ctx.pss_signer_aid[:16]}..."],
            children=[
                ChildLink(
                    node=ClaimNode(
                        name="ape_lookup",
                        status=ClaimStatus.INVALID,
                        reasons=["No APE credential in dossier"],
                    ),
                    required=True,
                ),
            ],
        )

    for ape in ape_credentials:
        issuee = _get_issuee(ape)
        if issuee == ctx.pss_signer_aid:
            return ClaimNode(
                name="party_authorized",
                status=ClaimStatus.VALID,
                evidence=[
                    f"ape_said:{ape.said[:16]}...",
                    f"issuee_match:{ctx.pss_signer_aid[:16]}...",
                    f"accountable_party:{issuee[:16]}...",
                ],
            )

    # No APE with matching issuee.
    return ClaimNode(
        name="party_authorized",
        status=ClaimStatus.INVALID,
        reasons=[
            f"No APE credential with issuee matching signer AID "
            f"{ctx.pss_signer_aid[:20]}..."
        ],
        evidence=[
            f"ape_count:{len(ape_credentials)}",
            f"signer:{ctx.pss_signer_aid[:16]}...",
        ],
    )


# ======================================================================
# Step 11: TN Rights
# ======================================================================


def verify_tn_rights(
    authorized_aid: Optional[str],
    orig_tn: str,
    dossier_acdcs: List[ACDC],
) -> ClaimNode:
    """Verify accountable party has TN rights for ``orig_tn`` (Step 11).

    Finds TNAlloc credentials in the dossier whose issuee matches
    ``authorized_aid``, extracts TN allocation ranges from their
    attributes, and checks whether ``orig_tn`` is covered.

    Parameters
    ----------
    authorized_aid : str or None
        The AID of the accountable party (APE issuee from Step 10).
        If ``None``, TN rights cannot be validated.
    orig_tn : str
        The originating telephone number in E.164 format.
    dossier_acdcs : list[ACDC]
        All ACDC credentials from the dossier.

    Returns
    -------
    ClaimNode
        A ``tn_rights_valid`` claim.
    """
    if not authorized_aid:
        return ClaimNode(
            name="tn_rights_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=[
                "Cannot validate TN rights without accountable party AID"
            ],
        )

    tnalloc_credentials = _find_credentials_by_type(dossier_acdcs, "TNAlloc")

    if not tnalloc_credentials:
        return ClaimNode(
            name="tn_rights_valid",
            status=ClaimStatus.INVALID,
            reasons=["No TNAlloc credential found in dossier"],
            evidence=[f"authorized_aid:{authorized_aid[:16]}..."],
        )

    # Normalize the originating TN.
    normalized_tn = normalize_e164(orig_tn)

    # Filter to TNAlloc credentials bound to the accountable party.
    bound_tnallocs = [
        t for t in tnalloc_credentials
        if _get_issuee(t) == authorized_aid
    ]

    if not bound_tnallocs:
        return ClaimNode(
            name="tn_rights_valid",
            status=ClaimStatus.INVALID,
            reasons=[
                f"No TNAlloc credential issued to accountable party "
                f"{authorized_aid[:20]}..."
            ],
            evidence=[
                f"tnalloc_count:{len(tnalloc_credentials)}",
                f"authorized_aid:{authorized_aid[:16]}...",
            ],
        )

    # Check each bound TNAlloc for coverage.
    for tnalloc in bound_tnallocs:
        tn_data = _extract_tn_data(tnalloc)
        if tn_data is None:
            continue

        try:
            ranges = parse_tn_ranges(tn_data)
        except ValueError:
            logger.debug(
                "Malformed TN allocation in TNAlloc %s; skipping",
                tnalloc.said[:20],
            )
            continue

        if tn_in_ranges(normalized_tn, ranges):
            return ClaimNode(
                name="tn_rights_valid",
                status=ClaimStatus.VALID,
                evidence=[
                    f"tnalloc_said:{tnalloc.said[:16]}...",
                    f"issuee_match:{authorized_aid[:16]}...",
                    f"orig_tn:{orig_tn}",
                    "covered:true",
                ],
            )

    # No bound TNAlloc covers the orig_tn.
    return ClaimNode(
        name="tn_rights_valid",
        status=ClaimStatus.INVALID,
        reasons=[
            f"No TNAlloc credential for accountable party covers "
            f"orig.tn {orig_tn}"
        ],
        evidence=[
            f"bound_tnalloc_count:{len(bound_tnallocs)}",
            f"authorized_aid:{authorized_aid[:16]}...",
            f"orig_tn:{orig_tn}",
        ],
    )


# ======================================================================
# Delegation chain helpers
# ======================================================================


def _verify_via_delegation(
    ctx: AuthorizationContext,
    matching_des: List[ACDC],
) -> ClaimNode:
    """Attempt Case B authorization via DE → APE delegation chain.

    Tries each matching DE; the first chain that successfully
    terminates at an APE produces a VALID result.

    Parameters
    ----------
    ctx : AuthorizationContext
        The authorization context.
    matching_des : list[ACDC]
        DE credentials whose issuee matches ``pss_signer_aid``.

    Returns
    -------
    ClaimNode
        A ``party_authorized`` claim.
    """
    last_error: Optional[str] = None

    for de in matching_des:
        ape = _walk_de_chain(de, ctx.dossier_acdcs)
        if ape is not None:
            accountable_aid = _get_issuee(ape)
            evidence = [
                f"de_said:{de.said[:16]}...",
                f"de_issuee_match:{ctx.pss_signer_aid[:16]}...",
                f"ape_said:{ape.said[:16]}...",
            ]
            if accountable_aid:
                evidence.append(
                    f"accountable_party:{accountable_aid[:16]}..."
                )
            return ClaimNode(
                name="party_authorized",
                status=ClaimStatus.VALID,
                evidence=evidence,
            )
        else:
            last_error = (
                f"Delegation chain from DE {de.said[:20]}... "
                f"did not terminate at APE"
            )

    # All matching DEs failed.
    return ClaimNode(
        name="party_authorized",
        status=ClaimStatus.INVALID,
        reasons=[last_error or "All delegation chains failed"],
        evidence=[
            f"matching_de_count:{len(matching_des)}",
            f"signer:{ctx.pss_signer_aid[:16]}...",
        ],
    )


def _walk_de_chain(
    de: ACDC,
    acdcs: List[ACDC],
    max_depth: int = 10,
) -> Optional[ACDC]:
    """Walk a delegation chain from a DE credential to its terminal APE.

    Follows the delegation edge of each DE credential until either an
    APE is reached (success) or the chain is broken (failure).

    Cycle detection is performed using a visited set of SAIDs.

    Parameters
    ----------
    de : ACDC
        The starting DE credential.
    acdcs : list[ACDC]
        All credentials in the dossier for edge resolution.
    max_depth : int
        Maximum chain depth to prevent runaway traversal.

    Returns
    -------
    ACDC or None
        The terminal APE credential, or ``None`` if the chain could
        not be resolved.
    """
    visited: set = set()
    current = de
    depth = 0

    while depth < max_depth:
        visited.add(current.said)

        target = _find_delegation_target(current, acdcs)
        if target is None:
            logger.debug(
                "DE %s has no resolvable delegation edge target",
                current.said[:20],
            )
            return None

        if target.said in visited:
            logger.warning(
                "Circular delegation detected at %s", target.said[:20]
            )
            return None

        # Determine the credential type of the target.
        target_type = get_credential_type(target.schema)

        if target_type == "APE":
            return target

        if target_type == "DE":
            current = target
            depth += 1
            continue

        # Unexpected credential type in chain.
        logger.debug(
            "Unexpected credential type %s in delegation chain at %s",
            target_type,
            target.said[:20],
        )
        return None

    logger.warning("Delegation chain exceeds max depth %d", max_depth)
    return None


def _find_delegation_target(
    de: ACDC,
    acdcs: List[ACDC],
) -> Optional[ACDC]:
    """Resolve the delegation edge of a DE credential to its target.

    Examines the DE's edges for well-known delegation edge names and
    resolves the referenced SAID to a credential in *acdcs*.

    Edge names checked (case-insensitive): ``delegation``, ``d``,
    ``delegate``, ``delegator``, ``issuer``.

    Parameters
    ----------
    de : ACDC
        The DE credential whose delegation edge to resolve.
    acdcs : list[ACDC]
        All credentials available for resolution.

    Returns
    -------
    ACDC or None
        The target credential, or ``None`` if the edge could not be
        resolved.
    """
    if not de.edges:
        return None

    # Build a SAID-keyed index for O(1) lookup.
    acdc_index: Dict[str, ACDC] = {a.said: a for a in acdcs}

    delegation_names = {"delegation", "d", "delegate", "delegator", "issuer"}

    for edge_name, edge_ref in de.edges.items():
        if edge_name.lower() not in delegation_names:
            continue

        target_said: Optional[str] = None

        if isinstance(edge_ref, str):
            target_said = edge_ref
        elif isinstance(edge_ref, dict):
            target_said = edge_ref.get("n") or edge_ref.get("d")

        if target_said and target_said in acdc_index:
            return acdc_index[target_said]

    return None


# ======================================================================
# ACDC helper functions
# ======================================================================


def _get_issuee(acdc: ACDC) -> Optional[str]:
    """Extract the issuee (subject) AID from an ACDC's attributes.

    Per the ACDC specification, the issuee may appear under several
    attribute keys depending on the credential type and version:

    * ``i`` — standard issuee field
    * ``issuee`` — alternative naming
    * ``holder`` — used in some earlier implementations

    Parameters
    ----------
    acdc : ACDC
        The credential to inspect.

    Returns
    -------
    str or None
        The issuee AID, or ``None`` if not found.
    """
    if not acdc.attributes:
        return None
    return (
        acdc.attributes.get("i")
        or acdc.attributes.get("issuee")
        or acdc.attributes.get("holder")
    )


def _find_credentials_by_type(
    acdcs: List[ACDC],
    cred_type: str,
) -> List[ACDC]:
    """Filter a list of ACDC credentials by credential type.

    Uses :func:`~app.vvp.schema.get_credential_type` to resolve each
    credential's schema SAID to a type name.

    Parameters
    ----------
    acdcs : list[ACDC]
        The credentials to filter.
    cred_type : str
        The credential type to select (e.g. ``"APE"``, ``"DE"``,
        ``"TNAlloc"``).

    Returns
    -------
    list[ACDC]
        Credentials whose schema resolves to *cred_type*.
    """
    return [
        acdc
        for acdc in acdcs
        if get_credential_type(acdc.schema) == cred_type
    ]


def _extract_authorized_aid(party_claim: ClaimNode) -> Optional[str]:
    """Extract the accountable party AID from a party_authorized claim.

    Scans the claim's evidence strings for the
    ``accountable_party:<aid>...`` pattern recorded by
    :func:`verify_party_authorization`.

    Parameters
    ----------
    party_claim : ClaimNode
        The ``party_authorized`` claim node.

    Returns
    -------
    str or None
        The full AID (or the truncated portion from evidence), or
        ``None`` if not found.
    """
    if party_claim.status != ClaimStatus.VALID:
        return None

    for ev in party_claim.evidence:
        if ev.startswith("accountable_party:"):
            # Evidence format: "accountable_party:<aid_prefix>..."
            return ev.split(":", 1)[1].rstrip(".")

    # Fallback: if issuee_match is present (Case A, where signer == AP).
    for ev in party_claim.evidence:
        if ev.startswith("issuee_match:"):
            return ev.split(":", 1)[1].rstrip(".")

    return None


def _extract_tn_data(tnalloc: ACDC) -> Any:
    """Extract TN allocation data from a TNAlloc credential's attributes.

    Tries the following attribute keys in order: ``tn``, ``phone``,
    ``numbers``, ``allocation``.

    Parameters
    ----------
    tnalloc : ACDC
        The TNAlloc credential.

    Returns
    -------
    Any
        The TN allocation data (typically a string or dict), or
        ``None`` if not found.
    """
    if not tnalloc.attributes:
        return None
    return (
        tnalloc.attributes.get("tn")
        or tnalloc.attributes.get("phone")
        or tnalloc.attributes.get("numbers")
        or tnalloc.attributes.get("allocation")
    )


# ======================================================================
# E.164 and TN range utilities
# ======================================================================


def normalize_e164(tn: str) -> str:
    """Normalize a telephone number to E.164 format.

    Strips whitespace and ensures the number starts with ``+``.

    Parameters
    ----------
    tn : str
        The telephone number to normalize.

    Returns
    -------
    str
        The normalized telephone number (e.g. ``"+442071234567"``).

    Examples
    --------
    >>> normalize_e164("  +44 207 123 4567  ")
    '+442071234567'
    >>> normalize_e164("442071234567")
    '+442071234567'
    """
    cleaned = re.sub(r"\s+", "", tn.strip())
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    return cleaned


def parse_tn_ranges(
    tn_data: Any,
) -> List[Tuple[str, str]]:
    """Parse TN allocation data into a list of ``(start, end)`` ranges.

    Supports several input formats:

    * A single E.164 string: ``"+441234567890"`` → ``[("+441234567890", "+441234567890")]``
    * A comma-separated string: ``"+441234567890,+441234567899"`` → single range
    * A hyphenated range: ``"+441234567890-+441234567899"`` → single range
    * A list of strings: each parsed as above
    * A dict with ``"start"``/``"end"`` keys
    * A list of dicts with ``"start"``/``"end"`` keys

    Parameters
    ----------
    tn_data : Any
        The TN allocation data from a TNAlloc credential.

    Returns
    -------
    list[tuple[str, str]]
        Parsed ranges as ``(start_tn, end_tn)`` tuples (inclusive).

    Raises
    ------
    ValueError
        If the data cannot be parsed into valid TN ranges.
    """
    ranges: List[Tuple[str, str]] = []

    if isinstance(tn_data, str):
        ranges.extend(_parse_tn_string(tn_data))

    elif isinstance(tn_data, dict):
        start = tn_data.get("start") or tn_data.get("from")
        end = tn_data.get("end") or tn_data.get("to")
        if start and end:
            ranges.append((normalize_e164(str(start)), normalize_e164(str(end))))
        else:
            raise ValueError(f"TN dict missing start/end keys: {tn_data!r}")

    elif isinstance(tn_data, list):
        for item in tn_data:
            if isinstance(item, str):
                ranges.extend(_parse_tn_string(item))
            elif isinstance(item, dict):
                start = item.get("start") or item.get("from")
                end = item.get("end") or item.get("to")
                if start and end:
                    ranges.append(
                        (normalize_e164(str(start)), normalize_e164(str(end)))
                    )
                else:
                    raise ValueError(
                        f"TN dict missing start/end keys: {item!r}"
                    )
            else:
                raise ValueError(
                    f"Unexpected TN allocation item type: "
                    f"{type(item).__name__}"
                )
    else:
        raise ValueError(
            f"Unexpected TN allocation data type: "
            f"{type(tn_data).__name__}"
        )

    if not ranges:
        raise ValueError("No TN ranges could be parsed from allocation data")

    return ranges


def _parse_tn_string(s: str) -> List[Tuple[str, str]]:
    """Parse a single TN allocation string into ranges.

    Handles:
    * Single number: ``"+441234567890"``
    * Hyphenated range: ``"+441234567890-+441234567899"``
    * Comma-separated pair: ``"+441234567890,+441234567899"``

    Parameters
    ----------
    s : str
        The TN string to parse.

    Returns
    -------
    list[tuple[str, str]]
        One or more ``(start, end)`` tuples.
    """
    s = s.strip()

    # Hyphenated range: "+441234567890-+441234567899"
    if "-" in s and s.count("-") == 1:
        parts = s.split("-", 1)
        start = normalize_e164(parts[0])
        end = normalize_e164(parts[1])
        return [(start, end)]

    # Comma-separated: could be a range pair or multiple single numbers.
    if "," in s:
        parts = [p.strip() for p in s.split(",")]
        if len(parts) == 2:
            # Treat as a range if both look like TNs.
            start = normalize_e164(parts[0])
            end = normalize_e164(parts[1])
            return [(start, end)]
        else:
            # Multiple individual numbers.
            return [(normalize_e164(p), normalize_e164(p)) for p in parts]

    # Single number.
    normalized = normalize_e164(s)
    return [(normalized, normalized)]


def tn_in_ranges(
    tn: str,
    ranges: List[Tuple[str, str]],
) -> bool:
    """Check whether a telephone number falls within any of the given ranges.

    Comparison is lexicographic on the normalized E.164 strings (which
    works correctly because E.164 numbers are digit-only after the ``+``
    prefix and same-length numbers sort correctly).

    Parameters
    ----------
    tn : str
        The normalized E.164 telephone number to check.
    ranges : list[tuple[str, str]]
        The ``(start, end)`` ranges to check against (inclusive).

    Returns
    -------
    bool
        ``True`` if ``tn`` falls within at least one range.
    """
    normalized = normalize_e164(tn)
    for start, end in ranges:
        if start <= normalized <= end:
            return True
    return False
