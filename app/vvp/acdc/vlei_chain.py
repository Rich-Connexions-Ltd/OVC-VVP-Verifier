# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""LE→QVI qualifying link validation (Sprint 88).

Validates that a Legal Entity (LE) credential has a qualifying link
to a governed, trusted-root Qualified vLEI Issuer (QVI) credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional

from app.vvp.schema import CredentialClassification, KNOWN_SCHEMAS

from .models import ACDC


# Well-known vLEI schema SAIDs for quick lookup by credential type.
# Uses the first SAID from each KNOWN_SCHEMAS entry (governance canonical).
VLEI_SCHEMA_SAIDS: dict[str, str] = {
    cred_type: next(iter(saids))
    for cred_type, saids in KNOWN_SCHEMAS.items()
    if saids  # skip pending-governance types with empty frozenset
}


def _extract_edge_target(edge_ref: Any) -> Optional[str]:
    """Extract target SAID from an edge reference.

    Edge references can be:
    - String: direct SAID reference
    - Dict with 'n' key: nested SAID reference
    """
    if isinstance(edge_ref, str):
        return edge_ref
    if isinstance(edge_ref, dict):
        return edge_ref.get("n") or edge_ref.get("d")
    return None


@dataclass(frozen=True)
class QualifyingLinkResult:
    """Result of LE→QVI qualifying-link validation."""
    valid: bool
    status: str  # "valid", "indeterminate", "invalid"
    reason: Optional[str] = None


def validate_qualifying_link(
    le_acdc: ACDC,
    classifications: Dict[str, CredentialClassification],
    resolved_acdcs: Dict[str, ACDC],
    trusted_root_aids: FrozenSet[str],
) -> QualifyingLinkResult:
    """Validate that LE has a qualifying link to a governed, trusted-root QVI.

    Checks:
    1. LE has 'qvi' edge
    2. Target credential is found in resolved_acdcs (dossier or external)
    3. Target credential is GOVERNED as QVI type
    4. QVI issuer is in trusted_root_aids (GLEIF root)
    5. I2I semantics: issuer of LE == issuee of QVI

    Args:
        le_acdc: The LE credential to validate.
        classifications: Map of SAID → CredentialClassification.
        resolved_acdcs: Map of SAID → ACDC (dossier + externally resolved).
        trusted_root_aids: Set of trusted root AIDs (GLEIF).

    Returns:
        QualifyingLinkResult with validity status and reason.
    """
    # Step 1: LE must have edges with 'qvi' key
    if not le_acdc.edges:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE credential has no edges",
        )

    qvi_edge = le_acdc.edges.get("qvi")
    if qvi_edge is None:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE credential missing required 'qvi' edge",
        )

    # Step 2: Extract target SAID and find the QVI
    target_said = _extract_edge_target(qvi_edge)
    if not target_said:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason="LE 'qvi' edge has no target SAID",
        )

    qvi_acdc = resolved_acdcs.get(target_said)
    if qvi_acdc is None:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=f"QVI credential {target_said[:20]}... not found in dossier or external resolution",
        )

    # Step 3: QVI must be GOVERNED
    qvi_cls = classifications.get(target_said)
    if qvi_cls is None:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=f"QVI credential {target_said[:20]}... has no classification",
        )
    if not qvi_cls.is_governed:
        return QualifyingLinkResult(
            valid=False,
            status="indeterminate",
            reason=(
                f"QVI credential {target_said[:20]}... has non-governed status "
                f"({qvi_cls.governance_status.value})"
            ),
        )
    if qvi_cls.credential_type != "QVI":
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason=(
                f"LE 'qvi' edge target classified as {qvi_cls.credential_type}, "
                f"not QVI"
            ),
        )

    # Step 4: QVI issuer must be a trusted root
    # Note: OSS ACDC uses .issuer, VVP common ACDC uses .issuer_aid
    if qvi_acdc.issuer not in trusted_root_aids:
        return QualifyingLinkResult(
            valid=False,
            status="invalid",
            reason=(
                f"QVI issuer {qvi_acdc.issuer[:20]}... is not a trusted root AID"
            ),
        )

    # Step 5: I2I operator check — issuer of LE must be issuee of QVI
    qvi_attrs = qvi_acdc.attributes
    if isinstance(qvi_attrs, dict):
        qvi_issuee = qvi_attrs.get("i")
        if qvi_issuee and le_acdc.issuer != qvi_issuee:
            return QualifyingLinkResult(
                valid=False,
                status="invalid",
                reason=(
                    f"I2I violation: LE issuer {le_acdc.issuer[:20]}... "
                    f"!= QVI issuee {qvi_issuee[:20]}..."
                ),
            )

    return QualifyingLinkResult(valid=True, status="valid")
