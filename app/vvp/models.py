# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""VVP Verifier API models per §3.2, §4.1-§4.3."""

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# =============================================================================
# §3.2 Claim Status
# =============================================================================

class ClaimStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


# =============================================================================
# §4.2 Error Models
# =============================================================================

class ErrorCode(str, Enum):
    VVP_IDENTITY_MISSING = "VVP_IDENTITY_MISSING"
    VVP_IDENTITY_INVALID = "VVP_IDENTITY_INVALID"
    VVP_OOBI_FETCH_FAILED = "VVP_OOBI_FETCH_FAILED"
    PASSPORT_MISSING = "PASSPORT_MISSING"
    PASSPORT_PARSE_FAILED = "PASSPORT_PARSE_FAILED"
    PASSPORT_EXPIRED = "PASSPORT_EXPIRED"
    PASSPORT_FORBIDDEN_ALG = "PASSPORT_FORBIDDEN_ALG"
    PASSPORT_SIG_INVALID = "PASSPORT_SIG_INVALID"
    ACDC_SAID_MISMATCH = "ACDC_SAID_MISMATCH"
    ACDC_PROOF_MISSING = "ACDC_PROOF_MISSING"
    DOSSIER_URL_MISSING = "DOSSIER_URL_MISSING"
    DOSSIER_FETCH_FAILED = "DOSSIER_FETCH_FAILED"
    DOSSIER_PARSE_FAILED = "DOSSIER_PARSE_FAILED"
    DOSSIER_GRAPH_INVALID = "DOSSIER_GRAPH_INVALID"
    KERI_RESOLUTION_FAILED = "KERI_RESOLUTION_FAILED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    TN_RIGHTS_INVALID = "TN_RIGHTS_INVALID"
    INTERNAL_ERROR = "INTERNAL_ERROR"


ERROR_RECOVERABILITY: Dict[str, bool] = {
    ErrorCode.VVP_OOBI_FETCH_FAILED: True,
    ErrorCode.DOSSIER_FETCH_FAILED: True,
    ErrorCode.KERI_RESOLUTION_FAILED: True,
    ErrorCode.INTERNAL_ERROR: True,
}


class ErrorDetail(BaseModel):
    code: str
    message: str
    recoverable: bool


def make_error(code: str, message: str) -> ErrorDetail:
    """Create an ErrorDetail with auto-determined recoverability."""
    return ErrorDetail(
        code=code,
        message=message,
        recoverable=ERROR_RECOVERABILITY.get(code, False),
    )


# =============================================================================
# §4.3B Claim Node Schema
# =============================================================================

class ChildLink(BaseModel):
    required: bool
    node: "ClaimNode"


class ClaimNode(BaseModel):
    name: str
    status: ClaimStatus
    reasons: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    children: List["ChildLink"] = Field(default_factory=list)


ChildLink.model_rebuild()
ClaimNode.model_rebuild()


# =============================================================================
# §4.1 Request / §4.3 Response
# =============================================================================

class VerifyRequest(BaseModel):
    passport_jwt: str
    vvp_identity: Optional[str] = None
    dossier_url: Optional[str] = None


CAPABILITIES: Dict[str, str] = {
    "signature_tier1_nontransferable": "implemented",
    "signature_tier1_transferable": "rejected",
    "signature_tier2": "not_implemented",
    "dossier_validation": "implemented",
    "acdc_chain": "implemented",
    "revocation": "implemented",
    "authorization": "implemented",
    "brand_verification": "not_implemented",
    "goal_verification": "not_implemented",
    "vetter_constraints": "not_implemented",
    "sip_context": "not_implemented",
    "callee_verification": "not_implemented",
}


def _status_to_certainty(
    status: ClaimStatus,
) -> Literal["full", "partial", "none"]:
    """Map verification status to public certainty indicator.

    full    — VALID: all claims verified
    partial — INDETERMINATE: structural checks passed, Tier 2 resolution unavailable
    none    — INVALID: one or more required claims failed
    """
    if status == ClaimStatus.VALID:
        return "full"
    if status == ClaimStatus.INDETERMINATE:
        return "partial"
    return "none"


class VerifyResponse(BaseModel):
    request_id: str
    overall_status: ClaimStatus
    claims: Optional[List[ClaimNode]] = None
    errors: Optional[List[ErrorDetail]] = None
    capabilities: Dict[str, str] = Field(default_factory=lambda: dict(CAPABILITIES))
    brand_name: Optional[str] = None
    signer_aid: Optional[str] = None
    certainty: Literal["full", "partial", "none"] = "none"
    revocation_pending: bool = False
    cache_hit: bool = False


# =============================================================================
# §4.3A Status Derivation
# =============================================================================

def derive_overall_status(
    claims: Optional[List[ClaimNode]],
    errors: Optional[List[ErrorDetail]],
) -> ClaimStatus:
    """Derive overall_status per §3.3A: INVALID > INDETERMINATE > VALID."""
    worst = ClaimStatus.VALID
    if errors:
        for err in errors:
            if not err.recoverable:
                return ClaimStatus.INVALID
        worst = ClaimStatus.INDETERMINATE
    if claims:
        for claim in claims:
            if claim.status == ClaimStatus.INVALID:
                return ClaimStatus.INVALID
            if claim.status == ClaimStatus.INDETERMINATE:
                worst = ClaimStatus.INDETERMINATE
    return worst
