# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""ACDC signature verification and credential chain validation."""

from __future__ import annotations

import base64
import json
import logging
from typing import List, Set, Tuple

from app.vvp.canonical import (
    CanonicalSerializationError,
    canonical_serialize,
)
from app.vvp.api_models import (
    ChildLink,
    ClaimNode,
    ClaimStatus,
)
from app.vvp.schema import get_credential_type, is_brand_schema

from .models import ACDC, DossierDAG, _SAID_TOTAL_LEN
from .parser import validate_acdc_said

# Lazy import: pysodium for Ed25519 signature verification.
try:
    import pysodium
except ImportError:  # pragma: no cover
    pysodium = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def verify_acdc_signature(acdc: ACDC, verkey: bytes) -> bool:
    """Verify the Ed25519 signature on an ACDC credential.

    Uses the first signature in ``acdc.signatures``.  The message being
    verified is the canonical serialization of ``acdc.raw``.

    Parameters
    ----------
    acdc : ACDC
        The parsed ACDC credential (must have at least one signature).
    verkey : bytes
        The 32-byte Ed25519 public key of the issuer.

    Returns
    -------
    bool
        ``True`` if the signature is valid.
    """
    if pysodium is None:  # pragma: no cover
        logger.warning("pysodium not installed; cannot verify ACDC signature")
        return False

    if not acdc.signatures:
        logger.debug("No signatures attached to ACDC %s", acdc.said)
        return False

    # Serialize the credential for verification.  If it has a "t" field
    # we use canonical serialization; otherwise compact JSON with
    # original key order.
    raw = acdc.raw
    if "t" in raw:
        try:
            serialized = canonical_serialize(raw)
        except CanonicalSerializationError:
            serialized = json.dumps(
                raw, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
    else:
        serialized = json.dumps(
            raw, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    signature = acdc.signatures[0]
    if isinstance(signature, str):
        # Decode base64url if provided as string.
        try:
            signature = base64.urlsafe_b64decode(signature + "==")
        except Exception:
            logger.debug("Failed to decode signature string for ACDC %s", acdc.said)
            return False

    try:
        pysodium.crypto_sign_verify_detached(signature, serialized, verkey)
        return True
    except Exception as exc:
        logger.debug(
            "Signature verification failed for ACDC %s: %s", acdc.said, exc
        )
        return False


def verify_chain(dag: DossierDAG) -> ClaimNode:
    """Verify the full credential chain within a dossier DAG.

    Walks the graph from the root, and for each credential:
    1. Validates the SAID (self-addressing integrity).
    2. Determines the credential type from its schema.
    3. Verifies the signature if signatures are attached.

    Builds a claim tree representing the chain verification result.

    Parameters
    ----------
    dag : DossierDAG
        The credential graph (must have been validated with
        :func:`validate_dag` first).

    Returns
    -------
    ClaimNode
        A claim node representing the chain verification outcome, with
        child nodes for each credential in the chain.
    """
    # Build adjacency for traversal.
    adjacency: dict[str, list[tuple[str, str]]] = {
        said: [] for said in dag.nodes
    }
    for from_said, to_said, edge_name in dag.edges:
        if from_said in adjacency:
            adjacency[from_said].append((to_said, edge_name))

    child_claims: List[ChildLink] = []
    overall_status = ClaimStatus.VALID
    reasons: List[str] = []

    if dag.root is None:
        return ClaimNode(
            name="chain_verified",
            status=ClaimStatus.INVALID,
            reasons=["No root credential in dossier graph"],
        )

    # --- Walk from root using BFS ---
    visited: Set[str] = set()
    queue: List[str] = [dag.root]
    order: List[str] = []  # Traversal order for deterministic output.

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        order.append(current)
        for neighbor, _ in adjacency.get(current, []):
            if neighbor not in visited and neighbor in dag.nodes:
                queue.append(neighbor)

    # --- Verify each credential ---
    for said in order:
        acdc = dag.nodes[said]
        cred_children: List[ChildLink] = []
        cred_status = ClaimStatus.VALID
        cred_reasons: List[str] = []
        cred_evidence: List[str] = []

        # 1. Credential type from schema.
        cred_type = get_credential_type(acdc.schema)
        cred_evidence.append(f"schema={acdc.schema}")
        if cred_type:
            cred_evidence.append(f"type={cred_type}")

        # Brand credentials are display-only leaf nodes, not authority-bearing.
        is_brand = is_brand_schema(acdc.schema)
        if is_brand:
            cred_name = cred_type if cred_type else f"credential_{said[:8]}"
            cred_node = ClaimNode(
                name=cred_name,
                status=ClaimStatus.VALID,
                reasons=[],
                evidence=cred_evidence + ["display-only: brand credential, not authority-bearing"],
                children=[],
            )
            child_claims.append(ChildLink(node=cred_node, required=False))  # not required for auth
            continue

        # 2. SAID validation.
        said_claim = _verify_credential_said(acdc)
        cred_children.append(ChildLink(node=said_claim, required=True))
        if said_claim.status == ClaimStatus.INVALID:
            cred_status = ClaimStatus.INVALID
            cred_reasons.extend(said_claim.reasons)

        # 3. Signature verification (if signatures present).
        sig_claim = _verify_credential_signature(acdc)
        cred_children.append(ChildLink(node=sig_claim, required=True))
        if sig_claim.status == ClaimStatus.INVALID:
            cred_status = ClaimStatus.INVALID
            cred_reasons.extend(sig_claim.reasons)
        elif sig_claim.status == ClaimStatus.INDETERMINATE:
            # No signatures — cannot fully validate, but not invalid.
            if cred_status == ClaimStatus.VALID:
                cred_status = ClaimStatus.INDETERMINATE

        # Build the per-credential claim node.
        cred_name = cred_type if cred_type else f"credential_{said[:8]}"
        cred_node = ClaimNode(
            name=cred_name,
            status=cred_status,
            reasons=cred_reasons,
            evidence=cred_evidence,
            children=cred_children,
        )
        child_claims.append(ChildLink(node=cred_node, required=True))

        # Propagate to overall status.
        if cred_status == ClaimStatus.INVALID:
            overall_status = ClaimStatus.INVALID
        elif (
            cred_status == ClaimStatus.INDETERMINATE
            and overall_status == ClaimStatus.VALID
        ):
            overall_status = ClaimStatus.INDETERMINATE

    if overall_status == ClaimStatus.INVALID:
        reasons.append("One or more credentials failed validation")
    elif overall_status == ClaimStatus.INDETERMINATE:
        reasons.append(
            "Chain verification indeterminate — "
            "one or more credentials lack signatures"
        )

    return ClaimNode(
        name="chain_verified",
        status=overall_status,
        reasons=reasons,
        children=child_claims,
    )


# ======================================================================
# Internal helpers for verify_chain
# ======================================================================


def _verify_credential_said(acdc: ACDC) -> ClaimNode:
    """Verify the SAID of a single ACDC credential.

    Returns a ClaimNode with VALID/INVALID status.
    """
    if validate_acdc_said(acdc):
        return ClaimNode(
            name="said_valid",
            status=ClaimStatus.VALID,
            evidence=[f"said={acdc.said}"],
        )
    else:
        return ClaimNode(
            name="said_valid",
            status=ClaimStatus.INVALID,
            reasons=[f"SAID mismatch for credential {acdc.said}"],
            evidence=[f"said={acdc.said}"],
        )


def _verify_credential_signature(acdc: ACDC) -> ClaimNode:
    """Verify the signature of a single ACDC credential.

    If no signatures are attached, returns INDETERMINATE.
    Signature verification requires the issuer's public key, which for
    Tier 1 can only be derived from non-transferable ``B``-prefix AIDs.

    Returns a ClaimNode with VALID/INVALID/INDETERMINATE status.
    """
    if not acdc.signatures:
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=["No signatures attached to credential"],
            evidence=[f"said={acdc.said}"],
        )

    # Attempt to derive verkey from issuer AID (Tier 1 only).
    issuer = acdc.issuer
    if not issuer or len(issuer) != _SAID_TOTAL_LEN:
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=[f"Cannot derive verkey from issuer AID: {issuer}"],
            evidence=[f"issuer={issuer}"],
        )

    prefix = issuer[0]
    if prefix == "B":
        # Non-transferable Ed25519 — derive verkey.
        try:
            from app.vvp.cesr import decode_aid_verkey

            verkey = decode_aid_verkey(issuer)
        except Exception as exc:
            return ClaimNode(
                name="signature_valid",
                status=ClaimStatus.INDETERMINATE,
                reasons=[f"Failed to decode issuer verkey: {exc}"],
                evidence=[f"issuer={issuer}"],
            )

        if verify_acdc_signature(acdc, verkey):
            return ClaimNode(
                name="signature_valid",
                status=ClaimStatus.VALID,
                evidence=[f"issuer={issuer}", f"said={acdc.said}"],
            )
        else:
            return ClaimNode(
                name="signature_valid",
                status=ClaimStatus.INVALID,
                reasons=["Ed25519 signature verification failed"],
                evidence=[f"issuer={issuer}", f"said={acdc.said}"],
            )

    elif prefix == "D":
        # Transferable — would need KEL resolution (Tier 2).
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=[
                "Transferable AID requires KEL resolution (Tier 2)"
            ],
            evidence=[f"issuer={issuer}"],
        )

    else:
        return ClaimNode(
            name="signature_valid",
            status=ClaimStatus.INDETERMINATE,
            reasons=[f"Unknown AID prefix '{prefix}' for issuer {issuer}"],
            evidence=[f"issuer={issuer}"],
        )
