# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""DAG building and structural validation for dossier credentials."""

from __future__ import annotations

import logging
from typing import Dict, FrozenSet, List, Tuple

from app.vvp.acdc import ACDC, DossierDAG, build_credential_graph, validate_dag
from app.vvp.api_models import ClaimStatus, ErrorDetail
from app.vvp.exceptions import DossierGraphError
from app.vvp.schema import CredentialClassification

logger = logging.getLogger(__name__)


def build_and_validate_dossier(
    acdcs: List[ACDC],
) -> Tuple[DossierDAG, List[ErrorDetail]]:
    """Build and validate a credential graph from parsed ACDCs.

    Constructs a :class:`DossierDAG` from the provided credentials and
    runs structural validation (root existence, cycle detection, dangling
    edge targets).

    Parameters
    ----------
    acdcs : list[ACDC]
        The parsed ACDC credentials from the dossier.

    Returns
    -------
    tuple[DossierDAG, list[ErrorDetail]]
        The credential graph and a (possibly empty) list of structural
        errors.  An empty error list means the DAG is structurally valid.

    Raises
    ------
    DossierGraphError
        If the credential list is empty or the graph cannot be
        constructed at all (e.g. every credential is a duplicate).
    """
    if not acdcs:
        raise DossierGraphError("Cannot build graph from empty credential list")

    try:
        dag = build_credential_graph(acdcs)
    except ValueError as exc:
        raise DossierGraphError(
            f"Failed to build credential graph: {exc}"
        ) from exc

    errors = validate_dag(dag)

    if errors:
        logger.warning(
            "Dossier DAG validation found %d error(s): %s",
            len(errors),
            "; ".join(e.message if hasattr(e, "message") else str(e) for e in errors),
        )
    else:
        logger.debug(
            "Dossier DAG valid: %d nodes, %d edges, root=%s",
            len(dag.nodes),
            len(dag.edges),
            dag.root,
        )

    return dag, errors


# ---------------------------------------------------------------------------
# Dossier CVD Root Edge Validation (Sprint 88)
# Validates that the dossier root credential's edges conform to the
# normative dossier schema contract.
# ---------------------------------------------------------------------------

DOSSIER_CVD_REQUIRED_EDGES: FrozenSet[str] = frozenset({
    "vetting", "tnalloc", "delsig",
})
DOSSIER_CVD_OPTIONAL_EDGES: FrozenSet[str] = frozenset({
    "alloc", "bownr", "bproxy",
})
DOSSIER_CVD_ALL_EDGES: FrozenSet[str] = (
    DOSSIER_CVD_REQUIRED_EDGES | DOSSIER_CVD_OPTIONAL_EDGES
)


def validate_dossier_cvd_edges(
    root_acdc: ACDC,
    dossier_acdcs: Dict[str, ACDC],
    classifications: Dict[str, CredentialClassification],
) -> Tuple[ClaimStatus, List[str]]:
    """Validate dossier CVD root edges per the dossier schema contract.

    Checks:
    1. All 4 required edges are present (vetting, alloc, tnalloc, delsig)
    2. Each edge's target SAID references a credential in the dossier
    3. Each edge's target has GOVERNED classification
    4. Optional edges (bownr, bproxy) are valid if present

    Args:
        root_acdc: The dossier root ACDC credential.
        dossier_acdcs: Map of SAID → ACDC for all credentials in the dossier.
        classifications: Map of SAID → CredentialClassification for each ACDC.

    Returns:
        Tuple of (ClaimStatus, list of evidence/warning strings):
        - VALID if all required edges present with governed targets
        - INVALID if required edges missing or targets not in dossier
        - INDETERMINATE if targets present but non-GOVERNED
    """
    evidence: List[str] = []
    status = ClaimStatus.VALID

    root_edges = root_acdc.edges or {}

    # Check all required edges are present
    for required_edge in sorted(DOSSIER_CVD_REQUIRED_EDGES):
        if required_edge not in root_edges:
            evidence.append(
                f"CVD_MISSING_REQUIRED_EDGE: dossier root missing "
                f"required edge '{required_edge}'"
            )
            status = ClaimStatus.INVALID

    if status == ClaimStatus.INVALID:
        return status, evidence

    # Validate each known edge (required + optional if present)
    for edge_name, edge_ref in root_edges.items():
        if edge_name == "d":
            continue  # Skip edge block SAID

        # Extract target SAID
        target_said = None
        if isinstance(edge_ref, str):
            target_said = edge_ref
        elif isinstance(edge_ref, dict):
            target_said = edge_ref.get("n") or edge_ref.get("d")

        if not target_said:
            continue

        is_required = edge_name in DOSSIER_CVD_REQUIRED_EDGES
        is_known = edge_name in DOSSIER_CVD_ALL_EDGES

        # Check target is in dossier
        if target_said not in dossier_acdcs:
            if is_required:
                evidence.append(
                    f"CVD_TARGET_NOT_IN_DOSSIER: required edge '{edge_name}' "
                    f"target {target_said[:20]}... not found in dossier"
                )
                status = ClaimStatus.INVALID
            elif is_known:
                evidence.append(
                    f"CVD_TARGET_NOT_IN_DOSSIER: optional edge '{edge_name}' "
                    f"target {target_said[:20]}... not found in dossier"
                )
            continue

        # Check target has GOVERNED classification
        classification = classifications.get(target_said)
        if classification and not classification.is_governed:
            code = "CVD_TARGET_NOT_GOVERNED"
            msg = (
                f"{code}: edge '{edge_name}' target "
                f"{target_said[:20]}... has status "
                f"{classification.governance_status.value}"
            )
            evidence.append(msg)
            if status != ClaimStatus.INVALID:
                status = ClaimStatus.INDETERMINATE

    return status, evidence
