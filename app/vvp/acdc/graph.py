# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Credential graph (DAG) construction and structural validation."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set, Tuple

from app.vvp.api_models import (
    ErrorCode,
    ErrorDetail,
    make_error,
)

from .models import ACDC, DossierDAG

logger = logging.getLogger(__name__)


def _extract_edges(acdc: ACDC) -> List[Tuple[str, str, str]]:
    """Extract edge references from an ACDC's ``e`` field.

    Walks the edges dict looking for nested dicts containing an ``n``
    (node SAID) field, which indicates a chaining reference to another
    credential.

    Returns a list of ``(from_said, to_said, edge_name)`` tuples.
    """
    result: List[Tuple[str, str, str]] = []

    def _walk(obj: Any, parent_key: str = "") -> None:
        if isinstance(obj, dict):
            # If this dict has an "n" field, it's a node reference.
            node_said = obj.get("n")
            if isinstance(node_said, str) and node_said:
                result.append((acdc.said, node_said, parent_key))
            # Recurse into nested dicts.
            for key, value in obj.items():
                if key == "d":
                    # Skip the edge-section SAID itself.
                    continue
                _walk(value, parent_key=key)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, parent_key=parent_key)

    _walk(acdc.edges)
    return result


def build_credential_graph(acdcs: List[ACDC]) -> DossierDAG:
    """Build a directed acyclic graph from a list of ACDC credentials.

    Parameters
    ----------
    acdcs : list[ACDC]
        The credentials to include in the graph.

    Returns
    -------
    DossierDAG
        The constructed credential graph.

    Raises
    ------
    ValueError
        If no credentials are provided or no root can be identified.
    """
    if not acdcs:
        raise ValueError("Cannot build credential graph from empty list")

    dag = DossierDAG()

    # Index credentials by SAID.
    for acdc in acdcs:
        if acdc.said in dag.nodes:
            logger.warning("Duplicate ACDC SAID: %s", acdc.said)
        dag.nodes[acdc.said] = acdc

    # Extract edges.
    for acdc in acdcs:
        edges = _extract_edges(acdc)
        dag.edges.extend(edges)

    # Identify root: a node that is never the target of any edge.
    target_saids: Set[str] = {to_said for _, to_said, _ in dag.edges}
    roots = [said for said in dag.nodes if said not in target_saids]

    if len(roots) == 1:
        dag.root = roots[0]
    elif len(roots) == 0:
        raise ValueError(
            "No root credential found — every credential is referenced "
            "by another (possible cycle)"
        )
    else:
        logger.warning(
            "Multiple root credentials found: %s; using first", roots
        )
        dag.root = roots[0]

    return dag


def validate_dag(dag: DossierDAG) -> List[ErrorDetail]:
    """Validate the structural integrity of a credential DAG.

    Checks:
    - Single root node exists.
    - No cycles (the graph is a proper DAG).
    - All edge targets reference nodes that exist in the graph.

    Parameters
    ----------
    dag : DossierDAG
        The credential graph to validate.

    Returns
    -------
    list[ErrorDetail]
        A list of errors found (empty means the DAG is valid).
    """
    errors: List[ErrorDetail] = []

    # --- Check root ---
    if dag.root is None:
        errors.append(
            make_error(
                ErrorCode.DOSSIER_GRAPH_INVALID,
                "Credential graph has no root node",
            )
        )

    # --- Check dangling edge targets ---
    for from_said, to_said, edge_name in dag.edges:
        if to_said not in dag.nodes:
            errors.append(
                make_error(
                    ErrorCode.DOSSIER_GRAPH_INVALID,
                    f"Edge '{edge_name}' from {from_said} references "
                    f"unknown credential {to_said}",
                )
            )

    # --- Cycle detection (DFS) ---
    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[str, int] = {said: WHITE for said in dag.nodes}

    # Build adjacency list.
    adjacency: Dict[str, List[str]] = {said: [] for said in dag.nodes}
    for from_said, to_said, _ in dag.edges:
        if from_said in adjacency and to_said in dag.nodes:
            adjacency[from_said].append(to_said)

    def _dfs(node: str) -> bool:
        """Return True if a cycle is detected."""
        color[node] = GRAY
        for neighbor in adjacency[node]:
            if color[neighbor] == GRAY:
                return True
            if color[neighbor] == WHITE and _dfs(neighbor):
                return True
        color[node] = BLACK
        return False

    for said in dag.nodes:
        if color[said] == WHITE:
            if _dfs(said):
                errors.append(
                    make_error(
                        ErrorCode.DOSSIER_GRAPH_INVALID,
                        "Credential graph contains a cycle",
                    )
                )
                break  # One cycle error is sufficient.

    return errors
