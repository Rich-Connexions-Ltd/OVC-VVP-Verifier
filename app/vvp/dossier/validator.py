# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""DAG building and structural validation for dossier credentials."""

from __future__ import annotations

import logging
from typing import List, Tuple

from app.vvp.acdc import ACDC, DossierDAG, build_credential_graph, validate_dag
from app.vvp.exceptions import DossierGraphError
from app.vvp.api_models import ErrorDetail

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
