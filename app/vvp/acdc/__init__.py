# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""ACDC credential model, SAID computation, and chain validation.

Provides parsing, self-addressing identifier (SAID) verification,
signature verification, credential graph construction, and chain
validation for Authentic Chained Data Container (ACDC) credentials
used in VVP dossiers.

The credential graph (DAG) models the chained structure of a vLEI
credential hierarchy — from root QVI credentials through Legal Entity
and OOR credentials down to VVP-specific telephony authorizations.

References
----------
- KERI spec / KID0009 — SAID computation
- ToIP ACDC specification — Credential structure
- VVP Verifier Specification §6 — Dossier graph validation
"""

from .graph import build_credential_graph, validate_dag
from .models import ACDC, DossierDAG
from .parser import compute_said, parse_acdc, validate_acdc_said
from .verifier import verify_acdc_signature, verify_chain

__all__ = [
    "ACDC",
    "DossierDAG",
    "parse_acdc",
    "compute_said",
    "validate_acdc_said",
    "verify_acdc_signature",
    "build_credential_graph",
    "validate_dag",
    "verify_chain",
]
