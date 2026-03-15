# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Dossier fetch, parse, DAG validation, and LRU cache.

Provides the plumbing between raw dossier bytes (fetched from the URL
carried in the VVP-Identity ``evd`` field) and the structured
credential graph used by the verification pipeline.

References
----------
- VVP Verifier Specification §6 — Dossier graph validation
- ToIP ACDC specification — Credential structure
"""

from .cache import (
    CachedDossier,
    DossierCache,
    get_dossier_cache,
    reset_dossier_cache,
)
from .fetch import fetch_dossier
from .parser import DossierParseResult, _is_keri_event, parse_dossier
from .validator import build_and_validate_dossier

__all__ = [
    "fetch_dossier",
    "parse_dossier",
    "build_and_validate_dossier",
    "DossierParseResult",
    "CachedDossier",
    "DossierCache",
    "get_dossier_cache",
    "reset_dossier_cache",
    "_is_keri_event",
]
