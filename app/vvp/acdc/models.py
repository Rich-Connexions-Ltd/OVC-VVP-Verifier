# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""ACDC credential data model and DAG structure."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# CESR SAID prefix for Blake3-256 digests (one-character code "E").
_SAID_PREFIX = "E"
# Length of the base64url-encoded portion after the prefix (43 chars).
_SAID_B64_LEN = 43
# Total SAID length: prefix + 43 = 44 characters.
_SAID_TOTAL_LEN = 44
# The 44-char placeholder used for SAID self-hashing.
_SAID_PLACEHOLDER = "#" * _SAID_TOTAL_LEN


@dataclass
class ACDC:
    """Parsed ACDC credential.

    Attributes
    ----------
    said : str
        The self-addressing identifier (``d`` field digest).
    issuer : str
        AID of the credential issuer (``i`` field).
    schema : str
        Schema SAID (``s`` field — may be extracted from a nested dict).
    attributes : dict
        Credential attributes (``a`` field).
    edges : dict
        Edges to other credentials (``e`` field).
    signatures : list[bytes]
        Attached cryptographic signatures (raw bytes).
    raw : dict
        The original dict for re-serialization and SAID verification.
    """

    said: str
    issuer: str
    schema: str
    attributes: dict
    edges: dict = field(default_factory=dict)
    signatures: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class DossierDAG:
    """Directed acyclic graph of chained ACDC credentials.

    The graph represents the credential hierarchy within a VVP dossier.
    Nodes are individual ACDC credentials keyed by their SAID.  Edges
    represent chaining relationships (the ``e`` field in ACDC).

    Attributes
    ----------
    nodes : dict[str, ACDC]
        Credentials indexed by SAID.
    edges : list[tuple[str, str, str]]
        Directed edges as ``(from_said, to_said, edge_name)`` triples.
    root : str | None
        The SAID of the root credential (the credential that is not the
        target of any edge).
    """

    nodes: Dict[str, ACDC] = field(default_factory=dict)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)
    root: Optional[str] = None
