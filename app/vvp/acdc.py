# Copyright (c) Rich Connexions Ltd. All rights reserved.
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

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from app.vvp.canonical import (
    FIELD_ORDER,
    CanonicalSerializationError,
    canonical_serialize,
    compute_acdc_said,
    most_compact_form,
)
from app.vvp.models import (
    ChildLink,
    ClaimNode,
    ClaimStatus,
    ErrorCode,
    ErrorDetail,
    make_error,
)
from app.vvp.schema import get_credential_type, is_brand_schema

# Lazy import: blake3 is required for SAID computation but may not
# be installed in lightweight environments.
try:
    import blake3
except ImportError:  # pragma: no cover
    blake3 = None  # type: ignore[assignment]

# Lazy import: pysodium for Ed25519 signature verification.
try:
    import pysodium
except ImportError:  # pragma: no cover
    pysodium = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

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

# CESR SAID prefix for Blake3-256 digests (one-character code "E").
_SAID_PREFIX = "E"
# Length of the base64url-encoded portion after the prefix (43 chars).
_SAID_B64_LEN = 43
# Total SAID length: prefix + 43 = 44 characters.
_SAID_TOTAL_LEN = 44
# The 44-char placeholder used for SAID self-hashing.
_SAID_PLACEHOLDER = "#" * _SAID_TOTAL_LEN


# ======================================================================
# ACDC dataclass
# ======================================================================


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


# ======================================================================
# Parsing
# ======================================================================


def parse_acdc(data: dict) -> ACDC:
    """Parse a dictionary into an ACDC credential.

    Parameters
    ----------
    data : dict
        A dictionary representing a serialized ACDC credential.  Must
        contain at least ``d`` (SAID), ``i`` (issuer), ``s`` (schema),
        and ``a`` (attributes).

    Returns
    -------
    ACDC
        The parsed credential.

    Raises
    ------
    ValueError
        If required fields are missing or have unexpected types.
    """
    if not isinstance(data, dict):
        raise ValueError(f"ACDC data must be a dict, got {type(data).__name__}")

    said = data.get("d", "")
    if not said:
        raise ValueError("ACDC missing 'd' (SAID) field")

    issuer = data.get("i", "")
    if not issuer:
        raise ValueError("ACDC missing 'i' (issuer) field")

    # Schema may be a bare SAID string or a dict with {"d": "<said>", ...}.
    schema_raw = data.get("s")
    if schema_raw is None:
        raise ValueError("ACDC missing 's' (schema) field")
    if isinstance(schema_raw, str):
        schema = schema_raw
    elif isinstance(schema_raw, dict):
        schema = schema_raw.get("d", "")
        if not schema:
            raise ValueError("ACDC schema dict missing 'd' field")
    else:
        raise ValueError(
            f"ACDC 's' field must be str or dict, got {type(schema_raw).__name__}"
        )

    attributes = data.get("a", {})
    if not isinstance(attributes, dict):
        raise ValueError(
            f"ACDC 'a' field must be a dict, got {type(attributes).__name__}"
        )

    edges = data.get("e", {})
    if not isinstance(edges, dict):
        raise ValueError(
            f"ACDC 'e' field must be a dict, got {type(edges).__name__}"
        )

    return ACDC(
        said=said,
        issuer=issuer,
        schema=schema,
        attributes=attributes,
        edges=edges,
        raw=dict(data),
    )


# ======================================================================
# SAID computation
# ======================================================================


def _base64url_encode_no_pad(data: bytes) -> str:
    """Base64url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compute_said(data: dict) -> str:
    """Compute the SAID (Self-Addressing IDentifier) for a KERI/ACDC dict.

    The SAID is computed by:
    1. Replacing the ``d`` field with a 44-char ``#`` placeholder.
    2. Serializing to compact JSON (using KERI field ordering if a ``t``
       field is present, otherwise key-sorted).
    3. Hashing the serialized bytes with Blake3-256.
    4. Encoding the first 32 bytes as ``"E" + base64url[:43]``.

    Parameters
    ----------
    data : dict
        The KERI event or ACDC credential dict.  Must contain a ``d``
        field (the existing SAID value is replaced for computation).

    Returns
    -------
    str
        The computed 44-character SAID, or ``""`` if the ``d`` field is
        absent or blake3 is unavailable.
    """
    if "d" not in data:
        return ""

    if blake3 is None:  # pragma: no cover
        logger.warning("blake3 not installed; SAID computation unavailable")
        return ""

    event_type = data.get("t")

    # If the event has a type and canonical serialization supports it,
    # use most_compact_form for deterministic placeholder insertion.
    if event_type and event_type in FIELD_ORDER:
        try:
            serialized = most_compact_form(data, said_field="d")
        except CanonicalSerializationError:
            # Fall back to manual placeholder approach.
            serialized = _placeholder_serialize(data)

        digest = blake3.blake3(serialized).digest()
        encoded = _base64url_encode_no_pad(digest[:32])

        # CESR E-prefix SAID: "E" + first 43 base64url characters.
        return _SAID_PREFIX + encoded[:_SAID_B64_LEN]
    else:
        # ACDC credential (no 't' field) - use ACDC canonical ordering
        result = compute_acdc_said(data)
        if result:
            return result
        # Fallback to simple placeholder if compute_acdc_said returns empty
        serialized = _placeholder_serialize(data)
        digest = blake3.blake3(serialized).digest()
        encoded = _base64url_encode_no_pad(digest[:32])
        return _SAID_PREFIX + encoded[:_SAID_B64_LEN]


def _placeholder_serialize(data: dict) -> bytes:
    """Serialize *data* with the ``d`` field replaced by a placeholder.

    For ACDC credentials that lack a ``t`` field (and therefore cannot
    use :func:`canonical_serialize`), we produce deterministic compact
    JSON by preserving the original key order and using compact
    separators.

    If the ``i`` field equals the ``d`` field (self-addressing inception
    pattern), both are replaced with the placeholder.
    """
    work = dict(data)
    original_said = work["d"]
    work["d"] = _SAID_PLACEHOLDER

    # Self-addressing: i == d (inception / delegation).
    if work.get("i") == original_said:
        work["i"] = _SAID_PLACEHOLDER

    return json.dumps(work, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_acdc_said(acdc: ACDC) -> bool:
    """Validate that an ACDC's ``d`` field matches its computed SAID.

    Parameters
    ----------
    acdc : ACDC
        The parsed ACDC credential.

    Returns
    -------
    bool
        ``True`` if the recomputed SAID matches ``acdc.said``.
    """
    recomputed = compute_said(acdc.raw)
    if not recomputed:
        logger.warning("SAID computation returned empty for ACDC %s", acdc.said)
        return False
    match = recomputed == acdc.said
    if not match:
        logger.debug(
            "SAID mismatch for ACDC: expected=%s, computed=%s",
            acdc.said,
            recomputed,
        )
    return match


# ======================================================================
# Signature verification
# ======================================================================


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


# ======================================================================
# Credential graph (DAG)
# ======================================================================


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


# ======================================================================
# DAG validation
# ======================================================================


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


# ======================================================================
# Chain verification
# ======================================================================


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
    adjacency: Dict[str, List[Tuple[str, str]]] = {
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
