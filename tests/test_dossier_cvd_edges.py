# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for dossier CVD edge validation (Sprint 88, Component 2).

Validates validate_dossier_cvd_edges() — structural edge validation
for the dossier root CVD credential.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

import pytest

from app.vvp.schema import (
    CredentialClassification,
    SchemaGovernanceStatus,
)
from app.vvp.api_models import ClaimStatus
from app.vvp.dossier.validator import (
    DOSSIER_CVD_REQUIRED_EDGES,
    DOSSIER_CVD_OPTIONAL_EDGES,
    validate_dossier_cvd_edges,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _MockACDC:
    """Minimal ACDC stub for CVD edge testing."""
    said: str = "Eroot"
    issuer: str = "Eissuer"
    schema_said: str = "Eschema"
    edges: Optional[Dict] = None
    attributes: Optional[Dict] = None


def _governed(said: str, cred_type: str = "LE") -> CredentialClassification:
    return CredentialClassification(cred_type, SchemaGovernanceStatus.GOVERNED, said)


def _unclassified(said: str) -> CredentialClassification:
    return CredentialClassification("APE", SchemaGovernanceStatus.UNCLASSIFIED, said)


def _make_dossier_with_edges(edge_names, optional_edges=None):
    """Build a mock dossier root with required edges and target ACDCs."""
    edges = {}
    acdcs = {}
    classifications = {}
    for name in edge_names:
        target_said = f"E{name}_target"
        edges[name] = {"n": target_said}
        acdcs[target_said] = _MockACDC(said=target_said)
        classifications[target_said] = _governed(target_said)
    for name in (optional_edges or []):
        target_said = f"E{name}_target"
        edges[name] = {"n": target_said}
        acdcs[target_said] = _MockACDC(said=target_said)
        classifications[target_said] = _governed(target_said)
    root = _MockACDC(edges=edges)
    return root, acdcs, classifications


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestCVDEdgeConstants:
    def test_required_edges_are_four(self):
        assert DOSSIER_CVD_REQUIRED_EDGES == frozenset({"vetting", "alloc", "tnalloc", "delsig"})

    def test_optional_edges(self):
        assert DOSSIER_CVD_OPTIONAL_EDGES == frozenset({"bownr", "bproxy"})


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestCVDEdgesValid:
    def test_all_required_edges_present_and_governed(self):
        root, acdcs, cls = _make_dossier_with_edges(DOSSIER_CVD_REQUIRED_EDGES)
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.VALID
        assert evidence == []

    def test_required_plus_optional_edges(self):
        root, acdcs, cls = _make_dossier_with_edges(
            DOSSIER_CVD_REQUIRED_EDGES, optional_edges=["bownr"]
        )
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.VALID

    def test_string_edge_reference(self):
        """Edge references can be plain strings (direct SAID)."""
        target_said = "Edirect_target"
        edges = {name: {"n": f"E{name}_target"} for name in DOSSIER_CVD_REQUIRED_EDGES}
        edges["vetting"] = target_said  # override one with string ref
        acdcs = {f"E{name}_target": _MockACDC(said=f"E{name}_target") for name in DOSSIER_CVD_REQUIRED_EDGES}
        acdcs[target_said] = _MockACDC(said=target_said)
        del acdcs["Evetting_target"]
        cls = {s: _governed(s) for s in acdcs}
        root = _MockACDC(edges=edges)
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.VALID


# ---------------------------------------------------------------------------
# Missing required edges
# ---------------------------------------------------------------------------

class TestCVDEdgesMissing:
    def test_missing_one_required_edge(self):
        edges = list(DOSSIER_CVD_REQUIRED_EDGES)
        edges.remove("vetting")
        root, acdcs, cls = _make_dossier_with_edges(edges)
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.INVALID
        assert any("CVD_MISSING_REQUIRED_EDGE" in e for e in evidence)
        assert any("vetting" in e for e in evidence)

    def test_missing_all_required_edges(self):
        root = _MockACDC(edges={})
        status, evidence = validate_dossier_cvd_edges(root, {}, {})
        assert status == ClaimStatus.INVALID
        assert len(evidence) == 4  # all 4 missing

    def test_no_edges_at_all(self):
        root = _MockACDC(edges=None)
        # edges is None → empty dict, all required missing
        status, evidence = validate_dossier_cvd_edges(root, {}, {})
        assert status == ClaimStatus.INVALID


# ---------------------------------------------------------------------------
# Target not in dossier
# ---------------------------------------------------------------------------

class TestCVDEdgesTargetMissing:
    def test_required_target_not_in_dossier(self):
        root, acdcs, cls = _make_dossier_with_edges(DOSSIER_CVD_REQUIRED_EDGES)
        # Remove one target from dossier
        target = "Evetting_target"
        del acdcs[target]
        del cls[target]
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.INVALID
        assert any("CVD_TARGET_NOT_IN_DOSSIER" in e for e in evidence)

    def test_optional_target_not_in_dossier_is_warning(self):
        root, acdcs, cls = _make_dossier_with_edges(
            DOSSIER_CVD_REQUIRED_EDGES, optional_edges=["bownr"]
        )
        del acdcs["Ebownr_target"]
        del cls["Ebownr_target"]
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        # Optional missing should NOT cause INVALID
        assert status == ClaimStatus.VALID
        assert any("CVD_TARGET_NOT_IN_DOSSIER" in e and "optional" in e for e in evidence)


# ---------------------------------------------------------------------------
# Governance status
# ---------------------------------------------------------------------------

class TestCVDEdgesGovernance:
    def test_unclassified_target_produces_indeterminate(self):
        root, acdcs, cls = _make_dossier_with_edges(DOSSIER_CVD_REQUIRED_EDGES)
        cls["Evetting_target"] = _unclassified("Evetting_target")
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.INDETERMINATE
        assert any("CVD_TARGET_NOT_GOVERNED" in e for e in evidence)

    def test_multiple_unclassified_targets(self):
        root, acdcs, cls = _make_dossier_with_edges(DOSSIER_CVD_REQUIRED_EDGES)
        cls["Evetting_target"] = _unclassified("Evetting_target")
        cls["Ealloc_target"] = _unclassified("Ealloc_target")
        status, evidence = validate_dossier_cvd_edges(root, acdcs, cls)
        assert status == ClaimStatus.INDETERMINATE
        governance_warnings = [e for e in evidence if "CVD_TARGET_NOT_GOVERNED" in e]
        assert len(governance_warnings) == 2
