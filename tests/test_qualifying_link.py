# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for LE→QVI qualifying link validation (Sprint 88, Component 3).

Validates validate_qualifying_link() and QualifyingLinkResult.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

import pytest

from app.vvp.schema import (
    KNOWN_SCHEMAS,
    CredentialClassification,
    SchemaGovernanceStatus,
)
from app.vvp.acdc.vlei_chain import (
    QualifyingLinkResult,
    validate_qualifying_link,
    VLEI_SCHEMA_SAIDS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TRUSTED_ROOT = "EGLEIF_root_aid_for_testing_1234567890"
QVI_SAID = "Eqvi_credential_said_for_testing"
LE_ISSUER = "Ele_issuer_aid_for_testing_1234567890"


@dataclass
class _MockACDC:
    said: str = ""
    issuer: str = ""
    schema_said: str = ""
    edges: Optional[Dict] = None
    attributes: Optional[Dict] = None


def _make_governed_qvi_cls():
    return CredentialClassification("QVI", SchemaGovernanceStatus.GOVERNED, VLEI_SCHEMA_SAIDS["QVI"])


def _make_valid_setup():
    """Build a valid LE→QVI qualifying link scenario."""
    le = _MockACDC(
        said="Ele_said",
        issuer=LE_ISSUER,
        schema_said=VLEI_SCHEMA_SAIDS["LE"],
        edges={"qvi": {"n": QVI_SAID}},
    )
    qvi = _MockACDC(
        said=QVI_SAID,
        issuer=TRUSTED_ROOT,
        schema_said=VLEI_SCHEMA_SAIDS["QVI"],
        attributes={"i": LE_ISSUER},  # issuee = LE issuer (I2I)
    )
    classifications = {
        QVI_SAID: _make_governed_qvi_cls(),
    }
    resolved = {QVI_SAID: qvi}
    trusted_roots = frozenset({TRUSTED_ROOT})
    return le, classifications, resolved, trusted_roots


# ---------------------------------------------------------------------------
# QualifyingLinkResult
# ---------------------------------------------------------------------------

class TestQualifyingLinkResult:
    def test_result_is_frozen(self):
        r = QualifyingLinkResult(valid=True, status="valid")
        with pytest.raises(AttributeError):
            r.valid = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Valid qualifying link
# ---------------------------------------------------------------------------

class TestQualifyingLinkValid:
    def test_valid_le_qvi_link(self):
        le, cls, resolved, roots = _make_valid_setup()
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is True
        assert result.status == "valid"


# ---------------------------------------------------------------------------
# Invalid: missing edges
# ---------------------------------------------------------------------------

class TestQualifyingLinkMissingEdges:
    def test_no_edges(self):
        le, cls, resolved, roots = _make_valid_setup()
        le.edges = None
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "invalid"
        assert "no edges" in result.reason

    def test_no_qvi_edge(self):
        le, cls, resolved, roots = _make_valid_setup()
        le.edges = {"other": {"n": "Eother_said"}}
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert "missing required 'qvi' edge" in result.reason


# ---------------------------------------------------------------------------
# Indeterminate: QVI not found
# ---------------------------------------------------------------------------

class TestQualifyingLinkQVINotFound:
    def test_qvi_not_in_resolved(self):
        le, cls, resolved, roots = _make_valid_setup()
        del resolved[QVI_SAID]
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "indeterminate"
        assert "not found" in result.reason


# ---------------------------------------------------------------------------
# Governance checks
# ---------------------------------------------------------------------------

class TestQualifyingLinkGovernance:
    def test_qvi_not_governed(self):
        le, cls, resolved, roots = _make_valid_setup()
        cls[QVI_SAID] = CredentialClassification(
            "QVI", SchemaGovernanceStatus.UNCLASSIFIED, "Efake"
        )
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "indeterminate"
        assert "non-governed" in result.reason

    def test_qvi_wrong_type(self):
        le, cls, resolved, roots = _make_valid_setup()
        cls[QVI_SAID] = CredentialClassification(
            "LE", SchemaGovernanceStatus.GOVERNED, VLEI_SCHEMA_SAIDS["LE"]
        )
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "invalid"
        assert "not QVI" in result.reason

    def test_no_classification(self):
        le, cls, resolved, roots = _make_valid_setup()
        del cls[QVI_SAID]
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "indeterminate"
        assert "no classification" in result.reason


# ---------------------------------------------------------------------------
# Trusted root checks
# ---------------------------------------------------------------------------

class TestQualifyingLinkTrustedRoot:
    def test_qvi_issuer_not_trusted(self):
        le, cls, resolved, roots = _make_valid_setup()
        resolved[QVI_SAID].issuer = "Euntrusted_aid"
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "invalid"
        assert "not a trusted root" in result.reason


# ---------------------------------------------------------------------------
# I2I semantics
# ---------------------------------------------------------------------------

class TestQualifyingLinkI2I:
    def test_i2i_violation(self):
        le, cls, resolved, roots = _make_valid_setup()
        # QVI issuee != LE issuer
        resolved[QVI_SAID].attributes = {"i": "Ewrong_issuee"}
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is False
        assert result.status == "invalid"
        assert "I2I violation" in result.reason

    def test_qvi_without_issuee_passes(self):
        """If QVI has no issuee binding, I2I check is skipped."""
        le, cls, resolved, roots = _make_valid_setup()
        resolved[QVI_SAID].attributes = {}  # no 'i' field
        result = validate_qualifying_link(le, cls, resolved, roots)
        assert result.valid is True
