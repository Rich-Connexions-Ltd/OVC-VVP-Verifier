# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for schema-first credential classification (Sprint 88).

Validates SchemaGovernanceStatus, CredentialClassification, and
classify_credential() — the canonical classification layer that
replaces heuristic credential_type for governance-sensitive decisions.
"""

from app.vvp.schema import (
    CredentialClassification,
    SchemaGovernanceStatus,
    classify_credential,
    KNOWN_SCHEMAS,
    _SCHEMA_SAID_TO_TYPE,
    _PENDING_GOVERNANCE_TYPES,
)


# --- Reverse index tests ---

def test_reverse_index_covers_all_governed_saids():
    """Every non-empty SAID in KNOWN_SCHEMAS appears in _SCHEMA_SAID_TO_TYPE."""
    for cred_type, saids in KNOWN_SCHEMAS.items():
        for said in saids:
            assert said in _SCHEMA_SAID_TO_TYPE, f"{said} missing from reverse index"
            assert _SCHEMA_SAID_TO_TYPE[said] == cred_type


def test_pending_governance_types():
    """Types with empty frozenset are pending governance."""
    assert "APE" in _PENDING_GOVERNANCE_TYPES
    # LE has SAIDs so should not be pending
    assert "LE" not in _PENDING_GOVERNANCE_TYPES


# --- classify_credential tests ---

def test_governed_schema_produces_governed():
    """Known governance SAID → GOVERNED with authoritative type."""
    le_said = next(iter(KNOWN_SCHEMAS["LE"]))
    result = classify_credential(le_said, heuristic_type_hint="LE")
    assert result.governance_status == SchemaGovernanceStatus.GOVERNED
    assert result.credential_type == "LE"
    assert result.is_governed is True
    assert result.type_is_reliable is True


def test_governed_ignores_wrong_heuristic_hint():
    """Heuristic hint cannot override governed type from schema lookup."""
    le_said = next(iter(KNOWN_SCHEMAS["LE"]))
    result = classify_credential(le_said, heuristic_type_hint="APE")
    assert result.governance_status == SchemaGovernanceStatus.GOVERNED
    assert result.credential_type == "LE"  # From registry, not hint


def test_pending_governance_type_produces_unclassified():
    """Unknown SAID + pending-governance hint → UNCLASSIFIED."""
    result = classify_credential("Eunknown_said_for_ape", heuristic_type_hint="APE")
    assert result.governance_status == SchemaGovernanceStatus.UNCLASSIFIED
    assert result.credential_type == "APE"
    assert result.is_governed is False
    assert result.type_is_reliable is False


def test_unknown_said_unknown_type_produces_unrecognized():
    """Unknown SAID + unknown type hint → UNRECOGNIZED."""
    result = classify_credential("Etotally_unknown_said", heuristic_type_hint="unknown")
    assert result.governance_status == SchemaGovernanceStatus.UNRECOGNIZED
    assert result.credential_type == "unknown"
    assert result.is_governed is False
    assert result.type_is_reliable is False


def test_unknown_said_governed_type_hint_produces_unrecognized():
    """Unknown SAID + governed type hint (LE) → UNRECOGNIZED, not GOVERNED."""
    result = classify_credential("Efake_le_said", heuristic_type_hint="LE")
    assert result.governance_status == SchemaGovernanceStatus.UNRECOGNIZED
    assert result.credential_type == "LE"
    assert result.type_is_reliable is False


def test_classification_is_immutable():
    """CredentialClassification is frozen — cannot be mutated."""
    result = classify_credential("Eunknown", heuristic_type_hint="APE")
    try:
        result.credential_type = "LE"  # type: ignore[misc]
        assert False, "Should have raised FrozenInstanceError"
    except AttributeError:
        pass  # Expected — frozen dataclass


def test_all_governed_saids_classify_correctly():
    """Every SAID in the registry classifies to GOVERNED with correct type."""
    for cred_type, saids in KNOWN_SCHEMAS.items():
        for said in saids:
            result = classify_credential(said)
            assert result.governance_status == SchemaGovernanceStatus.GOVERNED
            assert result.credential_type == cred_type
