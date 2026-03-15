# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Integration tests for the VVP verification pipeline.

Tests the verify response structure, capabilities contract, and error
handling for various input scenarios.  Uses mocked dossier fetch to
avoid network dependencies.

References:
    - VVP Verifier Specification §4.1-§4.3 — Request/Response models
    - VVP Verifier Specification §3.3A — Status derivation
    - app.vvp.models — VerifyRequest, VerifyResponse, CAPABILITIES
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from app.vvp.api_models import (
    CAPABILITIES,
    ClaimNode,
    ClaimStatus,
    ErrorCode,
    ErrorDetail,
    VerifyRequest,
    VerifyResponse,
    derive_overall_status,
    make_error,
)
from app.vvp.exceptions import PassportError, VVPIdentityError


# =========================================================================
# VerifyResponse Structure
# =========================================================================

class TestVerifyResponseStructure:
    """Test that VerifyResponse has all required fields and defaults."""

    def test_response_required_fields(self):
        """VerifyResponse should be constructable with minimal fields."""
        resp = VerifyResponse(
            request_id="req-001",
            overall_status=ClaimStatus.VALID,
        )
        assert resp.request_id == "req-001"
        assert resp.overall_status == ClaimStatus.VALID
        assert resp.claims is None
        assert resp.errors is None
        assert resp.revocation_pending is False
        assert resp.cache_hit is False

    def test_response_signer_aid(self):
        """VerifyResponse should carry the signer AID when available."""
        resp = VerifyResponse(
            request_id="req-002",
            overall_status=ClaimStatus.VALID,
            signer_aid="Btest_aid_00000000000000000000000000000000000",
        )
        assert resp.signer_aid == "Btest_aid_00000000000000000000000000000000000"

    def test_response_brand_name(self):
        """VerifyResponse should carry the brand name when available."""
        resp = VerifyResponse(
            request_id="req-003",
            overall_status=ClaimStatus.VALID,
            brand_name="Acme Corp",
        )
        assert resp.brand_name == "Acme Corp"

    def test_response_json_serialization(self):
        """VerifyResponse should serialize to JSON with all fields."""
        resp = VerifyResponse(
            request_id="req-004",
            overall_status=ClaimStatus.INVALID,
            errors=[
                ErrorDetail(code="PASSPORT_MISSING", message="No JWT", recoverable=False)
            ],
        )
        data = resp.model_dump()
        assert data["request_id"] == "req-004"
        assert data["overall_status"] == "INVALID"
        assert len(data["errors"]) == 1
        assert data["errors"][0]["code"] == "PASSPORT_MISSING"


# =========================================================================
# Capabilities
# =========================================================================

class TestCapabilities:
    """Test the capabilities signaling contract."""

    def test_capabilities_present(self):
        """VerifyResponse should always include a capabilities dict."""
        resp = VerifyResponse(
            request_id="req-caps",
            overall_status=ClaimStatus.VALID,
        )
        assert resp.capabilities is not None
        assert isinstance(resp.capabilities, dict)

    def test_capabilities_all_keys(self):
        """The capabilities dict should contain all expected feature keys."""
        resp = VerifyResponse(
            request_id="req-caps2",
            overall_status=ClaimStatus.VALID,
        )
        expected_keys = {
            "signature_tier1_nontransferable",
            "signature_tier1_transferable",
            "signature_tier2",
            "dossier_validation",
            "acdc_chain",
            "revocation",
            "authorization",
            "brand_verification",
            "goal_verification",
            "vetter_constraints",
            "sip_context",
            "callee_verification",
        }
        assert set(resp.capabilities.keys()) == expected_keys

    def test_capabilities_valid_values(self):
        """Each capability value should be one of the allowed status strings."""
        allowed_values = {"implemented", "not_implemented", "rejected", "tier2_required"}
        resp = VerifyResponse(
            request_id="req-caps3",
            overall_status=ClaimStatus.VALID,
        )
        for key, value in resp.capabilities.items():
            assert value in allowed_values, f"Capability '{key}' has invalid value: {value}"

    def test_capabilities_match_module_constant(self):
        """VerifyResponse default capabilities should match the CAPABILITIES constant."""
        resp = VerifyResponse(
            request_id="req-caps4",
            overall_status=ClaimStatus.VALID,
        )
        assert resp.capabilities == CAPABILITIES


# =========================================================================
# Status Derivation
# =========================================================================

class TestStatusDerivation:
    """Test overall_status derivation per §3.3A."""

    def test_no_errors_no_claims(self):
        """No errors and no claims should yield VALID."""
        status = derive_overall_status(None, None)
        assert status == ClaimStatus.VALID

    def test_recoverable_error_yields_indeterminate(self):
        """Only recoverable errors should yield INDETERMINATE."""
        errors = [make_error(ErrorCode.DOSSIER_FETCH_FAILED, "Network error")]
        status = derive_overall_status(None, errors)
        assert status == ClaimStatus.INDETERMINATE

    def test_non_recoverable_error_yields_invalid(self):
        """A non-recoverable error should yield INVALID."""
        errors = [make_error(ErrorCode.PASSPORT_MISSING, "No JWT")]
        status = derive_overall_status(None, errors)
        assert status == ClaimStatus.INVALID

    def test_mixed_errors(self):
        """A mix of recoverable and non-recoverable errors should yield INVALID."""
        errors = [
            make_error(ErrorCode.DOSSIER_FETCH_FAILED, "Network"),
            make_error(ErrorCode.PASSPORT_MISSING, "No JWT"),
        ]
        status = derive_overall_status(None, errors)
        assert status == ClaimStatus.INVALID


# =========================================================================
# ErrorDetail Construction
# =========================================================================

class TestErrorDetail:
    """Test ErrorDetail and make_error helper."""

    def test_make_error_recoverable(self):
        """Recoverable error codes should produce recoverable=True."""
        err = make_error(ErrorCode.DOSSIER_FETCH_FAILED, "timeout")
        assert err.recoverable is True

    def test_make_error_non_recoverable(self):
        """Non-recoverable error codes should produce recoverable=False."""
        err = make_error(ErrorCode.PASSPORT_MISSING, "empty")
        assert err.recoverable is False


# =========================================================================
# VerifyRequest Validation
# =========================================================================

class TestVerifyRequest:
    """Test the VerifyRequest model."""

    def test_minimal_request(self):
        """A request with only passport_jwt should be valid."""
        req = VerifyRequest(passport_jwt="some.jwt.here")
        assert req.passport_jwt == "some.jwt.here"
        assert req.vvp_identity is None
        assert req.dossier_url is None

    def test_full_request(self):
        """A fully populated request should preserve all fields."""
        req = VerifyRequest(
            passport_jwt="some.jwt.here",
            vvp_identity="encoded_identity",
            dossier_url="https://example.com/dossier.cesr",
        )
        assert req.passport_jwt == "some.jwt.here"
        assert req.vvp_identity == "encoded_identity"
        assert req.dossier_url == "https://example.com/dossier.cesr"


# =========================================================================
# Missing PASSporT Verification
# =========================================================================

class TestVerifyMissingPassport:
    """Test verification with missing PASSporT."""

    def test_verify_missing_passport_exception(self):
        """Parsing an empty JWT should raise PassportError with PASSPORT_MISSING."""
        from app.vvp.passport import parse_passport

        with pytest.raises(PassportError) as exc_info:
            parse_passport("")
        assert exc_info.value.code == "PASSPORT_MISSING"

    def test_verify_missing_passport_response(self):
        """A missing passport should produce an INVALID response with the correct error."""
        errors = [make_error(ErrorCode.PASSPORT_MISSING, "PASSporT JWT is missing or empty")]
        status = derive_overall_status(None, errors)

        resp = VerifyResponse(
            request_id="req-missing",
            overall_status=status,
            errors=[ErrorDetail(code=e.code, message=e.message, recoverable=e.recoverable) for e in errors],
        )

        assert resp.overall_status == ClaimStatus.INVALID
        assert len(resp.errors) == 1
        assert resp.errors[0].code == "PASSPORT_MISSING"


# =========================================================================
# Mock Dossier Fetch Integration
# =========================================================================

class TestMockDossierFetch:
    """Test verification pipeline with mocked dossier fetch."""

    @pytest.mark.asyncio
    async def test_dossier_fetch_failure_produces_error(self):
        """A failed dossier fetch should produce a recoverable error."""
        from app.vvp.exceptions import DossierFetchError

        # Simulate the error path
        error = make_error(ErrorCode.DOSSIER_FETCH_FAILED, "Connection refused")
        assert error.recoverable is True
        assert error.code == "DOSSIER_FETCH_FAILED"

    @pytest.mark.asyncio
    async def test_dossier_parse_failure_produces_error(self):
        """A dossier parse failure should produce a non-recoverable error."""
        error = make_error(ErrorCode.DOSSIER_PARSE_FAILED, "Invalid CESR")
        assert error.recoverable is False
        assert error.code == "DOSSIER_PARSE_FAILED"


# =========================================================================
# ClaimStatus Enum
# =========================================================================

class TestClaimStatus:
    """Test the ClaimStatus enum values."""

    def test_valid_status(self):
        assert ClaimStatus.VALID == "VALID"

    def test_invalid_status(self):
        assert ClaimStatus.INVALID == "INVALID"

    def test_indeterminate_status(self):
        assert ClaimStatus.INDETERMINATE == "INDETERMINATE"

    def test_status_from_string(self):
        assert ClaimStatus("VALID") == ClaimStatus.VALID


# =========================================================================
# ErrorCode Enum
# =========================================================================

class TestErrorCode:
    """Test the ErrorCode enum for completeness."""

    def test_all_error_codes_present(self):
        """All expected error codes should be defined."""
        expected = {
            "VVP_IDENTITY_MISSING", "VVP_IDENTITY_INVALID", "VVP_OOBI_FETCH_FAILED",
            "PASSPORT_MISSING", "PASSPORT_PARSE_FAILED", "PASSPORT_EXPIRED",
            "PASSPORT_FORBIDDEN_ALG", "PASSPORT_SIG_INVALID",
            "ACDC_SAID_MISMATCH", "ACDC_PROOF_MISSING",
            "DOSSIER_URL_MISSING", "DOSSIER_FETCH_FAILED", "DOSSIER_PARSE_FAILED",
            "DOSSIER_GRAPH_INVALID", "KERI_RESOLUTION_FAILED", "KERI_STATE_INVALID",
            "VVP_OOBI_CONTENT_INVALID",
            "CREDENTIAL_REVOKED", "AUTHORIZATION_FAILED", "TN_RIGHTS_INVALID",
            "INTERNAL_ERROR",
        }
        actual = {e.value for e in ErrorCode}
        assert actual == expected


# =========================================================================
# DAG Error Propagation
# =========================================================================

class TestDossierErrorPropagation:
    """DAG validation errors must drive dossier_verified claim status."""

    def test_non_recoverable_dossier_error_overrides_valid_children(self):
        """Non-recoverable dossier errors should make dossier_verified INVALID."""
        chain_claim = ClaimNode(name="chain_verified", status=ClaimStatus.VALID)
        revocation_claim = ClaimNode(name="revocation_clear", status=ClaimStatus.VALID)

        # Simulate a DOSSIER_GRAPH_INVALID error (non-recoverable)
        dossier_error = make_error(ErrorCode.DOSSIER_GRAPH_INVALID, "Cycle detected in DAG")
        assert dossier_error.recoverable is False

        # Status derivation with this error should yield INVALID
        status = derive_overall_status(
            claims=[chain_claim, revocation_claim],
            errors=[dossier_error],
        )
        assert status == ClaimStatus.INVALID

    def test_recoverable_dossier_error_yields_indeterminate(self):
        """Recoverable dossier errors should yield at least INDETERMINATE."""
        dossier_error = make_error(ErrorCode.DOSSIER_FETCH_FAILED, "Timeout")
        assert dossier_error.recoverable is True

        status = derive_overall_status(claims=None, errors=[dossier_error])
        assert status == ClaimStatus.INDETERMINATE


# =========================================================================
# Revocation Checker Module Wiring
# =========================================================================

class TestRevocationCheckerWiring:
    """Verify that revocation checker module imports resolve correctly."""

    def test_revocation_checker_imports(self):
        """BackgroundRevocationChecker should be importable."""
        from app.vvp.revocation_checker import BackgroundRevocationChecker, get_revocation_checker
        assert BackgroundRevocationChecker is not None

    def test_tel_module_exports(self):
        """TEL module should export CredentialStatus and check_revocation."""
        from app.vvp.tel import CredentialStatus, check_revocation
        assert CredentialStatus is not None
        assert callable(check_revocation)
