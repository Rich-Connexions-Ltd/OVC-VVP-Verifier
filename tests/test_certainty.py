# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for certainty field and X-VVP-Certainty SIP header (Sprint 84)."""

import pytest

from app.vvp.api_models import ClaimStatus, VerifyResponse, _status_to_certainty
from app.sip.builder import _sanitize_sip_header_value, build_vvp_headers


# ---------------------------------------------------------------------------
# _status_to_certainty
# ---------------------------------------------------------------------------

class TestStatusToCertainty:
    def test_certainty_valid_is_full(self):
        assert _status_to_certainty(ClaimStatus.VALID) == "full"

    def test_certainty_indeterminate_is_partial(self):
        assert _status_to_certainty(ClaimStatus.INDETERMINATE) == "partial"

    def test_certainty_invalid_is_none(self):
        assert _status_to_certainty(ClaimStatus.INVALID) == "none"


# ---------------------------------------------------------------------------
# VerifyResponse.certainty field
# ---------------------------------------------------------------------------

class TestVerifyResponseCertainty:
    def _make_response(self, status: ClaimStatus, certainty: str = "none") -> VerifyResponse:
        return VerifyResponse(
            request_id="test",
            overall_status=status,
            certainty=certainty,
        )

    def test_default_certainty_is_none(self):
        resp = VerifyResponse(request_id="x", overall_status=ClaimStatus.VALID)
        assert resp.certainty == "none"

    def test_certainty_field_accepted(self):
        resp = self._make_response(ClaimStatus.INDETERMINATE, "partial")
        assert resp.certainty == "partial"

    def test_certainty_full_accepted(self):
        resp = self._make_response(ClaimStatus.VALID, "full")
        assert resp.certainty == "full"


# ---------------------------------------------------------------------------
# X-VVP-Certainty SIP header
# ---------------------------------------------------------------------------

class TestSipCertaintyHeader:
    def _make_verify_response(self, certainty: str, brand_name=None):
        return VerifyResponse(
            request_id="test",
            overall_status=ClaimStatus.INDETERMINATE,
            certainty=certainty,
            brand_name=brand_name,
        )

    def test_sip_header_contains_certainty(self):
        resp = self._make_verify_response("partial")
        headers = build_vvp_headers(resp)
        assert headers.get("X-VVP-Certainty") == "partial"

    def test_sip_header_certainty_full(self):
        resp = self._make_verify_response("full")
        headers = build_vvp_headers(resp)
        assert headers.get("X-VVP-Certainty") == "full"

    def test_sip_header_certainty_none(self):
        resp = self._make_verify_response("none")
        headers = build_vvp_headers(resp)
        assert headers.get("X-VVP-Certainty") == "none"

    def test_unknown_certainty_value_defaulted_to_none(self):
        """Invalid certainty values are coerced to 'none' for safety."""
        resp = self._make_verify_response("full")
        # Bypass Pydantic validation by patching the attribute directly
        object.__setattr__(resp, "certainty", "suspicious_value")
        headers = build_vvp_headers(resp)
        assert headers.get("X-VVP-Certainty") == "none"


# ---------------------------------------------------------------------------
# _sanitize_sip_header_value
# ---------------------------------------------------------------------------

class TestSanitizeSipHeaderValue:
    def test_sanitize_strips_control_chars(self):
        assert _sanitize_sip_header_value("Hello\r\nWorld") == "HelloWorld"

    def test_sanitize_strips_null(self):
        assert _sanitize_sip_header_value("Acme\x00Corp") == "AcmeCorp"

    def test_sanitize_strips_del(self):
        assert _sanitize_sip_header_value("Acme\x7fCorp") == "AcmeCorp"

    def test_sanitize_truncates_at_256(self):
        long_name = "A" * 300
        result = _sanitize_sip_header_value(long_name)
        assert len(result) == 256

    def test_sanitize_returns_none_for_empty(self):
        assert _sanitize_sip_header_value("") is None

    def test_sanitize_returns_none_for_control_chars_only(self):
        assert _sanitize_sip_header_value("\r\n\t") is None

    def test_sanitize_strips_tab(self):
        # Tab (\x09) is a control char
        assert _sanitize_sip_header_value("Tab\there") == "Tabhere"

    def test_brand_name_with_crlf_stripped_from_header(self):
        """Brand name CRLF injection → stripped before SIP header emission."""
        resp = VerifyResponse(
            request_id="test",
            overall_status=ClaimStatus.VALID,
            certainty="full",
            brand_name="Acme Corp\r\nX-Injected: evil",
        )
        headers = build_vvp_headers(resp)
        brand = headers.get("X-VVP-Brand-Name", "")
        assert "\r" not in brand
        assert "\n" not in brand
        assert brand == "Acme CorpX-Injected: evil"
