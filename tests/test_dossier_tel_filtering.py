# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for KERI TEL event filtering in dossier CESR streams (Sprint 84)."""

import json

import pytest

from app.vvp.dossier import DossierParseResult, _is_keri_event, parse_dossier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _acdc(said="ESaid123", issuer="BIssuer1", schema="ESchema1"):
    return {"d": said, "i": issuer, "s": schema, "a": {"attr": "val"}}


def _tel_iss(said="ESaid123", issuer="BIssuer1", registry="EReg1"):
    """Minimal KERI10 TEL issuance event."""
    return {
        "v": "KERI10JSON000001_",
        "t": "iss",
        "d": said,
        "i": issuer,
        "s": "0",
        "ri": registry,
    }


def _bytes(obj):
    return json.dumps(obj).encode()


# ---------------------------------------------------------------------------
# _is_keri_event tests
# ---------------------------------------------------------------------------

class TestIsKeriEvent:
    def test_t_field_identifies_keri_event(self):
        assert _is_keri_event({"t": "iss", "d": "X", "i": "Y", "s": "0"}) is True

    def test_keri10_version_identifies_keri_event(self):
        assert _is_keri_event({"v": "KERI10JSON000001_", "d": "X", "i": "Y"}) is True

    def test_acdc10_version_is_not_keri_event(self):
        assert _is_keri_event({"v": "ACDC10JSON000001_", "d": "X", "i": "Y", "s": "ESchema"}) is False

    def test_plain_acdc_is_not_keri_event(self):
        assert _is_keri_event(_acdc()) is False

    def test_empty_object_is_not_keri_event(self):
        assert _is_keri_event({}) is False

    def test_object_with_non_string_v_is_not_keri_event(self):
        assert _is_keri_event({"v": 42, "d": "X"}) is False


# ---------------------------------------------------------------------------
# parse_dossier — Strategy 3 TEL bifurcation
# ---------------------------------------------------------------------------

class TestParseDossierTelFiltering:
    def test_acdc_only_stream_unchanged(self):
        """CESR stream with no KERI events → tel_events empty, ACDCs returned."""
        acdc1 = _acdc("ESAID1", schema="ESchema1")
        acdc2 = _acdc("ESAID2", schema="ESchema2")
        raw = (_bytes(acdc1) + b"\n" + _bytes(acdc2)).lstrip(b"[")
        # Strategy 3 triggers when content doesn't start with [ or {
        # Build a mixed stream format by joining two JSON objects
        stream = json.dumps(acdc1).encode() + b" " + json.dumps(acdc2).encode()
        result = parse_dossier(stream)
        assert isinstance(result, DossierParseResult)
        assert len(result.tel_events) == 0
        assert len(result.acdcs) == 2

    def test_mixed_stream_separates_tel_events(self):
        """Mixed stream with ACDCs and TEL events → correct bifurcation."""
        acdc = _acdc("ESAID1", schema="ESchema1")
        tel = _tel_iss("ESAID1")
        # CESR-style mixed stream: both objects as adjacent JSON blobs
        stream = json.dumps(acdc).encode() + b" " + json.dumps(tel).encode()
        result = parse_dossier(stream)
        assert isinstance(result, DossierParseResult)
        assert len(result.acdcs) == 1
        assert len(result.tel_events) == 1
        assert result.tel_events[0]["t"] == "iss"

    def test_tel_events_are_retained_not_discarded(self):
        """TEL events are preserved in tel_events, not silently dropped."""
        acdc = _acdc()
        tel1 = _tel_iss("ESAID1")
        tel2 = {**_tel_iss("ESAID2"), "t": "rev"}
        stream = (
            json.dumps(acdc).encode()
            + b" "
            + json.dumps(tel1).encode()
            + b" "
            + json.dumps(tel2).encode()
        )
        result = parse_dossier(stream)
        assert len(result.tel_events) == 2
        saids = {e["d"] for e in result.tel_events}
        assert "ESAID1" in saids
        assert "ESAID2" in saids

    def test_unknown_object_falls_through_to_acdc_parse(self):
        """Object without t/KERI10 is attempted as ACDC; if parse fails it is dropped."""
        unknown = {"d": "ESAID1", "i": "BIssuer1", "s": "ESchema1", "x": "extra"}
        stream = json.dumps(unknown).encode()
        # parse_acdc will succeed here (extra fields are allowed)
        result = parse_dossier(stream)
        assert len(result.acdcs) == 1

    def test_strategy1_json_array_returns_parse_result(self):
        """JSON array (Strategy 1) returns DossierParseResult with empty tel_events."""
        acdc = _acdc()
        raw = json.dumps([acdc]).encode()
        result = parse_dossier(raw)
        assert isinstance(result, DossierParseResult)
        assert len(result.acdcs) == 1
        assert result.tel_events == []

    def test_strategy2_single_object_returns_parse_result(self):
        """Single JSON object (Strategy 2b) returns DossierParseResult."""
        acdc = _acdc()
        raw = json.dumps(acdc).encode()
        result = parse_dossier(raw)
        assert isinstance(result, DossierParseResult)
        assert len(result.acdcs) == 1
        assert result.tel_events == []
