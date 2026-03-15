# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for the KERI subsystem (app/vvp/keri/).

Covers: exceptions, key_parser, kel_parser, cesr, cache, kel_resolver,
delegation, oobi, signature, and STIR parameter stripping.
"""

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Exception tests
# ---------------------------------------------------------------------------

from app.vvp.keri.exceptions import (
    KeriError,
    SignatureInvalidError,
    ResolutionFailedError,
    StateInvalidError,
    KELChainInvalidError,
    KeyNotYetValidError,
    DelegationNotSupportedError,
    OOBIContentInvalidError,
    CESRFramingError,
    CESRMalformedError,
    UnsupportedSerializationKind,
    redact_for_log,
)
from app.vvp.api_models import ErrorCode


class TestExceptions:
    """Exception hierarchy and error code mapping."""

    def test_signature_invalid_error_code(self):
        err = SignatureInvalidError("bad sig")
        assert err.code == ErrorCode.PASSPORT_SIG_INVALID

    def test_resolution_failed_error_code(self):
        err = ResolutionFailedError("network down")
        assert err.code == ErrorCode.KERI_RESOLUTION_FAILED

    def test_state_invalid_error_code(self):
        err = StateInvalidError("bad state")
        assert err.code == ErrorCode.KERI_STATE_INVALID

    def test_kel_chain_invalid_inherits_state_invalid(self):
        err = KELChainInvalidError("chain break")
        assert isinstance(err, StateInvalidError)
        assert err.code == ErrorCode.KERI_STATE_INVALID

    def test_key_not_yet_valid_inherits_state_invalid(self):
        err = KeyNotYetValidError("too early")
        assert isinstance(err, StateInvalidError)

    def test_delegation_not_supported_inherits_resolution(self):
        err = DelegationNotSupportedError("no chain")
        assert isinstance(err, ResolutionFailedError)

    def test_oobi_content_invalid_error_code(self):
        err = OOBIContentInvalidError("bad content")
        assert err.code == ErrorCode.VVP_OOBI_CONTENT_INVALID

    def test_cesr_framing_error_code(self):
        err = CESRFramingError("bad frame")
        assert err.code == ErrorCode.KERI_STATE_INVALID

    def test_unsupported_serialization(self):
        err = UnsupportedSerializationKind("CBOR")
        assert "CBOR" in str(err)
        assert err.code == ErrorCode.KERI_RESOLUTION_FAILED


class TestLogRedaction:
    """redact_for_log() tests."""

    def test_redact_jwt(self):
        jwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJlYnl0ZXM"
        result = redact_for_log(jwt, kind="jwt")
        assert "..." in result
        assert len(result) < len(jwt)

    def test_redact_tn(self):
        result = redact_for_log("+15551234567", kind="tn")
        assert "redacted" in result
        assert "15551234567" not in result

    def test_redact_url(self):
        result = redact_for_log("https://witness.example.com/oobi/AID123", kind="url")
        assert "witness.example.com" in result
        assert "AID123" not in result

    def test_redact_empty(self):
        assert redact_for_log("", kind="jwt") == ""

    def test_redact_generic_strips_jwts(self):
        text = "Error for eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJlYnl0ZXM"
        result = redact_for_log(text, kind="generic")
        assert "eyJpc3MiOiJ0ZXN0In0" not in result


# ---------------------------------------------------------------------------
# Key parser tests
# ---------------------------------------------------------------------------

from app.vvp.keri.key_parser import (
    VerificationKey,
    parse_kid_to_verkey,
    extract_aid_from_oobi_url,
)


class TestKeyParser:
    """Key parser tests."""

    def test_b_prefix_decodes_raw_key(self):
        # Generate a test B-prefix AID (43 chars of base64url after B)
        raw_key = b"\x01" * 32
        b64 = base64.urlsafe_b64encode(raw_key).decode("ascii").rstrip("=")
        aid = "B" + b64
        vk = parse_kid_to_verkey(aid)
        assert vk.raw == raw_key
        assert vk.is_transferable is False
        assert vk.code == "B"

    def test_d_prefix_returns_none_raw(self):
        aid = "D" + "A" * 43
        vk = parse_kid_to_verkey(aid)
        assert vk.raw is None
        assert vk.is_transferable is True
        assert vk.code == "D"

    def test_e_prefix_returns_none_raw(self):
        aid = "E" + "A" * 43
        vk = parse_kid_to_verkey(aid)
        assert vk.raw is None
        assert vk.is_transferable is True

    def test_require_raw_raises_for_transferable(self):
        aid = "D" + "A" * 43
        vk = parse_kid_to_verkey(aid)
        with pytest.raises(StateInvalidError, match="Tier 2"):
            vk.require_raw()

    def test_invalid_kid_raises(self):
        with pytest.raises(ResolutionFailedError):
            parse_kid_to_verkey("")

    def test_unsupported_code_raises(self):
        with pytest.raises(ResolutionFailedError, match="Unsupported"):
            parse_kid_to_verkey("Z" + "A" * 43)

    def test_extract_aid_from_oobi_url(self):
        url = "https://witness.example.com/oobi/BAID123456789012345678901234567890123456789/controller"
        aid = extract_aid_from_oobi_url(url)
        assert aid == "BAID123456789012345678901234567890123456789"

    def test_extract_aid_from_invalid_url_raises(self):
        with pytest.raises(ResolutionFailedError):
            extract_aid_from_oobi_url("https://example.com/not-oobi")


# ---------------------------------------------------------------------------
# KEL parser tests
# ---------------------------------------------------------------------------

from app.vvp.keri.kel_parser import (
    EventType,
    KELEvent,
    WitnessReceipt,
    parse_kel_stream,
    validate_kel_chain,
    compute_said,
    ESTABLISHMENT_TYPES,
    DELEGATED_TYPES,
)


def _make_event(
    event_type: str = "icp",
    sequence: int = 0,
    digest: str = "ESAID1",
    prior_digest: str = "",
    keys: list = None,
    signatures: list = None,
    **kwargs
) -> KELEvent:
    """Helper to create KELEvent for tests."""
    signing_keys = keys or [b"\x01" * 32]
    return KELEvent(
        event_type=EventType(event_type),
        sequence=sequence,
        prior_digest=prior_digest,
        digest=digest,
        signing_keys=signing_keys,
        next_keys_digest=None,
        toad=0,
        witnesses=[],
        signatures=signatures or [b"\x02" * 64],
        raw={"t": event_type, "d": digest, "s": hex(sequence)[2:], "p": prior_digest, "k": [], **kwargs},
    )


class TestKELParser:
    """KEL parser tests."""

    def test_event_type_values(self):
        assert EventType.ICP.value == "icp"
        assert EventType.ROT.value == "rot"
        assert EventType.IXN.value == "ixn"
        assert EventType.DIP.value == "dip"
        assert EventType.DRT.value == "drt"

    def test_establishment_types(self):
        assert EventType.ICP in ESTABLISHMENT_TYPES
        assert EventType.ROT in ESTABLISHMENT_TYPES
        assert EventType.IXN not in ESTABLISHMENT_TYPES

    def test_delegated_types(self):
        assert EventType.DIP in DELEGATED_TYPES
        assert EventType.DRT in DELEGATED_TYPES
        assert EventType.ICP not in DELEGATED_TYPES

    def test_kel_event_properties(self):
        icp = _make_event("icp")
        assert icp.is_establishment is True
        assert icp.is_inception is True
        assert icp.is_delegated is False

        rot = _make_event("rot", sequence=1)
        assert rot.is_establishment is True
        assert rot.is_inception is False

        ixn = _make_event("ixn", sequence=2)
        assert ixn.is_establishment is False

    def test_parse_json_kel(self):
        kel_json = json.dumps([
            {"t": "icp", "s": "0", "d": "ESAID1", "p": "", "k": [], "bt": "0", "b": []},
        ]).encode()
        events = parse_kel_stream(kel_json, allow_json_only=True)
        assert len(events) == 1
        assert events[0].event_type == EventType.ICP

    def test_parse_invalid_json_raises(self):
        with pytest.raises(ResolutionFailedError):
            parse_kel_stream(b"not json", allow_json_only=True)

    def test_validate_kel_chain_empty_raises(self):
        with pytest.raises(KELChainInvalidError, match="Empty KEL"):
            validate_kel_chain([])

    def test_validate_kel_chain_no_inception_raises(self):
        rot = _make_event("rot", sequence=0)
        with pytest.raises(KELChainInvalidError, match="inception"):
            validate_kel_chain([rot], validate_saids=False, use_canonical=False)

    def test_validate_kel_chain_sequence_gap_raises(self):
        icp = _make_event("icp", sequence=0)
        rot = _make_event("rot", sequence=2, prior_digest="ESAID1")
        with patch("app.vvp.keri.kel_parser._validate_inception_signature"):
            with pytest.raises(KELChainInvalidError, match="Sequence gap"):
                validate_kel_chain([icp, rot], validate_saids=False, use_canonical=False)

    def test_compute_said_returns_string(self):
        data = {"t": "icp", "d": "", "s": "0"}
        said = compute_said(data)
        assert isinstance(said, str)
        assert said.startswith("E")
        assert len(said) > 40


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

from app.vvp.keri.cache import KeyStateCache, CacheConfig, CacheMetrics


class TestKeyStateCache:
    """Key state cache tests."""

    def _make_key_state(self, aid="AID1", seq=0):
        from app.vvp.keri.kel_resolver import KeyState
        return KeyState(
            aid=aid,
            signing_keys=[b"\x01" * 32],
            sequence=seq,
            establishment_digest=f"ESAID_{aid}_{seq}",
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            witnesses=[],
            toad=0,
        )

    @pytest.mark.asyncio
    async def test_put_and_get(self):
        cache = KeyStateCache(CacheConfig(ttl_seconds=60))
        ks = self._make_key_state()
        await cache.put(ks)
        result = await cache.get(ks.aid, ks.establishment_digest)
        assert result is not None
        assert result.aid == "AID1"

    @pytest.mark.asyncio
    async def test_miss_returns_none(self):
        cache = KeyStateCache(CacheConfig(ttl_seconds=60))
        result = await cache.get("UNKNOWN", "UNKNOWN_DIGEST")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_for_time(self):
        cache = KeyStateCache(CacheConfig(ttl_seconds=300, freshness_window_seconds=300))
        ks = self._make_key_state()
        ref_time = datetime.now(timezone.utc)
        await cache.put(ks, reference_time=ref_time)
        result = await cache.get_for_time(ks.aid, ref_time)
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalidate(self):
        cache = KeyStateCache(CacheConfig(ttl_seconds=300))
        ks = self._make_key_state()
        await cache.put(ks)
        count = await cache.invalidate(ks.aid)
        assert count == 1
        result = await cache.get(ks.aid, ks.establishment_digest)
        assert result is None

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        cache = KeyStateCache(CacheConfig(max_entries=2))
        ks1 = self._make_key_state("AID1", 0)
        ks2 = self._make_key_state("AID2", 0)
        ks3 = self._make_key_state("AID3", 0)
        await cache.put(ks1)
        await cache.put(ks2)
        await cache.put(ks3)
        assert cache.size == 2
        assert cache.metrics().evictions == 1

    def test_cache_metrics(self):
        m = CacheMetrics(hits=8, misses=2)
        assert m.hit_rate() == 0.8
        d = m.to_dict()
        assert d["hit_rate"] == 0.8
        m.reset()
        assert m.hits == 0

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = KeyStateCache()
        ks = self._make_key_state()
        await cache.put(ks)
        assert cache.size == 1
        await cache.clear()
        assert cache.size == 0


# ---------------------------------------------------------------------------
# STIR parameter stripping tests
# ---------------------------------------------------------------------------

from app.sip.handler import _strip_stir_params


class TestStirParamStripping:
    """Test RFC 8224 STIR parameter stripping from Identity header."""

    def test_plain_jwt_unchanged(self):
        jwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl"
        assert _strip_stir_params(jwt) == jwt

    def test_strips_stir_params(self):
        raw = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl;info=<https://cert.example.com>;alg=ES256;ppt=shaken"
        result = _strip_stir_params(raw)
        assert result == "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl"

    def test_strips_angle_brackets(self):
        raw = "<eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl>;info=<https://cert.example.com>"
        result = _strip_stir_params(raw)
        assert result == "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl"

    def test_strips_ppt_vvp(self):
        raw = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl;ppt=vvp"
        result = _strip_stir_params(raw)
        assert result == "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl"

    def test_handles_whitespace(self):
        raw = "  eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl  "
        result = _strip_stir_params(raw)
        assert result == "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0In0.c2lnbmF0dXJl"


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestTier2Config:
    """Tier 2 configuration values."""

    def test_tier2_enabled_default(self):
        from app.core.config import VVP_TIER2_KEL_ENABLED
        assert isinstance(VVP_TIER2_KEL_ENABLED, bool)

    def test_freshness_seconds_default(self):
        from app.core.config import VVP_KEY_STATE_FRESHNESS_SECONDS
        assert VVP_KEY_STATE_FRESHNESS_SECONDS == 120.0

    def test_oobi_timeout_default(self):
        from app.core.config import VVP_OOBI_TIMEOUT_SECONDS
        assert VVP_OOBI_TIMEOUT_SECONDS == 5.0

    def test_admin_disabled_by_default(self):
        from app.core.config import VVP_ADMIN_ENABLED
        assert VVP_ADMIN_ENABLED is False


# ---------------------------------------------------------------------------
# Signature auto-routing tests
# ---------------------------------------------------------------------------

from app.vvp.signature import _extract_aid_from_kid


class TestSignatureRouting:
    """Test the AID extraction and routing logic in signature.py."""

    def test_extract_bare_aid(self):
        assert _extract_aid_from_kid("BAID12345") == "BAID12345"

    def test_extract_from_oobi_url(self):
        url = "https://witness.example.com/oobi/BAID123456789012345678901234567890123456789/controller"
        aid = _extract_aid_from_kid(url)
        assert aid == "BAID123456789012345678901234567890123456789"

    def test_extract_from_invalid_url_raises(self):
        from app.vvp.exceptions import SignatureInvalidError
        with pytest.raises(SignatureInvalidError, match="OOBI"):
            _extract_aid_from_kid("https://example.com/no-oobi-path")


# ---------------------------------------------------------------------------
# Tier 2 disabled path
# ---------------------------------------------------------------------------


class TestTier2Disabled:
    """Test behavior when VVP_TIER2_KEL_ENABLED=false."""

    @pytest.mark.asyncio
    async def test_resolve_key_state_raises_when_disabled(self):
        """resolve_key_state should raise ResolutionFailedError when Tier 2 is disabled."""
        from app.vvp.keri.kel_resolver import resolve_key_state
        with patch("app.core.config.VVP_TIER2_KEL_ENABLED", False):
            with pytest.raises(ResolutionFailedError, match="Tier 2.*disabled"):
                await resolve_key_state("DAID12345678901234567890123456789012345678901", None)

    @pytest.mark.asyncio
    async def test_tier2_signature_raises_when_disabled(self):
        """verify_passport_signature_tier2 should raise when Tier 2 is disabled."""
        from app.vvp.keri.signature import verify_passport_signature_tier2
        mock_passport = AsyncMock()
        mock_passport.header = AsyncMock()
        mock_passport.header.kid = "DAID12345678901234567890123456789012345678901"
        with patch("app.core.config.VVP_TIER2_KEL_ENABLED", False):
            with pytest.raises(ResolutionFailedError, match="Tier 2.*disabled"):
                await verify_passport_signature_tier2(mock_passport)
