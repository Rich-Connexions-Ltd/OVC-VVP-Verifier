# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for the verification result cache (app.vvp.cache).

Covers put/get operations, TTL expiry, LRU eviction, config fingerprint
invalidation, deep copy isolation, and revocation status propagation.

All tests use pytest-asyncio for async cache operations.

References:
    - VVP Verifier Specification §5A — Verification pipeline caching
    - app.vvp.cache.VerificationResultCache
"""

from __future__ import annotations

import asyncio
import copy
import time
from unittest.mock import patch

import pytest
import pytest_asyncio

from app.vvp.verification_cache import (
    CachedDossierVerification,
    RevocationStatus,
    VerificationResultCache,
    reset_verification_cache,
)


# =========================================================================
# Helpers
# =========================================================================

def _make_entry(
    dossier_url: str = "https://example.com/dossier.cesr",
    passport_kid: str = "Btest_kid_000000000000000000000000000000000",
    brand_name: str = "Acme Corp",
) -> CachedDossierVerification:
    """Create a minimal CachedDossierVerification for testing."""
    return CachedDossierVerification(
        dossier_url=dossier_url,
        passport_kid=passport_kid,
        dag=None,
        chain_claim={"name": "chain", "status": "VALID", "reasons": []},
        contained_saids=["SAID_001", "SAID_002"],
        revocation_status={"SAID_001": RevocationStatus.UNREVOKED, "SAID_002": RevocationStatus.UNREVOKED},
        revocation_last_checked=None,
        cached_at=time.time(),
        config_hash="",  # will be overwritten by put()
        brand_name=brand_name,
    )


@pytest_asyncio.fixture
async def cache():
    """Create a fresh cache with small capacity for testing."""
    reset_verification_cache()
    c = VerificationResultCache(max_entries=5, ttl_seconds=60.0)
    yield c
    reset_verification_cache()


# =========================================================================
# Basic Operations
# =========================================================================

class TestPutAndGet:
    """Test basic cache put/get operations."""

    @pytest.mark.asyncio
    async def test_put_and_get(self, cache):
        """A stored entry should be retrievable by the same key."""
        url = "https://example.com/dossier.cesr"
        entry = _make_entry(dossier_url=url)
        await cache.put(url, "kid1", entry)

        result = await cache.get(url, "kid1")
        assert result is not None
        assert result.dossier_url == url
        assert result.brand_name == "Acme Corp"

    @pytest.mark.asyncio
    async def test_miss_on_absent_key(self, cache):
        """Getting a non-existent key should return None."""
        result = await cache.get("https://nonexistent.com/d.cesr", "kid1")
        assert result is None

    @pytest.mark.asyncio
    async def test_stats_counters(self, cache):
        """Stats should track hits and misses."""
        entry = _make_entry()
        await cache.put("https://example.com/d.cesr", "kid1", entry)

        await cache.get("https://example.com/d.cesr", "kid1")  # hit
        await cache.get("https://nonexistent.com/d.cesr", "kid2")  # miss

        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1


# =========================================================================
# TTL Expiry
# =========================================================================

class TestTTLExpiry:
    """Test time-to-live-based cache expiry."""

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        """An entry older than TTL should be treated as a miss."""
        cache = VerificationResultCache(max_entries=10, ttl_seconds=1.0)
        entry = _make_entry()
        # Backdate the entry by setting cached_at in the past
        entry.cached_at = time.time() - 100
        entry.config_hash = ""

        # Manually inject the entry to bypass put()'s config_hash update
        key = ("https://example.com/d.cesr", "kid1")
        # Use put() and then backdate
        await cache.put("https://example.com/d.cesr", "kid1", entry)
        # Directly backdate via internal state
        async with cache._lock:
            cache._cache[key].cached_at = time.time() - 100

        result = await cache.get("https://example.com/d.cesr", "kid1")
        assert result is None

        stats = cache.stats()
        assert stats["misses"] >= 1


# =========================================================================
# LRU Eviction
# =========================================================================

class TestLRUEviction:
    """Test LRU eviction when cache exceeds max_entries."""

    @pytest.mark.asyncio
    async def test_lru_eviction(self, cache):
        """Filling beyond max_entries should evict the oldest entry."""
        # cache has max_entries=5; insert 6 entries
        for i in range(6):
            entry = _make_entry(dossier_url=f"https://example.com/d{i}.cesr")
            await cache.put(f"https://example.com/d{i}.cesr", "kid", entry)

        # The first entry (d0) should have been evicted
        result = await cache.get("https://example.com/d0.cesr", "kid")
        assert result is None

        # The most recent entry should still be present
        result = await cache.get("https://example.com/d5.cesr", "kid")
        assert result is not None

    @pytest.mark.asyncio
    async def test_lru_access_promotes(self, cache):
        """Accessing an entry should promote it, preventing eviction."""
        # Insert 5 entries (fills cache)
        for i in range(5):
            entry = _make_entry(dossier_url=f"https://example.com/d{i}.cesr")
            await cache.put(f"https://example.com/d{i}.cesr", "kid", entry)

        # Access d0 to promote it to most-recently-used
        await cache.get("https://example.com/d0.cesr", "kid")

        # Insert a 6th entry — d1 (the new LRU) should be evicted, not d0
        entry = _make_entry(dossier_url="https://example.com/d5.cesr")
        await cache.put("https://example.com/d5.cesr", "kid", entry)

        assert await cache.get("https://example.com/d0.cesr", "kid") is not None
        assert await cache.get("https://example.com/d1.cesr", "kid") is None


# =========================================================================
# Config Fingerprint Invalidation
# =========================================================================

class TestConfigFingerprintInvalidation:
    """Test cache invalidation when config fingerprint changes."""

    @pytest.mark.asyncio
    async def test_config_fingerprint_invalidation(self):
        """Changing the config fingerprint should invalidate cached entries."""
        cache = VerificationResultCache(max_entries=10, ttl_seconds=3600.0)
        entry = _make_entry()
        await cache.put("https://example.com/d.cesr", "kid1", entry)

        # Verify it is retrievable
        result = await cache.get("https://example.com/d.cesr", "kid1")
        assert result is not None

        # Now change the config fingerprint
        with patch("app.vvp.verification_cache.config_fingerprint", return_value="changed_hash"):
            result = await cache.get("https://example.com/d.cesr", "kid1")
            assert result is None


# =========================================================================
# Deep Copy Isolation
# =========================================================================

class TestDeepCopyIsolation:
    """Test that cache returns deep copies to prevent cross-request mutation."""

    @pytest.mark.asyncio
    async def test_deep_copy_isolation(self, cache):
        """Modifying a returned entry should not affect the cached original."""
        entry = _make_entry()
        await cache.put("https://example.com/d.cesr", "kid1", entry)

        # Get a copy and mutate it
        result = await cache.get("https://example.com/d.cesr", "kid1")
        assert result is not None
        result.revocation_status["SAID_001"] = RevocationStatus.REVOKED
        result.chain_claim["status"] = "INVALID"

        # Get another copy — it should have the original values
        result2 = await cache.get("https://example.com/d.cesr", "kid1")
        assert result2 is not None
        assert result2.revocation_status["SAID_001"] == RevocationStatus.UNREVOKED
        assert result2.chain_claim["status"] == "VALID"


# =========================================================================
# Revocation Status Propagation
# =========================================================================

class TestRevocationUpdate:
    """Test revocation status updates across all kid variants."""

    @pytest.mark.asyncio
    async def test_revocation_update_all(self, cache):
        """Revoking a credential should update all kid variants for the same dossier URL."""
        url = "https://example.com/d.cesr"
        # Insert two entries with same URL but different kids
        entry1 = _make_entry(dossier_url=url, passport_kid="kid_A")
        entry2 = _make_entry(dossier_url=url, passport_kid="kid_B")
        await cache.put(url, "kid_A", entry1)
        await cache.put(url, "kid_B", entry2)

        # Revoke SAID_001 across all kids
        await cache.update_revocation_all_for_url(url, "SAID_001", RevocationStatus.REVOKED)

        # Both entries should show SAID_001 as REVOKED
        r1 = await cache.get(url, "kid_A")
        r2 = await cache.get(url, "kid_B")
        assert r1.revocation_status["SAID_001"] == RevocationStatus.REVOKED
        assert r2.revocation_status["SAID_001"] == RevocationStatus.REVOKED
        # SAID_002 should be unaffected
        assert r1.revocation_status["SAID_002"] == RevocationStatus.UNREVOKED

    @pytest.mark.asyncio
    async def test_revocation_sticky(self, cache):
        """REVOKED status should never be downgraded."""
        url = "https://example.com/d.cesr"
        entry = _make_entry(dossier_url=url)
        await cache.put(url, "kid1", entry)

        # Revoke
        await cache.update_revocation_all_for_url(url, "SAID_001", RevocationStatus.REVOKED)
        # Attempt to un-revoke
        await cache.update_revocation_all_for_url(url, "SAID_001", RevocationStatus.UNREVOKED)

        result = await cache.get(url, "kid1")
        assert result.revocation_status["SAID_001"] == RevocationStatus.REVOKED
