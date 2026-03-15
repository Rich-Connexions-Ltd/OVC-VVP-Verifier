# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for negative cache (Sprint 88, Component 6).

Validates NegativeCacheEntry, get_negative(), put_negative(), and
quota enforcement.
"""

import time

import pytest

from app.vvp.verification_cache import (
    NEGATIVE_CACHE_MAX_ENTRIES,
    NEGATIVE_CACHE_TTL_SECONDS,
    NegativeCacheEntry,
    VerificationResultCache,
)


# ---------------------------------------------------------------------------
# NegativeCacheEntry
# ---------------------------------------------------------------------------

class TestNegativeCacheEntry:
    def test_fresh_entry_not_expired(self):
        entry = NegativeCacheEntry(
            dossier_url="https://example.com/dossier",
            reason="CVD_MISSING_REQUIRED_EDGE",
            registry_version="v1",
        )
        assert entry.is_expired is False

    def test_old_entry_is_expired(self):
        entry = NegativeCacheEntry(
            dossier_url="https://example.com/dossier",
            reason="CVD_MISSING_REQUIRED_EDGE",
            registry_version="v1",
            created_at=time.time() - NEGATIVE_CACHE_TTL_SECONDS - 1,
        )
        assert entry.is_expired is True

    def test_entry_stores_fields(self):
        entry = NegativeCacheEntry(
            dossier_url="https://x.com/d",
            reason="test-reason",
            registry_version="v2",
        )
        assert entry.dossier_url == "https://x.com/d"
        assert entry.reason == "test-reason"
        assert entry.registry_version == "v2"


# ---------------------------------------------------------------------------
# get_negative / put_negative
# ---------------------------------------------------------------------------

class TestNegativeCacheLookup:
    def test_put_and_get(self):
        cache = VerificationResultCache()
        entry = NegativeCacheEntry("https://x.com/d", "reason", "v1")
        cache.put_negative(entry)
        result = cache.get_negative("https://x.com/d", "v1")
        assert result is not None
        assert result.reason == "reason"

    def test_get_miss(self):
        cache = VerificationResultCache()
        result = cache.get_negative("https://missing.com/d", "v1")
        assert result is None

    def test_get_expired_returns_none(self):
        cache = VerificationResultCache()
        entry = NegativeCacheEntry(
            "https://x.com/d", "reason", "v1",
            created_at=time.time() - NEGATIVE_CACHE_TTL_SECONDS - 10,
        )
        cache.put_negative(entry)
        result = cache.get_negative("https://x.com/d", "v1")
        assert result is None

    def test_get_wrong_version_returns_none(self):
        cache = VerificationResultCache()
        entry = NegativeCacheEntry("https://x.com/d", "reason", "v1")
        cache.put_negative(entry)
        result = cache.get_negative("https://x.com/d", "v2")
        assert result is None

    def test_clear_removes_negative_cache(self):
        import asyncio
        cache = VerificationResultCache()
        entry = NegativeCacheEntry("https://x.com/d", "reason", "v1")
        cache.put_negative(entry)
        asyncio.get_event_loop().run_until_complete(cache.clear())
        result = cache.get_negative("https://x.com/d", "v1")
        assert result is None


# ---------------------------------------------------------------------------
# Quota enforcement
# ---------------------------------------------------------------------------

class TestNegativeCacheQuota:
    def test_quota_enforced(self):
        cache = VerificationResultCache()
        # Fill to max
        for i in range(NEGATIVE_CACHE_MAX_ENTRIES + 5):
            entry = NegativeCacheEntry(f"https://x.com/{i}", "reason", "v1")
            cache.put_negative(entry)
        # Should not exceed max
        assert len(cache._negative_cache) <= NEGATIVE_CACHE_MAX_ENTRIES

    def test_oldest_evicted_first(self):
        cache = VerificationResultCache()
        # Fill exactly to max
        for i in range(NEGATIVE_CACHE_MAX_ENTRIES):
            entry = NegativeCacheEntry(f"https://x.com/{i}", "reason", "v1")
            cache.put_negative(entry)
        # Add one more — first entry should be evicted
        cache.put_negative(NegativeCacheEntry("https://x.com/new", "reason", "v1"))
        assert cache.get_negative("https://x.com/0", "v1") is None
        assert cache.get_negative("https://x.com/new", "v1") is not None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestNegativeCacheConfig:
    def test_max_entries_is_1000(self):
        assert NEGATIVE_CACHE_MAX_ENTRIES == 1000

    def test_ttl_is_60_seconds(self):
        assert NEGATIVE_CACHE_TTL_SECONDS == 60
