# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/cache.py
# Source commit: 398d40d (2026-03-14)

"""Range-based key state cache for KERI resolution.

Per spec §5C.2: "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"

Each cached entry covers a validity window [valid_from, valid_until), where:
- valid_from: timestamp of this establishment event
- valid_until: timestamp of the next establishment event (None = most recent)

Lookup strategy:
1. Exact match via time index — O(1)
2. Range scan over entries for the AID — O(N) where N ≈ 1-2 per AID
3. Higher KEL sequence number wins when multiple entries cover the same time

Freshness guard: Entries with valid_until=None are served only while their
immutable cached_at timestamp is within freshness_window_seconds (default 120s).
After expiry, an OOBI re-fetch is forced to detect any rotations.
"""

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

if TYPE_CHECKING:
    from .kel_resolver import KeyState

log = logging.getLogger(__name__)


@dataclass
class CacheMetrics:
    """Metrics for cache operations."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "invalidations": self.invalidations,
            "hit_rate": round(self.hit_rate(), 4),
        }

    def reset(self) -> None:
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.invalidations = 0


@dataclass
class CacheConfig:
    """Configuration for key state cache."""
    ttl_seconds: int = 300  # 5 minutes default per §5C.2
    max_entries: int = 1000
    freshness_window_seconds: float = 120.0
    max_time_index_entries: int = 10_000


@dataclass
class _CacheEntry:
    """Internal cache entry with metadata."""
    key_state: "KeyState"
    expires_at: datetime
    last_access: datetime
    cached_at: datetime  # Set once at creation — NOT updated on access
    valid_until: Optional[datetime] = None
    sequence: int = 0


def _normalize_datetime(dt: datetime) -> datetime:
    """Normalize datetime to UTC for comparison."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _entry_covers_time(
    entry: _CacheEntry, rt: datetime, now: datetime, freshness_window_seconds: float
) -> bool:
    """Check if entry's validity window covers reference_time."""
    ks = entry.key_state
    if ks.valid_from is None:
        return False
    vf = _normalize_datetime(ks.valid_from)
    if vf > rt:
        return False

    if entry.valid_until is not None:
        vu = _normalize_datetime(entry.valid_until)
        if rt >= vu:
            return False
    else:
        entry_age = (now - entry.cached_at).total_seconds()
        if entry_age > freshness_window_seconds:
            return False

    return True


class KeyStateCache:
    """Thread-safe, range-based cache for resolved key states.

    Supports lookup by:
    1. (AID, establishment_digest) - exact match
    2. (AID, reference_time) - range-based match
    """

    def __init__(self, config: Optional[CacheConfig] = None):
        self._config = config or CacheConfig()
        self._entries: Dict[Tuple[str, str], _CacheEntry] = {}
        self._time_index: Dict[Tuple[str, datetime], str] = {}
        self._access_order: OrderedDict[Tuple[str, str], None] = OrderedDict()
        self._lock = asyncio.Lock()
        self._metrics = CacheMetrics()

    async def get(self, aid: str, establishment_digest: str) -> Optional["KeyState"]:
        """Get cached key state by AID and establishment event digest."""
        async with self._lock:
            key = (aid, establishment_digest)
            entry = self._entries.get(key)

            if entry is None:
                self._metrics.misses += 1
                return None

            now = datetime.now(timezone.utc)
            if entry.expires_at < now:
                self._remove_entry(key)
                self._metrics.misses += 1
                return None

            entry.last_access = now
            self._touch_access_order(key)
            self._metrics.hits += 1
            return entry.key_state

    async def get_for_time(
        self,
        aid: str,
        reference_time: datetime
    ) -> Optional["KeyState"]:
        """Get cached key state valid at a specific reference time."""
        async with self._lock:
            now = datetime.now(timezone.utc)

            result = self._exact_match_locked(aid, reference_time, now)
            if result is not None:
                return result

            result = self._range_match_locked(aid, reference_time, now)
            if result is not None:
                return result

            self._metrics.misses += 1
            return None

    def _exact_match_locked(
        self, aid: str, reference_time: datetime, now: datetime
    ) -> Optional["KeyState"]:
        digest = self._time_index.get((aid, reference_time))
        if not digest:
            return None
        entry = self._entries.get((aid, digest))
        if entry and entry.expires_at >= now:
            self._touch_access_order((aid, digest))
            entry.last_access = now
            self._metrics.hits += 1
            return entry.key_state
        return None

    def _range_match_locked(
        self, aid: str, reference_time: datetime, now: datetime
    ) -> Optional["KeyState"]:
        rt = _normalize_datetime(reference_time)
        best_entry = None
        best_key = None
        best_seq = -1

        for key, entry in self._entries.items():
            if key[0] != aid or entry.expires_at < now:
                continue
            if not _entry_covers_time(
                entry, rt, now, self._config.freshness_window_seconds
            ):
                continue
            if entry.sequence > best_seq:
                best_entry = entry
                best_key = key
                best_seq = entry.sequence

        if best_entry is None:
            return None

        self._touch_access_order(best_key)
        best_entry.last_access = now
        self._metrics.hits += 1

        self._enforce_time_index_cap()
        self._time_index[(aid, reference_time)] = best_key[1]
        return best_entry.key_state

    async def put(
        self,
        key_state: "KeyState",
        reference_time: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        sequence: Optional[int] = None,
    ) -> None:
        """Store a resolved key state in the cache."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            key = (key_state.aid, key_state.establishment_digest)

            entry = _CacheEntry(
                key_state=key_state,
                expires_at=now + timedelta(seconds=self._config.ttl_seconds),
                last_access=now,
                cached_at=now,
                valid_until=valid_until,
                sequence=sequence if sequence is not None else key_state.sequence,
            )

            if len(self._entries) >= self._config.max_entries and key not in self._entries:
                self._evict_lru()

            self._entries[key] = entry
            self._touch_access_order(key)

            self._enforce_time_index_cap()

            if key_state.valid_from:
                time_key = (key_state.aid, key_state.valid_from)
                self._time_index[time_key] = key_state.establishment_digest

            if reference_time:
                ref_time_key = (key_state.aid, reference_time)
                self._time_index[ref_time_key] = key_state.establishment_digest

    async def invalidate(self, aid: str) -> int:
        """Invalidate all cached entries for an AID."""
        async with self._lock:
            keys_to_remove = [
                key for key in self._entries.keys()
                if key[0] == aid
            ]

            count = len(keys_to_remove)
            for key in keys_to_remove:
                self._remove_entry(key)

            time_keys_to_remove = [
                tkey for tkey in self._time_index.keys()
                if tkey[0] == aid
            ]
            for tkey in time_keys_to_remove:
                del self._time_index[tkey]

            if count > 0:
                self._metrics.invalidations += count

            return count

    def _enforce_time_index_cap(self) -> None:
        if len(self._time_index) >= self._config.max_time_index_entries:
            to_remove = list(self._time_index.keys())[
                : len(self._time_index) // 2
            ]
            for k in to_remove:
                del self._time_index[k]

    def _remove_entry(self, key: Tuple[str, str]) -> None:
        entry = self._entries.pop(key, None)
        self._access_order.pop(key, None)

        if entry:
            aid, digest = key
            time_keys_to_remove = [
                tkey for tkey, d in self._time_index.items()
                if tkey[0] == aid and d == digest
            ]
            for tkey in time_keys_to_remove:
                del self._time_index[tkey]

    def _touch_access_order(self, key: Tuple[str, str]) -> None:
        self._access_order[key] = None
        self._access_order.move_to_end(key)

    def _evict_lru(self) -> None:
        if self._access_order:
            lru_key = next(iter(self._access_order))
            self._remove_entry(lru_key)
            self._metrics.evictions += 1

    async def clear(self) -> None:
        async with self._lock:
            self._entries.clear()
            self._time_index.clear()
            self._access_order.clear()

    @property
    def size(self) -> int:
        return len(self._entries)

    def metrics(self) -> CacheMetrics:
        return self._metrics
