# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Dossier LRU cache with TTL expiry and content-addressable invalidation."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.config import (
    DOSSIER_CACHE_MAX_ENTRIES,
    DOSSIER_CACHE_TTL_SECONDS,
)
from app.vvp.acdc import ACDC, DossierDAG

logger = logging.getLogger(__name__)


def _content_hash(data: bytes) -> str:
    """Compute a SHA-256 hex digest of raw dossier bytes.

    This serves as a content-addressable identifier (distinct from the
    ACDC SAIDs within the dossier) for cache invalidation by content.
    """
    return hashlib.sha256(data).hexdigest()


@dataclass
class CachedDossier:
    """A cached dossier entry.

    Attributes
    ----------
    url : str
        The evidence URL from which this dossier was fetched.
    acdcs : list[ACDC]
        The parsed ACDC credentials.
    dag : DossierDAG
        The validated credential graph.
    fetched_at : float
        UNIX timestamp when the dossier was fetched.
    said : str
        Content hash (SHA-256 hex) of the raw dossier bytes, used for
        content-addressable invalidation.
    """

    url: str
    acdcs: List[ACDC]
    dag: DossierDAG
    fetched_at: float
    said: str


class DossierCache:
    """Thread-safe LRU cache for fetched and parsed dossiers.

    Provides TTL-based expiry and content-addressable invalidation.
    The cache is keyed by evidence URL and uses an :class:`OrderedDict`
    for efficient LRU eviction.

    Parameters
    ----------
    max_entries : int
        Maximum number of cached dossiers.  When exceeded, the least
        recently used entry is evicted.
    ttl_seconds : float
        Time-to-live in seconds.  Entries older than this are considered
        stale and evicted on access.

    Thread Safety
    -------------
    All mutating operations acquire an :class:`asyncio.Lock`, making the
    cache safe for concurrent async access within a single event loop.
    """

    def __init__(
        self,
        max_entries: int = DOSSIER_CACHE_MAX_ENTRIES,
        ttl_seconds: float = DOSSIER_CACHE_TTL_SECONDS,
    ) -> None:
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CachedDossier] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, url: str) -> Optional[CachedDossier]:
        """Retrieve a cached dossier by URL.

        If the entry exists and has not expired, it is moved to the end
        of the LRU order (most recently used) and returned.

        Parameters
        ----------
        url : str
            The evidence URL to look up.

        Returns
        -------
        CachedDossier or None
            The cached entry, or ``None`` if not found or expired.
        """
        async with self._lock:
            entry = self._cache.get(url)
            if entry is None:
                self._misses += 1
                return None

            # Check TTL expiry.
            age = time.monotonic() - entry.fetched_at
            if age > self._ttl_seconds:
                # Stale — evict.
                del self._cache[url]
                self._misses += 1
                logger.debug(
                    "Cache entry expired for %s (age=%.1fs, ttl=%.1fs)",
                    url,
                    age,
                    self._ttl_seconds,
                )
                return None

            # Move to end (most recently used).
            self._cache.move_to_end(url)
            self._hits += 1
            logger.debug("Cache hit for %s", url)
            return entry

    async def put(self, url: str, entry: CachedDossier) -> None:
        """Insert or update a cached dossier entry.

        If the cache is at capacity, the least recently used entry is
        evicted before insertion.

        Parameters
        ----------
        url : str
            The evidence URL (cache key).
        entry : CachedDossier
            The dossier entry to cache.
        """
        async with self._lock:
            # If already present, remove so we can re-insert at the end.
            if url in self._cache:
                del self._cache[url]

            # Evict oldest if at capacity.
            while len(self._cache) >= self._max_entries:
                evicted_url, _ = self._cache.popitem(last=False)
                logger.debug("Cache evicted LRU entry: %s", evicted_url)

            self._cache[url] = entry
            logger.debug(
                "Cached dossier for %s (said=%s, size=%d ACDCs)",
                url,
                entry.said[:16],
                len(entry.acdcs),
            )

    async def invalidate(self, url: str) -> bool:
        """Remove a specific URL from the cache.

        Parameters
        ----------
        url : str
            The evidence URL to invalidate.

        Returns
        -------
        bool
            ``True`` if the entry was found and removed.
        """
        async with self._lock:
            if url in self._cache:
                del self._cache[url]
                logger.debug("Cache invalidated: %s", url)
                return True
            return False

    async def invalidate_by_said(self, said: str) -> int:
        """Remove all entries whose content hash matches *said*.

        This enables invalidation when a credential is known to have
        changed (e.g. revoked) without knowing which URL served it.

        Parameters
        ----------
        said : str
            The content hash (SHA-256 hex digest) to match.

        Returns
        -------
        int
            The number of entries removed.
        """
        async with self._lock:
            to_remove = [
                url
                for url, entry in self._cache.items()
                if entry.said == said
            ]
            for url in to_remove:
                del self._cache[url]
                logger.debug(
                    "Cache invalidated by SAID %s: %s", said[:16], url
                )
            return len(to_remove)

    async def clear(self) -> None:
        """Remove all entries from the cache."""
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            logger.debug("Cache cleared (%d entries removed)", count)

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics.

        Returns
        -------
        dict
            A dictionary with keys ``hits``, ``misses``, ``size``,
            ``max_entries``, ``ttl_seconds``, and ``hit_rate``.
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100.0) if total > 0 else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._cache),
            "max_entries": self._max_entries,
            "ttl_seconds": self._ttl_seconds,
            "hit_rate": round(hit_rate, 1),
        }

    def __len__(self) -> int:
        """Return the number of entries currently in the cache."""
        return len(self._cache)

    def __repr__(self) -> str:
        stats = self.stats()
        return (
            f"DossierCache(size={stats['size']}, "
            f"max={stats['max_entries']}, "
            f"hits={stats['hits']}, "
            f"misses={stats['misses']})"
        )


# ======================================================================
# Module-level singleton
# ======================================================================

_dossier_cache: Optional[DossierCache] = None


def get_dossier_cache() -> DossierCache:
    """Return the module-level :class:`DossierCache` singleton.

    Creates the cache on first access using config defaults.

    Returns
    -------
    DossierCache
        The shared cache instance.
    """
    global _dossier_cache
    if _dossier_cache is None:
        _dossier_cache = DossierCache(
            max_entries=DOSSIER_CACHE_MAX_ENTRIES,
            ttl_seconds=DOSSIER_CACHE_TTL_SECONDS,
        )
        logger.debug(
            "Initialized dossier cache: max=%d, ttl=%ds",
            DOSSIER_CACHE_MAX_ENTRIES,
            DOSSIER_CACHE_TTL_SECONDS,
        )
    return _dossier_cache


def reset_dossier_cache() -> None:
    """Reset the module-level cache singleton.

    Intended for use in tests to ensure a fresh cache between test runs.
    """
    global _dossier_cache
    _dossier_cache = None
    logger.debug("Dossier cache singleton reset")
