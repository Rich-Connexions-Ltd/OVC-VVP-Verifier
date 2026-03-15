# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Verification result cache with LRU eviction and TTL expiry.

Caches dossier-derived verification artifacts (chain validation, ACDC
signatures, revocation status) keyed by ``(dossier_url, passport_kid)``.
On cache hit, expensive phases (DAG construction, chain walk, ACDC
signature verification) are skipped while per-request phases always
re-evaluate.

Only VALID chain results should be cached.  INVALID and INDETERMINATE
results are not cached to avoid sticky failures from transient
conditions (network errors, clock skew, etc.).

The cache is invalidated automatically when:

* The entry exceeds its TTL (configurable, default 3600 s).
* The configuration fingerprint changes (e.g. trusted roots are updated
  at restart).
* The entry is evicted under LRU pressure when the cache is full.

Revocation status is updated in-place by the background revocation
checker without evicting the entry, so the cached chain/DAG/signature
artifacts remain valid.

References
----------
- VVP Verifier Specification v1.5 §5A — Verification pipeline
- Sprint 51 — Verification result caching
"""

from __future__ import annotations

import asyncio
import copy
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import (
    config_fingerprint,
    VERIFICATION_CACHE_ENABLED,
    VERIFICATION_CACHE_MAX_ENTRIES,
    VERIFICATION_CACHE_TTL,
)

logger = logging.getLogger("vvp.cache")

__all__ = [
    "CachedDossierVerification",
    "CacheMetrics",
    "NegativeCacheEntry",
    "NEGATIVE_CACHE_MAX_ENTRIES",
    "NEGATIVE_CACHE_TTL_SECONDS",
    "RevocationStatus",
    "VerificationResultCache",
    "get_verification_cache",
    "reset_verification_cache",
]


# ======================================================================
# NegativeCacheEntry (Sprint 88)
# Slim cache for governance-deterministic INDETERMINATE results.
# ======================================================================

NEGATIVE_CACHE_MAX_ENTRIES = 1000
NEGATIVE_CACHE_TTL_SECONDS = 60


@dataclass
class NegativeCacheEntry:
    """Slim negative cache entry for governance-deterministic INDETERMINATE.

    Only caches deterministic failures (schema governance mismatch, missing
    required edges). Does NOT cache transient failures (network timeouts,
    witness unavailability).

    Invalidated when SCHEMA_REGISTRY_VERSION changes.
    """
    dossier_url: str
    reason: str  # e.g., "CVD_MISSING_REQUIRED_EDGE: ..."
    registry_version: str  # Invalidation key
    created_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > NEGATIVE_CACHE_TTL_SECONDS


# ======================================================================
# RevocationStatus
# ======================================================================


class RevocationStatus(str, Enum):
    """Three-state revocation status for cached credentials.

    Transitions are monotonically upward: ``UNDEFINED`` may become
    ``UNREVOKED`` or ``REVOKED``; ``UNREVOKED`` may become ``REVOKED``;
    ``REVOKED`` is terminal and **never** downgrades.

    Values
    ------
    UNDEFINED
        Revocation has not yet been checked (initial state when the
        entry is first cached).
    UNREVOKED
        The credential has been checked against the TEL and is active
        (not revoked).
    REVOKED
        The credential has been revoked.  This status is sticky — once
        set, background rechecks will never downgrade it.
    """

    UNDEFINED = "UNDEFINED"
    UNREVOKED = "UNREVOKED"
    REVOKED = "REVOKED"


# ======================================================================
# CacheMetrics
# ======================================================================


@dataclass
class CacheMetrics:
    """Operational metrics for the verification result cache.

    All counters are monotonically increasing for the lifetime of the
    cache instance (reset only on process restart or explicit
    ``reset_verification_cache()``).

    Attributes
    ----------
    hits : int
        Number of cache hits (key found, TTL valid, config hash matches).
    misses : int
        Number of cache misses (key absent, TTL expired, or config hash
        mismatch).
    evictions : int
        Number of entries removed — includes both LRU evictions and TTL
        / config-hash invalidations.
    revocation_checks : int
        Number of revocation status updates applied to cached entries
        (regardless of whether the status changed).
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    revocation_checks: int = 0

    def to_dict(self) -> dict:
        """Serialize metrics to a plain dict for API / logging output."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "revocation_checks": self.revocation_checks,
        }


# ======================================================================
# CachedDossierVerification
# ======================================================================


@dataclass
class CachedDossierVerification:
    """Immutable snapshot of dossier-derived verification artifacts.

    Stored in the cache keyed by ``(dossier_url, passport_kid)``.
    Mutable fields (``revocation_status``, ``revocation_last_checked``)
    are updated in-place by the background revocation checker;
    all other fields are effectively immutable after creation.

    On cache *read* the caller receives a **deep copy** of the mutable
    containers (``revocation_status``, ``chain_claim``) to prevent
    cross-request mutation.

    Attributes
    ----------
    dossier_url : str
        Evidence URL from the VVP-Identity header (``evd`` field).
    passport_kid : str
        Key identifier from the PASSporT JWT header.
    dag : Any
        Reference to the ``DossierDAG`` credential graph.  Treated as
        read-only; not deep-copied on cache read.
    chain_claim : Any
        Reference to the ``ClaimNode`` tree produced by chain
        verification.  Deep-copied on cache read.
    contained_saids : list[str]
        Credential SAIDs present in the dossier (used by the background
        revocation checker to enumerate credentials).
    revocation_status : dict[str, RevocationStatus]
        Per-credential revocation state, keyed by credential SAID.
        Updated in-place by the background revocation checker.
    revocation_last_checked : float or None
        Epoch timestamp of the most recent revocation check for this
        entry.  ``None`` means revocation has never been checked.
    cached_at : float
        Epoch timestamp when the entry was created.
    config_hash : str
        Configuration fingerprint at the time of caching.  If the
        current config fingerprint differs, the entry is treated as a
        miss and evicted.
    brand_name : str or None
        Brand name extracted from the dossier's brand credential (if
        any).  Informational; used by SIP services for the
        ``X-VVP-Brand-Name`` header.
    """

    dossier_url: str
    passport_kid: str
    dag: Any
    chain_claim: Any
    contained_saids: List[str]
    revocation_status: Dict[str, RevocationStatus]
    revocation_last_checked: Optional[float]
    cached_at: float
    config_hash: str
    brand_name: Optional[str] = None


# ======================================================================
# VerificationResultCache
# ======================================================================

# Type alias for the compound cache key.
CacheKey = Tuple[str, str]  # (dossier_url, passport_kid)


class VerificationResultCache:
    """In-memory LRU + TTL cache for dossier verification results.

    Concurrency-safe: all public methods acquire an ``asyncio.Lock``
    before touching internal state, so the cache can be shared across
    concurrent request handlers on the same event loop.

    Parameters
    ----------
    max_entries : int
        Maximum number of entries before LRU eviction kicks in.
    ttl_seconds : float
        Time-to-live for each entry in seconds.  Entries older than
        ``ttl_seconds`` are treated as misses on the next ``get``.
    """

    def __init__(
        self,
        max_entries: int = 200,
        ttl_seconds: float = 3600.0,
    ) -> None:
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds

        # Main data store: compound key -> cached entry.
        self._cache: Dict[CacheKey, CachedDossierVerification] = {}

        # LRU ordering: OrderedDict gives O(1) move-to-end and
        # O(1) pop-from-front.
        self._access_order: OrderedDict[CacheKey, None] = OrderedDict()

        self._lock = asyncio.Lock()

        # Snapshot the config fingerprint at construction time so that
        # entries inserted under one configuration are transparently
        # invalidated if the process is reconfigured and the cache is
        # reused (e.g. in tests).
        self._config_hash: str = config_fingerprint()

        self._metrics = CacheMetrics()

        # Negative cache (Sprint 88): governance-deterministic INDETERMINATE
        self._negative_cache: Dict[str, NegativeCacheEntry] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(
        self,
        dossier_url: str,
        passport_kid: str,
    ) -> Optional[CachedDossierVerification]:
        """Retrieve a cached verification result.

        Returns a **deep copy** of the mutable containers inside the
        entry so that the caller can mutate them freely without
        affecting the cached state.

        Returns ``None`` (cache miss) if:

        * The key is not present.
        * The entry has expired (age > TTL).
        * The entry's ``config_hash`` does not match the current
          configuration fingerprint.

        Parameters
        ----------
        dossier_url : str
            Evidence URL from the VVP-Identity header.
        passport_kid : str
            Key identifier from the PASSporT JWT header.

        Returns
        -------
        CachedDossierVerification or None
            A deep-copied entry on hit, or ``None`` on miss.
        """
        key: CacheKey = (dossier_url, passport_kid)
        current_fp = config_fingerprint()

        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._metrics.misses += 1
                return None

            # --- Config fingerprint check ---
            if entry.config_hash != current_fp:
                logger.info(
                    "Config hash mismatch for %s (cached=%s, current=%s); "
                    "evicting",
                    dossier_url[:60],
                    entry.config_hash,
                    current_fp,
                )
                self._evict_locked(key)
                self._metrics.misses += 1
                return None

            # --- TTL check ---
            age = time.time() - entry.cached_at
            if age > self._ttl_seconds:
                logger.debug(
                    "Cache TTL expired for %s (age=%.0fs, ttl=%.0fs)",
                    dossier_url[:60],
                    age,
                    self._ttl_seconds,
                )
                self._evict_locked(key)
                self._metrics.misses += 1
                return None

            # --- Cache hit ---
            self._metrics.hits += 1
            self._touch_locked(key)

            # Deep copy mutable containers to prevent cross-request
            # mutation; leave immutable / read-only references as-is.
            result = CachedDossierVerification(
                dossier_url=entry.dossier_url,
                passport_kid=entry.passport_kid,
                dag=entry.dag,  # read-only reference
                chain_claim=copy.deepcopy(entry.chain_claim),
                contained_saids=list(entry.contained_saids),
                revocation_status=copy.deepcopy(entry.revocation_status),
                revocation_last_checked=entry.revocation_last_checked,
                cached_at=entry.cached_at,
                config_hash=entry.config_hash,
                brand_name=entry.brand_name,
            )
            return result

    async def put(
        self,
        dossier_url: str,
        passport_kid: str,
        entry: CachedDossierVerification,
    ) -> None:
        """Store a verification result in the cache.

        The entry's ``config_hash`` is set to the current configuration
        fingerprint at insertion time.  If the cache is at capacity and
        the new key is not already present, the least-recently-used
        entry is evicted first.

        Parameters
        ----------
        dossier_url : str
            Evidence URL (used as the first part of the compound key).
        passport_kid : str
            PASSporT ``kid`` (second part of the compound key).
        entry : CachedDossierVerification
            The verification result to cache.  ``config_hash`` will be
            overwritten with the current fingerprint.
        """
        key: CacheKey = (dossier_url, passport_kid)
        entry.config_hash = config_fingerprint()

        async with self._lock:
            # Evict LRU entries until we have room (only if this is a
            # genuinely new key -- replacing an existing key does not
            # require eviction).
            while (
                len(self._cache) >= self._max_entries
                and key not in self._cache
            ):
                self._evict_lru_locked()

            self._cache[key] = entry
            self._touch_locked(key)

            logger.debug(
                "Cached verification result for %s kid=%s",
                dossier_url[:60],
                passport_kid[:30],
            )

    async def update_revocation_all_for_url(
        self,
        dossier_url: str,
        credential_said: str,
        new_status: RevocationStatus,
    ) -> None:
        """Update revocation status for a credential across **all** kid variants.

        Because revocation is a property of the credential itself (not
        of the PASSporT key that presented it), a single revocation
        event must propagate to every ``(dossier_url, *)`` entry.

        The ``REVOKED`` status is sticky: once a credential is marked
        ``REVOKED``, subsequent calls with ``UNREVOKED`` or
        ``UNDEFINED`` will **not** downgrade it.

        Parameters
        ----------
        dossier_url : str
            Dossier evidence URL.
        credential_said : str
            SAID of the credential whose status changed.
        new_status : RevocationStatus
            The new revocation status to apply.
        """
        async with self._lock:
            for key, entry in self._cache.items():
                if key[0] != dossier_url:
                    continue

                old = entry.revocation_status.get(credential_said)

                # Never downgrade from REVOKED.
                if old == RevocationStatus.REVOKED:
                    continue

                entry.revocation_status[credential_said] = new_status
                self._metrics.revocation_checks += 1

                if new_status == RevocationStatus.REVOKED:
                    logger.warning(
                        "Revocation detected: credential %s in %s "
                        "(kid=%s)",
                        credential_said[:20],
                        dossier_url[:60],
                        key[1][:30],
                    )

    async def update_revocation_timestamp_all_for_url(
        self,
        dossier_url: str,
    ) -> None:
        """Update ``revocation_last_checked`` for all kid variants of a URL.

        Called by the background revocation checker after it has
        finished checking all credentials in a dossier, regardless of
        whether any individual check succeeded or failed.

        Parameters
        ----------
        dossier_url : str
            Dossier evidence URL.
        """
        now = time.time()
        async with self._lock:
            for key, entry in self._cache.items():
                if key[0] == dossier_url:
                    entry.revocation_last_checked = now

    async def clear(self) -> None:
        """Clear entire cache (positive + negative)."""
        async with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._negative_cache.clear()

    # ---- Negative cache (Sprint 88) ----

    def get_negative(self, dossier_url: str, registry_version: str) -> Optional[NegativeCacheEntry]:
        """Get a negative cache entry if unexpired and version-matching."""
        entry = self._negative_cache.get(dossier_url)
        if entry is None:
            return None
        if entry.is_expired or entry.registry_version != registry_version:
            del self._negative_cache[dossier_url]
            return None
        return entry

    def put_negative(self, entry: NegativeCacheEntry) -> None:
        """Store a governance-deterministic INDETERMINATE result."""
        # Enforce quota
        while len(self._negative_cache) >= NEGATIVE_CACHE_MAX_ENTRIES:
            # Evict oldest
            oldest_key = next(iter(self._negative_cache))
            del self._negative_cache[oldest_key]
        self._negative_cache[entry.dossier_url] = entry

    def stats(self) -> dict:
        """Return a snapshot of cache metrics and current size.

        Returns
        -------
        dict
            Keys: ``hits``, ``misses``, ``evictions``,
            ``revocation_checks``, ``size``.
        """
        d = self._metrics.to_dict()
        d["size"] = len(self._cache)
        return d

    # ------------------------------------------------------------------
    # Internal helpers (must be called with ``_lock`` held)
    # ------------------------------------------------------------------

    def _touch_locked(self, key: CacheKey) -> None:
        """Move *key* to the most-recently-used end of the LRU order.

        ``OrderedDict.move_to_end`` is O(1).
        """
        self._access_order[key] = None
        self._access_order.move_to_end(key)

    def _evict_locked(self, key: CacheKey) -> None:
        """Remove *key* from both the data store and the LRU order."""
        if key in self._cache:
            del self._cache[key]
            self._metrics.evictions += 1
        self._access_order.pop(key, None)

    def _evict_lru_locked(self) -> None:
        """Evict the least-recently-used entry.

        ``next(iter(...))`` on an ``OrderedDict`` returns the first
        (oldest) key in O(1).
        """
        if self._access_order:
            lru_key: CacheKey = next(iter(self._access_order))
            logger.debug(
                "LRU eviction: %s kid=%s",
                lru_key[0][:60],
                lru_key[1][:30],
            )
            self._evict_locked(lru_key)


# ======================================================================
# Module-level singleton
# ======================================================================

_verification_cache: Optional[VerificationResultCache] = None


def get_verification_cache() -> VerificationResultCache:
    """Return the module-level verification cache singleton.

    The singleton is lazily created on first access using the
    configuration values ``VERIFICATION_CACHE_MAX_ENTRIES`` and
    ``VERIFICATION_CACHE_TTL`` from ``app.config``.

    Returns
    -------
    VerificationResultCache
        The shared cache instance.
    """
    global _verification_cache
    if _verification_cache is None:
        _verification_cache = VerificationResultCache(
            max_entries=VERIFICATION_CACHE_MAX_ENTRIES,
            ttl_seconds=VERIFICATION_CACHE_TTL,
        )
        logger.info(
            "Verification cache initialized: max_entries=%d, ttl=%.0fs, "
            "enabled=%s",
            VERIFICATION_CACHE_MAX_ENTRIES,
            VERIFICATION_CACHE_TTL,
            VERIFICATION_CACHE_ENABLED,
        )
    return _verification_cache


def reset_verification_cache() -> None:
    """Reset the module-level cache singleton.

    Intended for use in tests to ensure a clean cache between test
    cases.  Discards all cached entries and metrics.
    """
    global _verification_cache
    _verification_cache = None
