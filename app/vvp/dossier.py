# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Dossier fetch, parse, DAG validation, and LRU cache.

Provides the plumbing between raw dossier bytes (fetched from the URL
carried in the VVP-Identity ``evd`` field) and the structured
credential graph used by the verification pipeline.

The main entry points are:

- :func:`fetch_dossier` — async HTTP GET with size/timeout guards.
- :func:`parse_dossier` — multi-format detector (JSON array, Provenant
  wrapper, CESR stream) → list of :class:`ACDC`.
- :func:`build_and_validate_dossier` — construct a :class:`DossierDAG`
  and validate structural integrity.
- :class:`DossierCache` — thread-safe LRU cache with TTL expiry and
  content-addressable invalidation by SAID.

Format detection follows a lenient strategy: we attempt JSON parsing
first (compact arrays, Provenant credential wrappers, and bare ACDC
objects are all accepted), then fall back to bracket-counting extraction
for raw CESR/JSON-interleaved streams.

References
----------
- VVP Verifier Specification §6 — Dossier graph validation
- ToIP ACDC specification — Credential structure
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.config import (
    DOSSIER_CACHE_MAX_ENTRIES,
    DOSSIER_CACHE_TTL_SECONDS,
    DOSSIER_MAX_SIZE_BYTES,
)
from app.vvp.fetch import FetchError, safe_get
from app.vvp.acdc import (
    ACDC,
    DossierDAG,
    build_credential_graph,
    parse_acdc,
    validate_dag,
)
from app.vvp.exceptions import (
    DossierFetchError,
    DossierGraphError,
    DossierParseError,
)
from app.vvp.models import ErrorCode, ErrorDetail, make_error

logger = logging.getLogger(__name__)

__all__ = [
    "fetch_dossier",
    "parse_dossier",
    "build_and_validate_dossier",
    "CachedDossier",
    "DossierCache",
    "get_dossier_cache",
    "reset_dossier_cache",
]


# ======================================================================
# Fetching
# ======================================================================


async def fetch_dossier(url: str) -> bytes:
    """Fetch a dossier from *url* via SSRF-safe HTTP GET.

    Parameters
    ----------
    url : str
        The evidence URL from the VVP-Identity ``evd`` field.

    Returns
    -------
    bytes
        The raw response body.

    Raises
    ------
    DossierFetchError
        On network errors, timeouts, non-2xx status codes, or if the
        response body exceeds :data:`DOSSIER_MAX_SIZE_BYTES`.
    """
    if not url or not url.strip():
        raise DossierFetchError("Dossier URL is empty")

    logger.debug("Fetching dossier from %s", url)
    try:
        return await safe_get(url, max_size=DOSSIER_MAX_SIZE_BYTES)
    except FetchError as exc:
        raise DossierFetchError(str(exc)) from exc


# ======================================================================
# Parsing
# ======================================================================


def _extract_json_objects(data: str) -> List[dict]:
    """Extract complete JSON objects from a mixed text/JSON stream.

    Uses bracket counting to identify ``{...}`` boundaries within a
    string that may contain CESR primitives, whitespace, or other
    non-JSON content interleaved between JSON objects.

    Parameters
    ----------
    data : str
        The raw string to scan.

    Returns
    -------
    list[dict]
        A list of successfully parsed JSON objects.  Objects that fail
        ``json.loads`` are silently skipped (they may be non-ACDC JSON
        embedded in the stream).
    """
    objects: List[dict] = []
    i = 0
    length = len(data)

    while i < length:
        # Scan forward to the next opening brace.
        if data[i] != "{":
            i += 1
            continue

        # Count nesting depth to find the matching closing brace.
        depth = 0
        start = i
        in_string = False
        escape_next = False

        while i < length:
            ch = data[i]

            if escape_next:
                escape_next = False
                i += 1
                continue

            if ch == "\\":
                if in_string:
                    escape_next = True
                i += 1
                continue

            if ch == '"':
                in_string = not in_string
                i += 1
                continue

            if in_string:
                i += 1
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    # Complete JSON object candidate.
                    candidate = data[start : i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            objects.append(obj)
                    except (json.JSONDecodeError, ValueError):
                        # Not valid JSON — skip.
                        logger.debug(
                            "Skipping non-JSON object at offset %d", start
                        )
                    i += 1
                    break

            i += 1
        else:
            # Reached end of string without closing the brace — skip.
            logger.debug(
                "Unclosed JSON object starting at offset %d", start
            )
            break

    return objects


def _parse_json_array(data: list) -> List[ACDC]:
    """Parse a JSON array, treating each element as an ACDC dict.

    Parameters
    ----------
    data : list
        A JSON array of ACDC dicts.

    Returns
    -------
    list[ACDC]
        Successfully parsed credentials.

    Raises
    ------
    DossierParseError
        If no valid ACDC objects could be extracted.
    """
    acdcs: List[ACDC] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            logger.debug(
                "Skipping non-dict element at index %d in dossier array", idx
            )
            continue
        try:
            acdcs.append(parse_acdc(item))
        except ValueError as exc:
            logger.debug(
                "Failed to parse ACDC at index %d: %s", idx, exc
            )
    return acdcs


def _parse_provenant_wrapper(data: dict) -> List[ACDC]:
    """Parse a Provenant-style dossier wrapper.

    Provenant dossiers wrap credentials in a JSON object with a
    ``"credentials"`` key containing an array of ACDC dicts.

    Parameters
    ----------
    data : dict
        The wrapper object.

    Returns
    -------
    list[ACDC]
        Successfully parsed credentials.
    """
    creds = data.get("credentials")
    if not isinstance(creds, list):
        return []
    return _parse_json_array(creds)


def parse_dossier(raw: bytes) -> List[ACDC]:
    """Parse raw dossier bytes into a list of ACDC credentials.

    Format detection strategy:

    1. **JSON array** — starts with ``[``.  Each element is parsed as
       an ACDC dict.
    2. **JSON object** — starts with ``{``.  Checked for:
       a. Provenant wrapper (has ``"credentials"`` key).
       b. Bare single ACDC.
    3. **CESR / mixed stream** — bracket-counting extraction of embedded
       JSON objects, each parsed as a potential ACDC.

    Parameters
    ----------
    raw : bytes
        The raw dossier payload.

    Returns
    -------
    list[ACDC]
        Parsed ACDC credentials.

    Raises
    ------
    DossierParseError
        If no valid ACDC credentials can be extracted from the payload.
    """
    if not raw:
        raise DossierParseError("Empty dossier payload")

    # Decode bytes to string for JSON parsing.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DossierParseError(
            f"Dossier payload is not valid UTF-8: {exc}"
        ) from exc

    stripped = text.lstrip()
    if not stripped:
        raise DossierParseError("Dossier payload is empty after stripping")

    acdcs: List[ACDC] = []

    # ------------------------------------------------------------------
    # Strategy 1: JSON array
    # ------------------------------------------------------------------
    if stripped[0] == "[":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise DossierParseError(
                f"Dossier looks like a JSON array but failed to parse: {exc}"
            ) from exc

        if isinstance(data, list):
            acdcs = _parse_json_array(data)
            if acdcs:
                logger.debug(
                    "Parsed %d ACDCs from JSON array dossier", len(acdcs)
                )
                return acdcs

        raise DossierParseError(
            "Dossier JSON array contained no valid ACDC credentials"
        )

    # ------------------------------------------------------------------
    # Strategy 2: JSON object (Provenant wrapper or single ACDC)
    # ------------------------------------------------------------------
    if stripped[0] == "{":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            # Not valid JSON as a whole — fall through to bracket scanning.
            data = None

        if isinstance(data, dict):
            # 2a. Provenant wrapper: {"credentials": [...]}
            if "credentials" in data:
                acdcs = _parse_provenant_wrapper(data)
                if acdcs:
                    logger.debug(
                        "Parsed %d ACDCs from Provenant wrapper", len(acdcs)
                    )
                    return acdcs
                # Wrapper present but no valid creds — fall through.

            # 2b. Bare single ACDC (has "d", "i", "s", "a" fields).
            if all(k in data for k in ("d", "i", "s", "a")):
                try:
                    acdc = parse_acdc(data)
                    logger.debug("Parsed single ACDC dossier: %s", acdc.said)
                    return [acdc]
                except ValueError as exc:
                    logger.debug("Single ACDC parse failed: %s", exc)

    # ------------------------------------------------------------------
    # Strategy 3: CESR / mixed stream — bracket-counting extraction
    # ------------------------------------------------------------------
    json_objects = _extract_json_objects(stripped)
    if json_objects:
        for obj in json_objects:
            # Each extracted object might be an ACDC.
            if not all(k in obj for k in ("d", "i", "s")):
                logger.debug(
                    "Skipping non-ACDC JSON object (missing d/i/s fields)"
                )
                continue
            try:
                acdcs.append(parse_acdc(obj))
            except ValueError as exc:
                logger.debug("Failed to parse extracted ACDC: %s", exc)

    if acdcs:
        logger.debug(
            "Parsed %d ACDCs from CESR/mixed stream dossier", len(acdcs)
        )
        return acdcs

    raise DossierParseError(
        "No valid ACDC credentials found in dossier payload"
    )


# ======================================================================
# DAG Building and Validation
# ======================================================================


def build_and_validate_dossier(
    acdcs: List[ACDC],
) -> Tuple[DossierDAG, List[ErrorDetail]]:
    """Build and validate a credential graph from parsed ACDCs.

    Constructs a :class:`DossierDAG` from the provided credentials and
    runs structural validation (root existence, cycle detection, dangling
    edge targets).

    Parameters
    ----------
    acdcs : list[ACDC]
        The parsed ACDC credentials from the dossier.

    Returns
    -------
    tuple[DossierDAG, list[ErrorDetail]]
        The credential graph and a (possibly empty) list of structural
        errors.  An empty error list means the DAG is structurally valid.

    Raises
    ------
    DossierGraphError
        If the credential list is empty or the graph cannot be
        constructed at all (e.g. every credential is a duplicate).
    """
    if not acdcs:
        raise DossierGraphError("Cannot build graph from empty credential list")

    try:
        dag = build_credential_graph(acdcs)
    except ValueError as exc:
        raise DossierGraphError(
            f"Failed to build credential graph: {exc}"
        ) from exc

    errors = validate_dag(dag)

    if errors:
        logger.warning(
            "Dossier DAG validation found %d error(s): %s",
            len(errors),
            "; ".join(e.message if hasattr(e, "message") else str(e) for e in errors),
        )
    else:
        logger.debug(
            "Dossier DAG valid: %d nodes, %d edges, root=%s",
            len(dag.nodes),
            len(dag.edges),
            dag.root,
        )

    return dag, errors


# ======================================================================
# Dossier Cache
# ======================================================================


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
