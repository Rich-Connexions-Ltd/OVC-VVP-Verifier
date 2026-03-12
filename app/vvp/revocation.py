# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Background revocation checker for cached verification results.

Runs a single asynchronous background task that periodically re-checks
the revocation status of credentials in the verification result cache.
Operates on the :class:`~app.vvp.cache.VerificationResultCache`,
updating **all** ``passport_kid`` variants for a given dossier URL on
each check.

Deduplication is by dossier URL (not compound key) because revocation
is a per-credential property — independent of which PASSporT key
presented the dossier.

The checker uses an ``asyncio.Queue`` for work items and a semaphore to
limit concurrency.  Each dossier URL is enqueued at most once; the
``_pending`` set prevents duplicates.

Revocation checking flow:

1. A verification request finds a cache hit whose
   ``revocation_last_checked`` is older than ``recheck_interval``.
2. The request handler calls ``enqueue(dossier_url)``.
3. The background worker picks up the URL and checks every credential
   SAID via the TEL client.
4. Results are written back into the cache atomically (all kid
   variants) via ``update_revocation_all_for_url``.
5. The timestamp is updated via ``update_revocation_timestamp_all_for_url``.

The ``REVOKED`` status is never downgraded, even if a subsequent TEL
query returns an error or UNKNOWN.  Existing status is preserved on
transient failures.

References
----------
- VVP Verifier Specification v1.5 §5A Phase 9 — Revocation check
- Sprint 51 — Background revocation checker
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, Set

from app.vvp.cache import RevocationStatus, VerificationResultCache

logger = logging.getLogger("vvp.revocation")

__all__ = [
    "BackgroundRevocationChecker",
    "get_revocation_checker",
    "reset_revocation_checker",
]


class BackgroundRevocationChecker:
    """Asynchronous background worker for credential revocation re-checking.

    Parameters
    ----------
    cache : VerificationResultCache
        The shared verification result cache whose entries will be
        checked and updated.
    recheck_interval : float
        Minimum elapsed seconds since ``revocation_last_checked`` before
        a dossier is eligible for re-checking.  Default 300 s (5 min).
    concurrency : int
        Maximum number of concurrent revocation checks.  Default 1
        (serial processing) to be conservative with TEL endpoints.
    """

    def __init__(
        self,
        cache: VerificationResultCache,
        recheck_interval: float = 300.0,
        concurrency: int = 1,
    ) -> None:
        self._cache = cache
        self._recheck_interval = recheck_interval

        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._pending: Set[str] = set()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(self, dossier_url: str) -> None:
        """Enqueue a dossier URL for background revocation checking.

        Deduplicates by URL: if the same URL is already in the queue
        (or being processed), subsequent calls are silently ignored.

        Parameters
        ----------
        dossier_url : str
            The dossier evidence URL to check.
        """
        if dossier_url in self._pending:
            return
        self._pending.add(dossier_url)
        await self._queue.put(dossier_url)
        logger.debug(
            "Enqueued revocation check for %s", dossier_url[:60]
        )

    def needs_recheck(
        self, revocation_last_checked: Optional[float]
    ) -> bool:
        """Determine whether revocation data is stale.

        Parameters
        ----------
        revocation_last_checked : float or None
            Epoch timestamp of the last revocation check, or ``None``
            if revocation has never been checked.

        Returns
        -------
        bool
            ``True`` if revocation data is stale (never checked, or
            older than ``recheck_interval``).
        """
        if revocation_last_checked is None:
            return True
        age = time.time() - revocation_last_checked
        return age > self._recheck_interval

    async def start(self) -> None:
        """Start the background worker task.

        Idempotent: calling ``start()`` when already running is a
        no-op.
        """
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._worker())
        logger.info("Background revocation checker started")

    async def stop(self) -> None:
        """Gracefully stop the background worker.

        Sends a sentinel value to unblock the queue consumer, then
        waits up to 5 seconds for the task to finish.  If the task
        does not exit in time it is cancelled.
        """
        self._running = False
        if self._task is not None:
            # Send empty-string sentinel to unblock queue.get().
            await self._queue.put("")
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None
        logger.info("Background revocation checker stopped")

    # ------------------------------------------------------------------
    # Internal worker
    # ------------------------------------------------------------------

    async def _worker(self) -> None:
        """Main worker loop: consume URLs from the queue and check revocations."""
        while self._running:
            try:
                dossier_url = await asyncio.wait_for(
                    self._queue.get(), timeout=10.0
                )
            except asyncio.TimeoutError:
                continue

            # Sentinel check for shutdown.
            if not dossier_url:
                continue

            self._pending.discard(dossier_url)

            async with self._semaphore:
                try:
                    await self._check_revocations(dossier_url)
                except Exception:
                    logger.exception(
                        "Background revocation check failed for %s",
                        dossier_url[:60],
                    )

    async def _check_revocations(self, dossier_url: str) -> None:
        """Perform revocation checks for all credentials in a cached dossier.

        Looks up any cached entry for *dossier_url* (we only need one
        entry to get the list of ``contained_saids``).  For each SAID,
        queries the TEL and updates the cache.

        Revocation status is never downgraded from ``REVOKED``.
        Existing status is preserved on TEL query errors.

        Parameters
        ----------
        dossier_url : str
            The dossier evidence URL whose credentials should be
            checked.
        """
        cache = self._cache
        entry = None

        # Find any cached entry for this URL to get the credential SAIDs.
        # We access the internal _lock and _cache directly because there
        # is no public "scan by URL" method on the cache.
        async with cache._lock:
            for key, cached in cache._cache.items():
                if key[0] == dossier_url:
                    entry = cached
                    break

        if entry is None:
            logger.debug(
                "No cached entry for %s; skipping revocation check",
                dossier_url[:60],
            )
            return

        # Import TEL module lazily to avoid circular imports and to
        # allow the checker to operate without heavy dependencies in
        # unit tests (where _check_revocations is typically mocked).
        from app.vvp.tel import CredentialStatus, check_revocation

        # Extract registry SAIDs from the DAG for OOBI derivation.
        dag = entry.dag

        for said in entry.contained_saids:
            try:
                # Attempt to find the registry SAID from the DAG node
                # (needed by some TEL endpoints for OOBI resolution).
                registry_said = None
                if dag and hasattr(dag, "nodes"):
                    node = dag.nodes.get(said)
                    if (
                        node
                        and hasattr(node, "raw")
                        and isinstance(node.raw, dict)
                    ):
                        registry_said = node.raw.get("ri")

                result = await check_revocation(
                    credential_said=said,
                    registry_said=registry_said,
                )

                if result.status == CredentialStatus.REVOKED:
                    await cache.update_revocation_all_for_url(
                        dossier_url, said, RevocationStatus.REVOKED
                    )
                elif result.status == CredentialStatus.ACTIVE:
                    await cache.update_revocation_all_for_url(
                        dossier_url, said, RevocationStatus.UNREVOKED
                    )
                # UNKNOWN / ERROR: keep existing status (do not downgrade).
            except Exception:
                logger.exception(
                    "Revocation check failed for SAID %s", said[:20]
                )
                # Keep existing status on failure.

        # Update timestamp for all variants even if individual checks
        # failed, to prevent immediate re-enqueue.
        await cache.update_revocation_timestamp_all_for_url(dossier_url)

        logger.debug(
            "Revocation check complete for %s", dossier_url[:60]
        )


# ======================================================================
# Module-level singleton
# ======================================================================

_revocation_checker: Optional[BackgroundRevocationChecker] = None


def get_revocation_checker() -> BackgroundRevocationChecker:
    """Return the module-level revocation checker singleton.

    The singleton is lazily created on first access, configured with
    the shared verification cache from
    :func:`~app.vvp.cache.get_verification_cache`.

    Returns
    -------
    BackgroundRevocationChecker
        The shared checker instance.
    """
    global _revocation_checker
    if _revocation_checker is None:
        from app.vvp.cache import get_verification_cache

        _revocation_checker = BackgroundRevocationChecker(
            cache=get_verification_cache(),
        )
    return _revocation_checker


def reset_revocation_checker() -> None:
    """Reset the module-level revocation checker singleton.

    Intended for use in tests to ensure a clean checker between test
    cases.  Does **not** stop the background task — callers should
    ``await stop()`` first if the checker was started.
    """
    global _revocation_checker
    _revocation_checker = None
