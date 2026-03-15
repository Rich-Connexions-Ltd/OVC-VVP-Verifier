# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/kel_resolver.py
# Source commit: 398d40d (2026-03-14)

"""KERI Key State Resolver.

Resolves the key state for an AID at a specific reference time T.
This is the core component for Tier 2 verification, enabling
historical key state validation per VVP spec §5.

Per spec §5A Step 4: "Resolve issuer key state at reference time T"
Per spec §5D: "VVP passports can verify at arbitrary past moments using historical data"
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .cache import CacheConfig, KeyStateCache
from .delegation import DelegationChain
from .exceptions import (
    KELChainInvalidError,
    KeyNotYetValidError,
    ResolutionFailedError,
)
from .kel_parser import (
    ESTABLISHMENT_TYPES,
    EventType,
    KELEvent,
    WitnessReceipt,
    parse_kel_stream,
    validate_kel_chain,
)
from .oobi import OOBIResult, dereference_oobi, validate_oobi_is_kel


@dataclass
class KeyState:
    """Resolved key state at a specific point in time.

    Attributes:
        aid: The AID (Autonomic Identifier).
        signing_keys: List of Ed25519 public keys (32 bytes each).
        sequence: Establishment event sequence number.
        establishment_digest: SAID of the establishment event.
        valid_from: Earliest witness timestamp for this state.
        witnesses: List of witness AIDs.
        toad: Witness threshold (threshold of accountable duplicity).
        is_delegated: True if this is a delegated identifier (dip/drt).
        delegator_aid: For delegated identifiers, the delegator's AID.
        inception_event: The inception event (icp/dip) for multi-level resolution.
        delegation_chain: Full delegation chain if resolved.
    """
    aid: str
    signing_keys: List[bytes]
    sequence: int
    establishment_digest: str
    valid_from: Optional[datetime]
    witnesses: List[str]
    toad: int
    is_delegated: bool = False
    delegator_aid: Optional[str] = None
    inception_event: Optional[KELEvent] = None
    delegation_chain: Optional["DelegationChain"] = None


# Global cache instance (singleton pattern)
_cache: Optional[KeyStateCache] = None


def get_cache(config: Optional[CacheConfig] = None) -> KeyStateCache:
    """Get or create the global key state cache.

    Reads VVP_KEY_STATE_FRESHNESS_SECONDS from app.config and clamps to 10-3600s.
    """
    global _cache
    if _cache is None:
        if config is None:
            import logging
            _log = logging.getLogger(__name__)
            from app.core.config import VVP_KEY_STATE_FRESHNESS_SECONDS
            raw_freshness = VVP_KEY_STATE_FRESHNESS_SECONDS
            freshness = max(10.0, min(3600.0, raw_freshness))
            if freshness != raw_freshness:
                _log.warning(
                    f"VVP_KEY_STATE_FRESHNESS_SECONDS={raw_freshness} "
                    f"clamped to {freshness} (bounds: 10-3600)"
                )
            config = CacheConfig(freshness_window_seconds=freshness)
        _cache = KeyStateCache(config)
    return _cache


def reset_cache() -> None:
    """Reset the global cache (for testing)."""
    global _cache
    _cache = None


async def resolve_key_state(
    kid: str,
    reference_time: datetime,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    use_cache: bool = True,
    _allow_test_mode: bool = False
) -> KeyState:
    """Resolve the key state for an AID at reference time T.

    This is the main entry point for Tier 2 key state resolution.
    It fetches the KEL, validates the chain, and determines which
    keys were valid at time T.

    Args:
        kid: The AID (Autonomic Identifier) to resolve.
        reference_time: The reference time T (typically PASSporT iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        use_cache: Whether to use/update the cache.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Returns:
        KeyState representing the keys valid at time T.

    Raises:
        ResolutionFailedError: If Tier 2 is disabled or resolution fails.
        KELChainInvalidError: If chain validation fails.
        KeyNotYetValidError: If no establishment event at/before T.
    """
    from app.core.config import VVP_TIER2_KEL_ENABLED

    if not VVP_TIER2_KEL_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled. "
            "Set VVP_TIER2_KEL_ENABLED=true to enable KERI-based "
            "key state resolution."
        )

    aid = _extract_aid(kid)

    cache = get_cache() if use_cache else None

    if cache:
        cached = await cache.get_for_time(aid, reference_time)
        if cached:
            return cached

    if not oobi_url:
        oobi_url = _construct_oobi_url(kid)

    oobi_result, events = await _fetch_and_validate_oobi(
        oobi_url,
        aid,
        strict_validation=not _allow_test_mode
    )

    key_state, valid_until = _find_key_state_at_time(
        aid=aid,
        events=events,
        reference_time=reference_time,
        min_witnesses=min_witnesses,
        strict_validation=not _allow_test_mode
    )

    if cache:
        await cache.put(
            key_state,
            reference_time=reference_time,
            valid_until=valid_until,
            sequence=key_state.sequence,
        )

    return key_state


async def resolve_key_state_with_kel(
    kid: str,
    reference_time: datetime,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> Tuple[KeyState, List[KELEvent]]:
    """Resolve key state AND return the full KEL for delegation authorization.

    Used for delegation authorization validation which requires access to
    the delegator's full KEL to find anchor events.
    """
    from app.core.config import VVP_TIER2_KEL_ENABLED

    if not VVP_TIER2_KEL_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError("Tier 2 KEL resolution is disabled.")

    aid = _extract_aid(kid)

    if not oobi_url:
        oobi_url = _construct_oobi_url(kid)

    oobi_result, events = await _fetch_and_validate_oobi(
        oobi_url,
        aid,
        strict_validation=not _allow_test_mode
    )

    key_state, valid_until = _find_key_state_at_time(
        aid=aid,
        events=events,
        reference_time=reference_time,
        min_witnesses=min_witnesses,
        strict_validation=not _allow_test_mode
    )

    cache = get_cache()
    await cache.put(
        key_state,
        reference_time=reference_time,
        valid_until=valid_until,
        sequence=key_state.sequence,
    )

    return key_state, events


async def _fetch_and_validate_oobi(
    oobi_url: str,
    aid: str,
    timeout: float = 5.0,
    strict_validation: bool = True
) -> Tuple[OOBIResult, List[KELEvent]]:
    """Fetch OOBI and validate it contains a valid KEL.

    Per VVP §4.2, the kid OOBI must resolve to a valid Key Event Log.
    """
    from .exceptions import OOBIContentInvalidError

    oobi_result = await dereference_oobi(oobi_url, timeout=timeout)

    if not oobi_result.kel_data:
        raise OOBIContentInvalidError(f"OOBI response contains no KEL data for {aid}")

    events = parse_kel_stream(
        oobi_result.kel_data,
        content_type=oobi_result.content_type,
        allow_json_only=True
    )

    if not events:
        raise OOBIContentInvalidError(f"Empty KEL for AID {aid}")

    first_event = events[0]
    if first_event.event_type not in {EventType.ICP, EventType.DIP}:
        raise OOBIContentInvalidError(
            f"OOBI KEL must start with inception event, found: {first_event.event_type.value}"
        )

    validate_kel_chain(
        events,
        validate_saids=strict_validation,
        use_canonical=strict_validation,
        validate_witnesses=strict_validation
    )

    return oobi_result, events


def _extract_aid(kid: str) -> str:
    """Extract the AID from a kid value."""
    if kid.startswith(("http://", "https://")):
        from .oobi import _extract_aid_from_url
        aid = _extract_aid_from_url(kid)
        if aid:
            return aid
        raise ResolutionFailedError(f"Could not extract AID from OOBI URL: {kid}")

    if kid.startswith("did:web:"):
        if "#" in kid:
            aid = kid.split("#", 1)[1]
            if aid and aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                return aid
        raise ResolutionFailedError(f"Could not extract AID from did:web URL: {kid[:30]}...")

    if kid and kid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
        return kid

    raise ResolutionFailedError(f"Invalid kid format: {kid[:20]}...")


def _construct_oobi_url(kid: str) -> str:
    """Construct an OOBI URL from a kid value."""
    if kid.startswith(("http://", "https://")):
        return kid

    raise ResolutionFailedError(
        f"Cannot resolve bare AID {kid[:20]}...: OOBI URL required. "
        f"Tier 2 resolution requires either an OOBI URL in the kid field "
        f"or configured witness endpoints."
    )


def _find_key_state_at_time(
    aid: str,
    events: List[KELEvent],
    reference_time: datetime,
    min_witnesses: Optional[int],
    strict_validation: bool = False
) -> Tuple[KeyState, Optional[datetime]]:
    """Find the key state that was valid at reference time T.

    Walks the KEL chronologically and finds the last establishment event
    at or before T.
    """
    establishment_events = [e for e in events if e.is_establishment]

    if not establishment_events:
        raise ResolutionFailedError(f"No establishment events in KEL for {aid}")

    valid_event: Optional[KELEvent] = None
    rotation_without_timestamp = False

    for event in establishment_events:
        event_time = _get_event_time(event)

        if event_time is None:
            if event.is_inception:
                valid_event = event
            else:
                rotation_without_timestamp = True
        elif _compare_datetimes(event_time, reference_time) <= 0:
            valid_event = event
            rotation_without_timestamp = False

    if rotation_without_timestamp and valid_event is not None:
        raise ResolutionFailedError(
            f"Cannot determine key state at {reference_time.isoformat()}: "
            f"KEL contains rotation events without timestamps. "
            f"Witness receipts with timestamps are required for historical key state resolution."
        )

    if valid_event is None:
        first_event_time = _get_event_time(establishment_events[0])
        if first_event_time:
            raise KeyNotYetValidError(
                f"Reference time {reference_time.isoformat()} is before "
                f"inception at {first_event_time.isoformat()}"
            )
        else:
            raise KeyNotYetValidError(
                f"Reference time {reference_time.isoformat()} is before inception"
            )

    _validate_witness_receipts(valid_event, min_witnesses, strict_validation)

    valid_until = None
    valid_event_index = establishment_events.index(valid_event)
    if valid_event_index + 1 < len(establishment_events):
        next_event = establishment_events[valid_event_index + 1]
        valid_until = _get_event_time(next_event)

    inception_event = establishment_events[0]
    is_delegated = inception_event.event_type in {EventType.DIP, EventType.DRT}
    delegator_aid = inception_event.delegator_aid if is_delegated else None

    key_state = KeyState(
        aid=aid,
        signing_keys=valid_event.signing_keys,
        sequence=valid_event.sequence,
        establishment_digest=valid_event.digest,
        valid_from=_get_event_time(valid_event),
        witnesses=valid_event.witnesses,
        toad=valid_event.toad,
        is_delegated=is_delegated,
        delegator_aid=delegator_aid,
        inception_event=inception_event,
        delegation_chain=None
    )

    return key_state, valid_until


def _normalize_datetime(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _compare_datetimes(dt1: datetime, dt2: datetime) -> int:
    norm1 = _normalize_datetime(dt1)
    norm2 = _normalize_datetime(dt2)
    if norm1 < norm2:
        return -1
    elif norm1 > norm2:
        return 1
    return 0


def _get_event_time(event: KELEvent) -> Optional[datetime]:
    """Get the effective time for an event."""
    if event.timestamp:
        return event.timestamp

    receipt_times = [
        r.timestamp for r in event.witness_receipts
        if r.timestamp is not None
    ]
    if receipt_times:
        return min(receipt_times)

    return None


def _validate_witness_receipts(
    event: KELEvent,
    min_witnesses: Optional[int],
    strict_validation: bool = False
) -> None:
    """Validate that an event has sufficient witness receipts."""
    from .exceptions import StateInvalidError

    if min_witnesses is not None:
        threshold = min_witnesses
    else:
        threshold = event.toad

    if threshold <= 0:
        return

    receipt_count = len(event.witness_receipts)

    if receipt_count == 0:
        if strict_validation:
            raise ResolutionFailedError(
                f"No witness receipts for event (need {threshold} per toad)"
            )
        return

    if receipt_count < threshold:
        if strict_validation:
            raise StateInvalidError(
                f"Insufficient witness receipts: got {receipt_count}, "
                f"need {threshold} (toad={event.toad})"
            )
        else:
            raise ResolutionFailedError(
                f"Insufficient witness receipts: got {receipt_count}, "
                f"need {threshold} (toad={event.toad})"
            )

    if strict_validation:
        from .kel_parser import validate_witness_receipts as validate_witness_sigs
        from app.vvp.canonical import canonical_serialize

        signing_input = canonical_serialize(event.raw)

        try:
            validate_witness_sigs(event, signing_input, threshold)
        except Exception as e:
            raise StateInvalidError(f"Witness signature validation failed: {e}")


async def resolve_key_state_tier1_fallback(kid: str) -> KeyState:
    """Tier 1 fallback: Extract key directly from AID without KEL validation.

    WARNING: This does NOT validate key state at time T.
    """
    from .key_parser import parse_kid_to_verkey

    verkey = parse_kid_to_verkey(kid)

    return KeyState(
        aid=kid,
        signing_keys=[verkey.raw],
        sequence=0,
        establishment_digest="",
        valid_from=None,
        witnesses=[],
        toad=0
    )
