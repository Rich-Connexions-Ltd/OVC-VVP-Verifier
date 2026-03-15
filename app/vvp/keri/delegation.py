# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/delegation.py
# Source commit: 398d40d (2026-03-14)

"""Multi-level KERI delegation validation.

Supports delegation chains: Delegator A -> Sub-Delegator B -> Identifier C

Per KERI spec, delegated identifiers (dip/drt events) require authorization
from their delegator. This module resolves and validates complete delegation
chains back to a non-delegated root.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Set, Tuple

from .kel_parser import EventType, KELEvent
from .exceptions import KELChainInvalidError, ResolutionFailedError
from app.vvp.api_models import ClaimStatus

log = logging.getLogger(__name__)

# Maximum delegation depth to prevent infinite recursion
MAX_DELEGATION_DEPTH = 5


@dataclass
class DelegationChain:
    """Represents a validated delegation chain.

    Attributes:
        delegates: List of AIDs from leaf to root delegator.
        root_aid: The non-delegated root identifier.
        valid: Whether the chain was successfully validated.
        errors: List of validation errors encountered.
    """
    delegates: List[str] = field(default_factory=list)
    root_aid: Optional[str] = None
    valid: bool = False
    errors: List[str] = field(default_factory=list)


async def resolve_delegation_chain(
    delegated_aid: str,
    inception_event: KELEvent,
    reference_time: datetime,
    oobi_resolver: Callable,
    visited: Optional[Set[str]] = None,
    depth: int = 0
) -> DelegationChain:
    """Recursively resolve delegation chain to non-delegated root.

    For each delegated identifier:
    1. Extract delegator AID from 'di' field
    2. Resolve delegator's KEL via OOBI
    3. Validate delegator's key state at delegation time
    4. If delegator is also delegated, recurse
    5. Return full chain when non-delegated root found

    Args:
        delegated_aid: The delegated identifier to validate.
        inception_event: The DIP event establishing the delegation.
        reference_time: Time T for key state lookup.
        oobi_resolver: Async function(aid, time) -> KeyState to resolve key state.
        visited: Set of AIDs visited (cycle detection).
        depth: Current recursion depth.

    Returns:
        DelegationChain with full chain and validation status.

    Raises:
        KELChainInvalidError: If delegation chain is invalid.
        ResolutionFailedError: If delegator cannot be resolved.
    """
    if depth > MAX_DELEGATION_DEPTH:
        raise KELChainInvalidError(
            f"Delegation chain exceeds max depth {MAX_DELEGATION_DEPTH}"
        )

    visited = visited or set()
    if delegated_aid in visited:
        raise KELChainInvalidError(
            f"Circular delegation detected: {delegated_aid}"
        )
    visited.add(delegated_aid)

    delegator_aid = inception_event.delegator_aid
    if not delegator_aid:
        raise KELChainInvalidError(
            f"DIP event for {delegated_aid[:20]}... missing delegator AID"
        )

    log.debug(
        f"Resolving delegation: {delegated_aid[:20]}... -> {delegator_aid[:20]}... "
        f"(depth {depth})"
    )

    try:
        delegator_key_state = await oobi_resolver(delegator_aid, reference_time)
    except Exception as e:
        raise ResolutionFailedError(
            f"Failed to resolve delegator {delegator_aid[:20]}...: {e}"
        )

    if delegator_key_state.is_delegated:
        delegator_inception = delegator_key_state.inception_event
        if not delegator_inception:
            raise KELChainInvalidError(
                f"Delegator {delegator_aid[:20]}... missing inception event"
            )

        parent_chain = await resolve_delegation_chain(
            delegator_aid,
            delegator_inception,
            reference_time,
            oobi_resolver,
            visited,
            depth + 1
        )

        return DelegationChain(
            delegates=[delegated_aid] + parent_chain.delegates,
            root_aid=parent_chain.root_aid,
            valid=parent_chain.valid,
            errors=parent_chain.errors
        )

    log.debug(f"Found delegation root: {delegator_aid[:20]}...")
    return DelegationChain(
        delegates=[delegated_aid, delegator_aid],
        root_aid=delegator_aid,
        valid=True,
        errors=[]
    )


async def validate_delegation_authorization(
    delegation_event: KELEvent,
    delegator_kel: List[KELEvent],
    delegator_key_state: "KeyState"
) -> Tuple[bool, ClaimStatus, List[str]]:
    """Validate that delegator authorized this delegation.

    Per KERI spec, delegation requires:
    1. Delegator's seal in an interaction event (ixn) anchoring the delegation
    2. The seal contains the delegated identifier's inception event SAID
    3. Delegator's signature on the interaction event
    """
    errors: List[str] = []

    delegation_said = delegation_event.digest
    if not delegation_said:
        return (False, ClaimStatus.INVALID, ["Delegation event missing SAID"])

    anchor_event: Optional[KELEvent] = None
    for event in delegator_kel:
        if event.event_type != EventType.IXN:
            continue

        anchors = event.raw.get("a", [])
        if isinstance(anchors, list):
            for anchor in anchors:
                if isinstance(anchor, dict) and anchor.get("d") == delegation_said:
                    anchor_event = event
                    break
        elif isinstance(anchors, dict) and anchors.get("d") == delegation_said:
            anchor_event = event

        if anchor_event:
            break

    if not anchor_event:
        log.warning(
            f"Delegation anchor not found in delegator KEL for {delegation_said[:20]}..."
        )
        return (
            False,
            ClaimStatus.INDETERMINATE,
            ["Delegation anchor not found in delegator KEL"]
        )

    anchor_seq = anchor_event.sequence
    key_at_anchor = _find_key_state_at_sequence(delegator_kel, anchor_seq)
    if not key_at_anchor:
        return (
            False,
            ClaimStatus.INDETERMINATE,
            ["Cannot determine delegator key state at anchor time"]
        )

    if not _verify_event_signature(anchor_event, key_at_anchor):
        return (
            False,
            ClaimStatus.INVALID,
            ["Delegator anchor event signature invalid"]
        )

    if anchor_event.timestamp and delegation_event.timestamp:
        if anchor_event.timestamp > delegation_event.timestamp:
            return (
                False,
                ClaimStatus.INVALID,
                ["Delegation anchor event occurred after delegation"]
            )

    log.debug(
        f"Delegation authorization verified: anchor seq {anchor_seq} for "
        f"{delegation_said[:20]}..."
    )
    return (True, ClaimStatus.VALID, [])


def _find_key_state_at_sequence(
    kel: List[KELEvent],
    target_seq: int
) -> Optional[List[bytes]]:
    """Find signing keys in effect at a given sequence number."""
    current_keys: Optional[List[bytes]] = None

    for event in kel:
        if event.sequence > target_seq:
            break
        if event.is_establishment and event.signing_keys:
            current_keys = event.signing_keys

    return current_keys


def _verify_event_signature(
    event: KELEvent,
    signing_keys: List[bytes]
) -> bool:
    """Verify event signature against signing keys."""
    if not event.signatures:
        log.warning(f"Event seq {event.sequence} has no signatures")
        return False

    if not signing_keys:
        log.warning(f"No signing keys provided for event seq {event.sequence}")
        return False

    try:
        import pysodium
    except ImportError:
        log.warning("pysodium not available for delegation signature verification")
        return False

    from app.vvp.canonical import canonical_serialize

    try:
        signing_input = canonical_serialize(event.raw)
    except Exception as e:
        log.warning(f"Failed to serialize event for verification: {e}")
        return False

    for sig in event.signatures:
        for key in signing_keys:
            try:
                pysodium.crypto_sign_verify_detached(sig, signing_input, key)
                return True
            except Exception:
                continue

    log.warning(f"No valid signature found for event seq {event.sequence}")
    return False
