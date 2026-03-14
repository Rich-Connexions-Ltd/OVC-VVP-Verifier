# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/kel_parser.py
# Source commit: 398d40d (2026-03-14)

"""KEL (Key Event Log) parser and validator.

Parses and validates KERI Key Event Logs per the KERI spec.
Supports both CESR-encoded streams (normative) and JSON (test fallback).

Chain validation ensures:
1. Each event's prior_digest matches the previous event's digest
2. Each event is signed by keys from the prior event (or self-signed for inception)
"""

import base64
import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import pysodium as _pysodium
except ImportError:
    _pysodium = None  # type: ignore[assignment]

try:
    import blake3 as _blake3
except ImportError:
    _blake3 = None  # type: ignore[assignment]

from .cesr import CESRMessage, parse_cesr_stream as cesr_parse, is_cesr_stream
from .exceptions import (
    KELChainInvalidError,
    ResolutionFailedError,
)
from app.vvp.canonical import canonical_serialize, most_compact_form

# Content types for OOBI responses
CESR_CONTENT_TYPE = "application/json+cesr"
JSON_CONTENT_TYPE = "application/json"


class EventType(Enum):
    """KERI event types.

    Only establishment events (icp, rot, dip, drt) affect key state.
    Interaction events (ixn) are included in the log but don't change keys.
    """
    ICP = "icp"  # Inception - first event, establishes AID
    ROT = "rot"  # Rotation - changes signing keys
    IXN = "ixn"  # Interaction - anchors data, no key change
    DIP = "dip"  # Delegated inception
    DRT = "drt"  # Delegated rotation


# Establishment events that change key state
ESTABLISHMENT_TYPES = frozenset({EventType.ICP, EventType.ROT, EventType.DIP, EventType.DRT})

# Delegated events requiring special handling
DELEGATED_TYPES = frozenset({EventType.DIP, EventType.DRT})


@dataclass
class WitnessReceipt:
    """Receipt from a witness confirming an event.

    Witnesses provide threshold signatures on events to establish
    consensus on the event log state.

    Attributes:
        witness_aid: The AID of the witness (may be empty for indexed sigs).
        signature: The witness's signature on the event.
        timestamp: Optional timestamp when the witness signed.
        index: Optional index into the event's witnesses list (for indexed sigs).
    """
    witness_aid: str
    signature: bytes
    timestamp: Optional[datetime] = None
    index: Optional[int] = None


@dataclass
class KELEvent:
    """Parsed KERI event from a Key Event Log.

    Contains both the event data and attached signatures/receipts.

    Attributes:
        event_type: The type of event (icp, rot, etc.).
        sequence: Event sequence number (0 for inception).
        prior_digest: SAID of the prior event (empty for inception).
        digest: This event's SAID (self-addressing identifier).
        signing_keys: Current signing key(s) from 'k' field.
        next_keys_digest: Commitment to next keys ('n' field).
        toad: Witness threshold (threshold of accountable duplicity).
        witnesses: List of witness AIDs from 'b' field.
        timestamp: Timestamp from witness receipts (if available).
        signatures: Attached controller signatures.
        witness_receipts: Receipts from witnesses.
        raw: Original parsed event dict for debugging.
        delegator_aid: For delegated events (dip/drt), the delegator's AID from 'di' field.
    """
    event_type: EventType
    sequence: int
    prior_digest: str
    digest: str
    signing_keys: List[bytes]
    next_keys_digest: Optional[str]
    toad: int
    witnesses: List[str]
    timestamp: Optional[datetime] = None
    signatures: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    delegator_aid: Optional[str] = None

    @property
    def is_establishment(self) -> bool:
        """True if this event establishes or rotates key state."""
        return self.event_type in ESTABLISHMENT_TYPES

    @property
    def is_inception(self) -> bool:
        """True if this is an inception event (icp or dip)."""
        return self.event_type in {EventType.ICP, EventType.DIP}

    @property
    def is_delegated(self) -> bool:
        """True if this is a delegated event requiring delegator validation."""
        return self.event_type in DELEGATED_TYPES


def parse_kel_stream(
    kel_data: bytes,
    content_type: str = JSON_CONTENT_TYPE,
    allow_json_only: bool = False
) -> List[KELEvent]:
    """Parse a KEL stream into a list of events.

    Routes to CESR or JSON parser based on content type. Production use
    requires CESR format; JSON is only allowed for testing.

    Args:
        kel_data: Raw KEL data (CESR or JSON encoded).
        content_type: Content-Type from OOBI response. Used for routing
            to the appropriate parser.
        allow_json_only: If True, accept JSON format even when CESR is expected.
            Defaults to False (production mode). Set True only for testing.

    Returns:
        List of parsed KELEvent objects in sequence order.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
    # Detect format based on content type and data inspection
    is_cesr = CESR_CONTENT_TYPE.lower() in content_type.lower()

    # Also check for CESR markers in data (regardless of content type)
    if not is_cesr and kel_data:
        is_cesr = is_cesr_stream(kel_data)

    if is_cesr:
        return _parse_cesr_kel(kel_data)

    # JSON format - check if allowed
    if not allow_json_only:
        if kel_data and kel_data[0:1] == b"{":
            pass  # Allow JSON in transition period
        elif kel_data and kel_data[0:1] in (b"-", b"0", b"1", b"4", b"5", b"6"):
            return _parse_cesr_kel(kel_data)

    # Try JSON parsing
    try:
        return _parse_json_kel(kel_data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ResolutionFailedError(
            f"Failed to parse KEL: {e}"
        )


def _parse_json_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse JSON-encoded KEL (test fallback)."""
    data = json.loads(kel_data.decode("utf-8"))

    if isinstance(data, dict):
        events_data = [data]
    elif isinstance(data, list):
        events_data = data
    else:
        raise ResolutionFailedError("Invalid JSON KEL format: expected dict or list")

    events = []
    for event_data in events_data:
        event = _parse_event_dict(event_data)
        events.append(event)

    events.sort(key=lambda e: e.sequence)
    return events


def _parse_event_dict(data: Dict[str, Any]) -> KELEvent:
    """Parse a single event from a dictionary.

    KERI event fields:
    - t: event type
    - s: sequence number (hex string)
    - p: prior event digest
    - d: this event's digest (SAID)
    - k: signing keys
    - n: next keys digest
    - bt: witness threshold
    - b: witnesses
    """
    try:
        event_type_str = data.get("t", "")
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            raise ResolutionFailedError(f"Unknown event type: {event_type_str}")

        # Extract delegator AID for delegated events (dip/drt)
        delegator_aid = None
        if event_type in DELEGATED_TYPES:
            delegator_aid = data.get("di")
            if not delegator_aid:
                raise ResolutionFailedError(
                    f"Delegated event '{event_type_str}' missing required 'di' field"
                )

        # Parse sequence (hex string in KERI)
        seq_str = data.get("s", "0")
        sequence = int(seq_str, 16) if isinstance(seq_str, str) else int(seq_str)

        # Parse keys from 'k' field
        keys_data = data.get("k", [])
        signing_keys = []
        for key_str in keys_data:
            key_bytes = _decode_keri_key(key_str)
            signing_keys.append(key_bytes)

        # Parse signatures
        signatures = []
        sigs_data = data.get("signatures", data.get("-", []))
        if isinstance(sigs_data, list):
            for sig in sigs_data:
                if isinstance(sig, str):
                    signatures.append(_decode_signature(sig))
                elif isinstance(sig, dict) and "sig" in sig:
                    signatures.append(_decode_signature(sig["sig"]))

        # Parse witness receipts
        witness_receipts = []
        receipts_data = data.get("receipts", data.get("rcts", []))
        if isinstance(receipts_data, list):
            for rct in receipts_data:
                if isinstance(rct, dict):
                    witness_receipts.append(WitnessReceipt(
                        witness_aid=rct.get("i", ""),
                        signature=_decode_signature(rct.get("s", "")),
                        timestamp=_parse_timestamp(rct.get("dt"))
                    ))

        return KELEvent(
            event_type=event_type,
            sequence=sequence,
            prior_digest=data.get("p", ""),
            digest=data.get("d", ""),
            signing_keys=signing_keys,
            next_keys_digest=data.get("n", [None])[0] if isinstance(data.get("n"), list) else data.get("n"),
            toad=int(data.get("bt", "0"), 16) if isinstance(data.get("bt"), str) else data.get("bt", 0),
            witnesses=data.get("b", []),
            timestamp=_parse_timestamp(data.get("dt")),
            signatures=signatures,
            witness_receipts=witness_receipts,
            raw=data,
            delegator_aid=delegator_aid
        )
    except ResolutionFailedError:
        raise
    except Exception as e:
        raise ResolutionFailedError(f"Failed to parse event: {e}")


def _parse_cesr_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse CESR-encoded KEL stream.

    Only KEL (Key Event Log) events are parsed: icp, rot, ixn, dip, drt.
    Other KERI events like rpy (reply), qry (query), exn (exchange) are
    skipped as they are not part of the KEL.

    Returns:
        List of KELEvent objects parsed from the CESR stream.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
    cesr_messages = cesr_parse(kel_data)

    if not cesr_messages:
        return []

    KEL_EVENT_TYPES = {"icp", "rot", "ixn", "dip", "drt"}

    events = []
    for msg in cesr_messages:
        event_type = msg.event_dict.get("t", "")
        if event_type not in KEL_EVENT_TYPES:
            continue

        event = _parse_event_dict(msg.event_dict)

        # Add signatures from CESR attachments
        event.signatures = msg.controller_sigs

        # Convert CESR witness receipts to KELEvent format
        for receipt in msg.witness_receipts:
            event.witness_receipts.append(WitnessReceipt(
                witness_aid=receipt.witness_aid,
                signature=receipt.signature,
                index=receipt.index,
            ))

        events.append(event)

    events.sort(key=lambda e: e.sequence)
    return events


def _decode_keri_key(key_str: str) -> bytes:
    """Decode a KERI-encoded public key.

    KERI keys use CESR encoding with a derivation code prefix.
    For Ed25519 keys (B or D prefix), the standard CESR qb64 format is:
    - 44 chars total, decodes to 33 bytes (1 lead byte + 32-byte key)
    """
    if not key_str or len(key_str) < 2:
        raise ResolutionFailedError("Invalid key format: too short")

    code = key_str[0]

    if code in ("B", "D"):
        try:
            full_decoded = base64.urlsafe_b64decode(key_str)
        except Exception as e:
            raise ResolutionFailedError(f"Failed to decode key: {e}")

        if len(full_decoded) == 33:
            lead_byte = full_decoded[0]
            if lead_byte in (0x04, 0x0c):
                return full_decoded[1:]
            else:
                key_b64 = key_str[1:]
                padded = key_b64 + "=" * (-len(key_b64) % 4)
                try:
                    return base64.urlsafe_b64decode(padded)
                except Exception as e:
                    raise ResolutionFailedError(f"Failed to decode key: {e}")
        elif len(full_decoded) == 32:
            return full_decoded
        else:
            raise ResolutionFailedError(
                f"Invalid key length after decode: {len(full_decoded)}, expected 32 or 33"
            )

    raise ResolutionFailedError(f"Unsupported key derivation code: {code}")


def _decode_signature(sig_str: str) -> bytes:
    """Decode a KERI-encoded signature."""
    if not sig_str:
        return b""

    if sig_str.startswith(("0A", "0B", "0C", "0D", "1A", "2A")):
        sig_b64 = sig_str[2:]
    elif sig_str.startswith("-"):
        sig_b64 = sig_str[1:]
    else:
        sig_b64 = sig_str

    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return b""


def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


def validate_kel_chain(
    events: List[KELEvent],
    validate_saids: bool = True,
    use_canonical: bool = True,
    validate_witnesses: bool = False
) -> None:
    """Validate KEL chain continuity and signatures.

    Validates:
    1. First event is inception (icp or dip)
    2. Sequence numbers are consecutive
    3. Each event's prior_digest matches previous event's digest
    4. Each event is signed by keys from prior event (or self-signed for inception)
    5. Each event's digest (d field) matches computed SAID (if validate_saids=True)
    6. Witness receipts meet threshold (if validate_witnesses=True)

    Args:
        events: List of KELEvent objects in sequence order.
        validate_saids: If True, verify each event's digest matches computed SAID.
        use_canonical: If True, use KERI canonical serialization for signing input.
        validate_witnesses: If True, validate witness receipt signatures against
            event.toad threshold.

    Raises:
        KELChainInvalidError: If chain validation fails.
    """
    if not events:
        raise KELChainInvalidError("Empty KEL: no events to validate")

    first_event = events[0]
    if not first_event.is_inception:
        raise KELChainInvalidError(
            f"KEL must start with inception, found {first_event.event_type.value}"
        )

    if first_event.sequence != 0:
        raise KELChainInvalidError(
            f"Inception event must have sequence 0, found {first_event.sequence}"
        )

    if validate_saids:
        _validate_event_said(first_event, use_canonical=use_canonical)

    _validate_inception_signature(first_event, use_canonical=use_canonical)

    if validate_witnesses and first_event.toad > 0:
        signing_input = _compute_signing_input(first_event, use_canonical=use_canonical)
        validate_witness_receipts(first_event, signing_input, min_threshold=first_event.toad)

    current_keys = first_event.signing_keys

    prev_event = first_event
    for event in events[1:]:
        expected_seq = prev_event.sequence + 1
        if event.sequence != expected_seq:
            raise KELChainInvalidError(
                f"Sequence gap: expected {expected_seq}, found {event.sequence}"
            )

        if event.prior_digest != prev_event.digest:
            raise KELChainInvalidError(
                f"Chain break at seq {event.sequence}: prior_digest "
                f"{event.prior_digest[:16]}... != previous digest {prev_event.digest[:16]}..."
            )

        if validate_saids:
            _validate_event_said(event, use_canonical=use_canonical)

        _validate_event_signature(event, current_keys, use_canonical=use_canonical)

        if validate_witnesses and event.toad > 0:
            signing_input = _compute_signing_input(event, use_canonical=use_canonical)
            validate_witness_receipts(event, signing_input, min_threshold=event.toad)

        if event.is_establishment:
            current_keys = event.signing_keys

        prev_event = event


def _validate_event_said(event: KELEvent, use_canonical: bool = False) -> None:
    """Validate that an event's digest (d field) matches its computed SAID."""
    if not event.digest:
        return
    if not event.raw:
        return

    raw_copy = dict(event.raw)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)
    raw_copy.pop("receipts", None)
    raw_copy.pop("rcts", None)

    if use_canonical:
        computed = compute_said_canonical(raw_copy)
    else:
        computed = compute_said(raw_copy)

    if len(event.digest) > 1 and len(computed) > 1:
        event_hash = event.digest[1:] if event.digest[0].isalpha() else event.digest
        computed_hash = computed[1:] if computed[0].isalpha() else computed

        if event_hash != computed_hash:
            raise KELChainInvalidError(
                f"Event at seq {event.sequence} has invalid SAID: "
                f"digest {event.digest[:20]}... != computed {computed[:20]}..."
            )


def _validate_inception_signature(event: KELEvent, use_canonical: bool = False) -> None:
    """Validate that an inception event is self-signed."""
    if not event.signatures:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signatures"
        )

    if not event.signing_keys:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signing keys"
        )

    signing_input = _compute_signing_input(event, use_canonical=use_canonical)
    verified = False

    for sig in event.signatures:
        for key in event.signing_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has invalid self-signature"
        )


def _validate_event_signature(
    event: KELEvent,
    prior_keys: List[bytes],
    use_canonical: bool = False
) -> None:
    """Validate that an event is signed by keys from the prior event."""
    if not event.signatures:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has no signatures"
        )

    if not prior_keys:
        raise KELChainInvalidError(
            f"No prior keys available to validate event at seq {event.sequence}"
        )

    signing_input = _compute_signing_input(event, use_canonical=use_canonical)
    verified = False

    for sig in event.signatures:
        for key in prior_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has invalid signature "
            f"(not signed by prior keys)"
        )


def _compute_signing_input(event: KELEvent, use_canonical: bool = True) -> bytes:
    """Compute the signing input for an event.

    Args:
        event: The KELEvent to compute signing input for.
        use_canonical: If True (default), use KERI canonical serialization.
            If False, use JSON sorted-keys (legacy test fixtures only).

    Returns:
        The bytes that should have been signed.
    """
    raw_copy = dict(event.raw)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)
    raw_copy.pop("receipts", None)
    raw_copy.pop("rcts", None)

    if use_canonical:
        return canonical_serialize(raw_copy)
    else:
        canonical = json.dumps(raw_copy, sort_keys=True, separators=(",", ":"))
        return canonical.encode("utf-8")


def _verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if len(public_key) != 32:
        return False
    if len(signature) != 64:
        return False

    try:
        if _pysodium is None:
            return False
        _pysodium.crypto_sign_verify_detached(signature, message, public_key)
        return True
    except Exception:
        return False


def compute_said(data: Dict[str, Any], algorithm: str = "blake3-256") -> str:
    """Compute the SAID (Self-Addressing IDentifier) for an event.

    SAID is computed by hashing the serialized event with the 'd' field
    set to a placeholder, then base64url encoding the hash.
    """
    data_copy = dict(data)
    placeholder = "E" + "_" * 43
    data_copy["d"] = placeholder

    canonical = json.dumps(data_copy, sort_keys=True, separators=(",", ":"))

    if algorithm == "blake3-256":
        if _blake3 is not None:
            digest = _blake3.blake3(canonical.encode("utf-8")).digest()
        else:
            digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    else:
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()

    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return "E" + encoded


def compute_kel_event_said(event: Dict[str, Any], require_blake3: bool = False) -> str:
    """Compute SAID for a KEL event using KERI canonical field ordering."""
    return compute_said_canonical(event, require_blake3=require_blake3, said_field="d")


def _cesr_encode(raw: bytes, code: str = "E") -> str:
    """Encode raw bytes in CESR format with derivation code."""
    ps = (3 - (len(raw) % 3)) % 3
    prepadded = bytes([0] * ps) + raw
    b64 = base64.urlsafe_b64encode(prepadded).decode("ascii")
    trimmed = b64[ps:].rstrip("=")
    return code + trimmed


def compute_said_canonical(
    event: Dict[str, Any],
    require_blake3: bool = False,
    said_field: str = "d"
) -> str:
    """Compute SAID using KERI canonical serialization.

    Steps:
    1. Create most compact form with placeholder
    2. Hash with Blake3-256 (or SHA256 in test mode)
    3. Encode with CESR derivation code
    """
    canonical_bytes = most_compact_form(event, said_field=said_field)

    if _blake3 is not None:
        digest = _blake3.blake3(canonical_bytes).digest()
    elif require_blake3:
        raise ImportError(
            "blake3 is required for production SAID computation. "
            "Install with: pip install blake3"
        )
    else:
        digest = hashlib.sha256(canonical_bytes).digest()

    return _cesr_encode(digest, code="E")


def validate_event_said_canonical(
    event: Dict[str, Any],
    require_blake3: bool = False,
    said_field: str = "d"
) -> None:
    """Validate that event's SAID field matches computed SAID.

    Raises:
        KELChainInvalidError: If SAID doesn't match.
    """
    if said_field not in event:
        return

    expected_said = event[said_field]
    if not expected_said or expected_said.startswith("#"):
        return

    computed_said = compute_said_canonical(
        event,
        require_blake3=require_blake3,
        said_field=said_field
    )

    if expected_said != computed_said:
        raise KELChainInvalidError(
            f"SAID mismatch: event has {expected_said[:20]}... "
            f"but computed {computed_said[:20]}..."
        )


def validate_witness_receipts(
    event: KELEvent,
    signing_input: bytes,
    min_threshold: int = 0
) -> List[str]:
    """Validate witness receipt signatures against an event.

    Per VVP §7.3, witness receipts must be cryptographically validated.

    Threshold determination (per KERI spec):
    - Use event's 'bt' (witness threshold) if present and non-zero
    - Otherwise, use provided min_threshold if non-zero
    - Otherwise, default to majority: ceil(len(witnesses) / 2)

    Args:
        event: The KELEvent with witness receipts to validate.
        signing_input: Canonical bytes that were signed by witnesses.
        min_threshold: Minimum valid signatures required.

    Returns:
        List of witness AIDs whose signatures validated successfully.

    Raises:
        KELChainInvalidError: If insufficient valid witness signatures.
    """
    if not event.witness_receipts:
        if min_threshold > 0:
            raise KELChainInvalidError(
                f"No witness receipts but threshold requires {min_threshold}"
            )
        if event.toad > 0:
            raise KELChainInvalidError(
                f"No witness receipts but event toad requires {event.toad}"
            )
        return []

    if min_threshold > 0:
        threshold = min_threshold
    elif event.toad > 0:
        threshold = event.toad
    elif event.witnesses:
        threshold = math.ceil(len(event.witnesses) / 2)
    else:
        threshold = 0

    valid_witness_aids = set(event.witnesses)
    validated_aids: List[str] = []
    errors = []

    for receipt in event.witness_receipts:
        witness_aid = receipt.witness_aid
        signature = receipt.signature

        if not witness_aid and receipt.index is not None:
            if event.witnesses and receipt.index < len(event.witnesses):
                witness_aid = event.witnesses[receipt.index]
            else:
                errors.append(f"Witness index {receipt.index} out of range")
                continue

        if not witness_aid:
            errors.append("Receipt has no witness AID and no valid index")
            continue

        if valid_witness_aids and witness_aid not in valid_witness_aids:
            errors.append(f"Witness {witness_aid[:16]}... not in event's witness list")
            continue

        try:
            public_key = _decode_keri_key(witness_aid)
        except ResolutionFailedError as e:
            errors.append(f"Cannot decode witness AID {witness_aid[:16]}...: {e}")
            continue

        if _verify_signature(signing_input, signature, public_key):
            validated_aids.append(witness_aid)
        else:
            errors.append(f"Invalid signature from witness {witness_aid[:16]}...")

    if len(validated_aids) < threshold:
        error_summary = "; ".join(errors[:3])
        if len(errors) > 3:
            error_summary += f" (and {len(errors) - 3} more)"
        raise KELChainInvalidError(
            f"Insufficient valid witness signatures: {len(validated_aids)} < threshold {threshold}. "
            f"Errors: {error_summary if errors else 'none'}"
        )

    return validated_aids


def compute_signing_input_canonical(event: Dict[str, Any]) -> bytes:
    """Compute canonical signing input for an event."""
    event_copy = dict(event)
    event_copy.pop("signatures", None)
    event_copy.pop("-", None)
    event_copy.pop("receipts", None)
    event_copy.pop("rcts", None)

    return canonical_serialize(event_copy)
