# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/oobi.py
# Source commit: 398d40d (2026-03-14)

"""OOBI (Out-of-Band Introduction) dereferencer.

OOBIs provide a way to bootstrap KERI communication by resolving a URL
to obtain the Key Event Log (KEL) for an AID.

Per spec §5A Step 4: "Resolve issuer key state at reference time T"

Uses the OVC verifier's existing safe_get() fetch layer for SSRF protection.
"""

import asyncio
import json
from dataclasses import dataclass
from typing import List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from .exceptions import OOBIContentInvalidError, ResolutionFailedError

if TYPE_CHECKING:
    from .kel_resolver import KeyState

# Accepted content types for OOBI responses
CESR_CONTENT_TYPE = "application/json+cesr"
JSON_CONTENT_TYPE = "application/json"


@dataclass
class OOBIResult:
    """Result of OOBI dereferencing.

    Attributes:
        aid: The AID (Autonomic Identifier) resolved.
        kel_data: Raw KEL data (CESR or JSON encoded).
        witnesses: List of witness URLs/AIDs discovered.
        content_type: Content-Type from OOBI response.
        error: Error message if resolution partially failed.
    """
    aid: str
    kel_data: bytes
    witnesses: List[str]
    content_type: str = JSON_CONTENT_TYPE
    error: Optional[str] = None


async def dereference_oobi(
    oobi_url: str,
    timeout: float = 5.0,
) -> OOBIResult:
    """Dereference an OOBI URL to fetch KEL data.

    Uses the OVC verifier's safe_get() for SSRF-safe HTTP fetching.
    No redirects followed.

    Args:
        oobi_url: The OOBI URL to dereference.
        timeout: Request timeout in seconds.

    Returns:
        OOBIResult containing the KEL data and metadata.

    Raises:
        ResolutionFailedError: If network/fetch fails (recoverable).
        OOBIContentInvalidError: If content type/format invalid (non-recoverable).
    """
    from app.vvp.fetch import safe_get, FetchError, validate_url

    # Validate URL (SSRF checks)
    try:
        validate_url(oobi_url)
    except FetchError as e:
        raise ResolutionFailedError(f"OOBI URL validation failed: {e}")

    # Extract AID from URL if present
    aid = _extract_aid_from_url(oobi_url)

    try:
        kel_data = await safe_get(oobi_url, timeout=timeout)
    except FetchError as e:
        error_msg = str(e)
        if "timed out" in error_msg.lower():
            raise ResolutionFailedError(f"OOBI fetch timeout after {timeout}s")
        raise ResolutionFailedError(f"OOBI fetch failed: {e}")

    if not kel_data:
        raise ResolutionFailedError("OOBI response is empty")

    # Extract witnesses from response if available
    witnesses = _extract_witnesses(kel_data, aid)

    # Detect content type from data
    from .cesr import is_cesr_stream
    if is_cesr_stream(kel_data):
        detected_content_type = CESR_CONTENT_TYPE
    else:
        detected_content_type = JSON_CONTENT_TYPE

    return OOBIResult(
        aid=aid,
        kel_data=kel_data,
        witnesses=witnesses,
        content_type=detected_content_type
    )


def _extract_aid_from_url(url: str) -> str:
    """Extract AID from OOBI URL path.

    Common formats:
    - /oobi/{aid}
    - /oobi/{aid}/witness/{witness}
    - /oobi/{aid}/controller
    """
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]

    for i, part in enumerate(path_parts):
        if part.lower() == "oobi" and i + 1 < len(path_parts):
            potential_aid = path_parts[i + 1]
            if potential_aid and potential_aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                return potential_aid

    if path_parts:
        last = path_parts[-1]
        if last and last[0] in "BDEFGHJKLMNOPQRSTUVWXYZ" and len(last) > 40:
            return last

    return ""


def _extract_witnesses(kel_data: bytes, aid: str) -> List[str]:
    """Extract witness AIDs from KEL data."""
    witnesses: List[str] = []

    try:
        data = json.loads(kel_data.decode("utf-8"))

        if isinstance(data, dict):
            witnesses.extend(data.get("b", []))
        elif isinstance(data, list):
            for event in reversed(data):
                if isinstance(event, dict):
                    event_type = event.get("t", "")
                    if event_type in ("icp", "rot", "dip", "drt"):
                        witnesses.extend(event.get("b", []))
                        break
    except Exception:
        pass

    return witnesses


async def fetch_kel_from_witnesses(
    aid: str,
    witnesses: List[str],
    timeout: float = 5.0,
    min_responses: int = 1
) -> OOBIResult:
    """Fetch KEL from multiple witnesses for consensus.

    Args:
        aid: The AID to fetch KEL for.
        witnesses: List of witness URLs.
        timeout: Per-request timeout.
        min_responses: Minimum witnesses that must respond.

    Returns:
        OOBIResult with the most consistent KEL.

    Raises:
        ResolutionFailedError: If insufficient witnesses respond.
    """
    if not witnesses:
        raise ResolutionFailedError("No witnesses provided for KEL fetch")

    results = []
    errors = []

    async def fetch_one(witness_url: str) -> Optional[OOBIResult]:
        try:
            return await dereference_oobi(witness_url, timeout=timeout)
        except Exception as e:
            errors.append(f"{witness_url}: {e}")
            return None

    tasks = [fetch_one(w) for w in witnesses]
    responses = await asyncio.gather(*tasks)

    results = [r for r in responses if r is not None]

    if len(results) < min_responses:
        raise ResolutionFailedError(
            f"Insufficient witness responses: got {len(results)}, "
            f"need {min_responses}. Errors: {errors[:3]}"
        )

    return results[0]


async def validate_oobi_is_kel(
    oobi_url: str,
    timeout: float = 5.0
) -> "KeyState":
    """Fetch OOBI and validate it contains a valid KEL.

    Per VVP §4.2, the kid OOBI must resolve to a valid Key Event Log.

    Args:
        oobi_url: OOBI URL from kid field.
        timeout: Request timeout in seconds.

    Returns:
        Resolved KeyState from the KEL.

    Raises:
        OOBIContentInvalidError: If content is not a valid KEL.
        ResolutionFailedError: If network/fetch fails.
    """
    from .kel_parser import parse_kel_stream, validate_kel_chain, EventType
    from .kel_resolver import KeyState

    result = await dereference_oobi(oobi_url, timeout=timeout)

    if not result.kel_data:
        raise OOBIContentInvalidError("OOBI response contains no KEL data")

    try:
        events = parse_kel_stream(
            result.kel_data,
            content_type=result.content_type,
            allow_json_only=True
        )
    except Exception as e:
        raise OOBIContentInvalidError(f"Failed to parse KEL from OOBI: {e}")

    if not events:
        raise OOBIContentInvalidError("OOBI KEL contains no events")

    first_event = events[0]
    if first_event.event_type not in {EventType.ICP, EventType.DIP}:
        raise OOBIContentInvalidError(
            f"OOBI KEL must start with inception event, found: {first_event.event_type.value}"
        )

    try:
        validate_kel_chain(
            events,
            validate_saids=False,
            use_canonical=True,
            validate_witnesses=False
        )
    except Exception as e:
        raise OOBIContentInvalidError(f"OOBI KEL chain validation failed: {e}")

    terminal_event = None
    for event in reversed(events):
        if event.is_establishment:
            terminal_event = event
            break

    if terminal_event is None:
        raise OOBIContentInvalidError("No establishment event found in OOBI KEL")

    key_state = KeyState(
        aid=result.aid or first_event.digest,
        signing_keys=terminal_event.signing_keys,
        sequence=terminal_event.sequence,
        establishment_digest=terminal_event.digest,
        valid_from=terminal_event.timestamp,
        witnesses=terminal_event.witnesses,
        toad=terminal_event.toad
    )

    return key_state
