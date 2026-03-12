# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Transaction Event Log (TEL) client with inline parsing and witness queries.

Provides revocation-status checking for ACDC credentials by querying
the KERI Transaction Event Log infrastructure.  Supports three data
sources in priority order:

1. **Inline / dossier TEL** — TEL events embedded directly in the
   dossier payload alongside the ACDC credentials.
2. **Witness queries** — HTTP queries to configured KERI witness nodes.
3. **Fallback** — combined strategy trying dossier first, then witnesses.

The inline parsing logic (Phase 9.4 of the verification pipeline)
handles multiple formats: JSON arrays of event dicts, Provenant-style
wrappers with a ``"details"`` key, and CESR/JSON-interleaved streams
where bracket counting is used to extract embedded JSON objects.

TEL event types recognized:

- ``"iss"`` — Issuance (credential is active).
- ``"bis"`` — Backerless issuance (credential is active, backer-independent registry).
- ``"rev"`` — Revocation (credential is permanently revoked).
- ``"brv"`` — Backerless revocation (same effect as ``"rev"``).

Chain checking aggregates per-credential results: if ANY credential in
the chain is revoked, the entire chain is considered revoked.

References
----------
- KERI TEL specification (KID0011)
- VVP Verifier Specification §9 — Revocation checking
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.config import TEL_CLIENT_TIMEOUT_SECONDS, WITNESS_URLS

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialStatus",
    "TELEvent",
    "RevocationResult",
    "ChainRevocationResult",
    "check_revocation",
    "parse_dossier_tel",
    "check_revocation_with_fallback",
    "check_chain_revocation",
    "extract_witness_base_url",
]


# ======================================================================
# Data structures
# ======================================================================


class CredentialStatus(str, Enum):
    """Revocation status of a credential."""

    ACTIVE = "active"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class TELEvent:
    """A single Transaction Event Log event.

    Attributes
    ----------
    type : str
        Event type code: ``"iss"`` (issuance), ``"rev"`` (revocation),
        or ``"brv"`` (backerless revocation).
    credential_said : str
        The SAID of the credential this event pertains to (``"i"`` field).
    registry_said : str
        The SAID of the credential registry (``"ri"`` field).
    sequence : int
        The event sequence number (``"s"`` field).
    datetime : str
        The event datetime string (``"dt"`` field), if present.
    digest : str
        The event digest / SAID (``"d"`` field), if present.
    """

    type: str
    credential_said: str
    registry_said: str
    sequence: int = 0
    datetime: str = ""
    digest: str = ""


@dataclass
class RevocationResult:
    """Result of a revocation check for a single credential.

    Attributes
    ----------
    status : CredentialStatus
        The determined status.
    credential_said : str
        The SAID of the credential that was checked.
    registry_said : str
        The registry SAID, if known.
    issuance_event : TELEvent or None
        The issuance event, if found.
    revocation_event : TELEvent or None
        The revocation event, if found (implies REVOKED status).
    error : str or None
        Human-readable error description, if status is ERROR.
    source : str
        Where the status was determined: ``"inline"``, ``"witness"``,
        ``"dossier"``, or ``"cache"``.
    """

    status: CredentialStatus
    credential_said: str
    registry_said: str = ""
    issuance_event: Optional[TELEvent] = None
    revocation_event: Optional[TELEvent] = None
    error: Optional[str] = None
    source: str = "unknown"


@dataclass
class ChainRevocationResult:
    """Aggregated revocation result for a credential chain.

    Attributes
    ----------
    chain_status : CredentialStatus
        REVOKED if any credential is revoked; ACTIVE only if all are
        active and check_complete is True.
    credential_results : list[RevocationResult]
        Per-credential results.
    revoked_credentials : list[str]
        SAIDs of revoked credentials (empty if none revoked).
    check_complete : bool
        ``True`` if every credential in the chain was successfully
        checked (no UNKNOWN or ERROR statuses).
    errors : list[str]
        Error messages from individual checks that failed.
    """

    chain_status: CredentialStatus = CredentialStatus.UNKNOWN
    credential_results: List[RevocationResult] = field(default_factory=list)
    revoked_credentials: List[str] = field(default_factory=list)
    check_complete: bool = False
    errors: List[str] = field(default_factory=list)


# ======================================================================
# Inline TEL event parsing
# ======================================================================

# Recognized TEL event type codes.
_TEL_EVENT_TYPES = frozenset({"iss", "rev", "brv", "bis"})


def _parse_event_dict(obj: dict) -> Optional[TELEvent]:
    """Parse a single dict as a TEL event.

    The dict must contain at least a ``"t"`` field with a recognized
    event type code.  Missing optional fields are defaulted.

    Parameters
    ----------
    obj : dict
        A candidate TEL event dict.

    Returns
    -------
    TELEvent or None
        The parsed event, or ``None`` if *obj* does not represent a
        recognized TEL event.
    """
    event_type = obj.get("t", "")
    if event_type not in _TEL_EVENT_TYPES:
        return None

    return TELEvent(
        type=event_type,
        credential_said=obj.get("i", ""),
        registry_said=obj.get("ri", ""),
        sequence=_safe_int(obj.get("s", 0)),
        datetime=str(obj.get("dt", "")),
        digest=str(obj.get("d", "")),
    )


def _safe_int(value: Any) -> int:
    """Coerce *value* to ``int``, returning ``0`` on failure."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _extract_json_objects_from_text(text: str) -> List[dict]:
    """Extract complete JSON objects from a mixed text stream.

    Uses bracket counting to find ``{...}`` boundaries, identical to
    the strategy in :mod:`app.vvp.dossier`.

    Parameters
    ----------
    text : str
        The text to scan.

    Returns
    -------
    list[dict]
        Successfully parsed JSON objects.
    """
    objects: List[dict] = []
    i = 0
    length = len(text)

    while i < length:
        if text[i] != "{":
            i += 1
            continue

        depth = 0
        start = i
        in_string = False
        escape_next = False

        while i < length:
            ch = text[i]

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
                    candidate = text[start : i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            objects.append(obj)
                    except (json.JSONDecodeError, ValueError):
                        pass
                    i += 1
                    break

            i += 1
        else:
            break

    return objects


def _extract_tel_events(data: str) -> List[TELEvent]:
    """Extract TEL events from a response string.

    Handles multiple formats:

    - **JSON array** — each element is tried as a TEL event dict.
    - **JSON object with "details" key** — Provenant wrapper; the
      ``"details"`` value is parsed as a string or nested object.
    - **CESR/text stream** — bracket counting to extract embedded JSON
      objects, each tried as a TEL event.

    Parameters
    ----------
    data : str
        The raw response text from a witness query or dossier segment.

    Returns
    -------
    list[TELEvent]
        Extracted TEL events (may be empty if none found).
    """
    events: List[TELEvent] = []

    if not data or not data.strip():
        return events

    stripped = data.strip()

    # ------------------------------------------------------------------
    # Try JSON parse first.
    # ------------------------------------------------------------------
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    if parsed is not None:
        # JSON array of event dicts.
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    event = _parse_event_dict(item)
                    if event is not None:
                        events.append(event)
            if events:
                return events

        # JSON object — check for Provenant "details" wrapper.
        if isinstance(parsed, dict):
            details = parsed.get("details")
            if details is not None:
                # Details may be a string (JSON-encoded) or a dict/list.
                if isinstance(details, str):
                    # Recurse: parse the details string.
                    inner_events = _extract_tel_events(details)
                    if inner_events:
                        return inner_events
                elif isinstance(details, list):
                    for item in details:
                        if isinstance(item, dict):
                            event = _parse_event_dict(item)
                            if event is not None:
                                events.append(event)
                    if events:
                        return events
                elif isinstance(details, dict):
                    event = _parse_event_dict(details)
                    if event is not None:
                        return [event]

            # The object itself might be a single event.
            event = _parse_event_dict(parsed)
            if event is not None:
                return [event]

    # ------------------------------------------------------------------
    # Fallback: bracket-counting extraction from CESR/text stream.
    # ------------------------------------------------------------------
    json_objects = _extract_json_objects_from_text(stripped)
    for obj in json_objects:
        event = _parse_event_dict(obj)
        if event is not None:
            events.append(event)

    return events


def _determine_status(events: List[TELEvent]) -> Tuple[CredentialStatus, Optional[TELEvent], Optional[TELEvent]]:
    """Determine credential status from a list of TEL events.

    Parameters
    ----------
    events : list[TELEvent]
        TEL events for a single credential, in any order.

    Returns
    -------
    tuple[CredentialStatus, TELEvent | None, TELEvent | None]
        ``(status, issuance_event, revocation_event)``.  If any
        revocation event is present the status is REVOKED.  If only
        issuance events are present the status is ACTIVE.  Otherwise
        UNKNOWN.
    """
    issuance: Optional[TELEvent] = None
    revocation: Optional[TELEvent] = None

    for event in events:
        if event.type in ("iss", "bis"):
            # Keep the highest-sequence issuance event.
            # "bis" (backerless issuance) has the same active-credential semantics as "iss".
            if issuance is None or event.sequence > issuance.sequence:
                issuance = event
        elif event.type in ("rev", "brv"):
            # Keep the highest-sequence revocation event.
            if revocation is None or event.sequence > revocation.sequence:
                revocation = event

    if revocation is not None:
        return CredentialStatus.REVOKED, issuance, revocation
    if issuance is not None:
        return CredentialStatus.ACTIVE, issuance, None

    return CredentialStatus.UNKNOWN, None, None


# ======================================================================
# Witness URL helpers
# ======================================================================


def extract_witness_base_url(oobi_url: str) -> str:
    """Extract the base URL (scheme://host:port) from an OOBI URL.

    Parameters
    ----------
    oobi_url : str
        A full OOBI URL, e.g.
        ``"http://witness.example.com:5642/oobi/EaK..."``

    Returns
    -------
    str
        The base URL, e.g. ``"http://witness.example.com:5642"``.
    """
    parsed = urlparse(oobi_url)
    if parsed.port:
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    return f"{parsed.scheme}://{parsed.hostname}"


def _build_witness_urls() -> List[str]:
    """Return the list of witness base URLs from configuration.

    Normalizes OOBI-style URLs to base URLs.
    """
    urls: List[str] = []
    for url in WITNESS_URLS:
        if not url:
            continue
        base = extract_witness_base_url(url)
        if base not in urls:
            urls.append(base)
    return urls


# ======================================================================
# Core functions — single credential
# ======================================================================


async def check_revocation(
    credential_said: str,
    registry_said: Optional[str] = None,
    oobi_url: Optional[str] = None,
) -> RevocationResult:
    """Check the revocation status of a credential via witness queries.

    Queries each configured witness URL (plus an optional OOBI-derived
    URL) with two endpoint patterns:

    1. ``GET /query?typ=tel&vcid={credential_said}``
    2. ``GET /tels/{registry_said}`` (if registry_said is provided)

    The first successful response that yields TEL events determines the
    status.

    Parameters
    ----------
    credential_said : str
        The SAID of the credential to check.
    registry_said : str or None
        The registry SAID (improves lookup specificity).
    oobi_url : str or None
        An additional witness URL to try (extracted from the dossier
        OOBI).

    Returns
    -------
    RevocationResult
        The revocation status.  Returns UNKNOWN if all witnesses fail.
    """
    witness_urls = _build_witness_urls()

    # Add OOBI-derived witness if provided.
    if oobi_url:
        oobi_base = extract_witness_base_url(oobi_url)
        if oobi_base not in witness_urls:
            witness_urls.append(oobi_base)

    if not witness_urls:
        logger.warning(
            "No witness URLs configured; cannot check revocation for %s",
            credential_said,
        )
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said or "",
            error="No witness URLs configured",
            source="witness",
        )

    last_error: Optional[str] = None

    for base_url in witness_urls:
        # Build query endpoints to try.
        endpoints: List[str] = [
            f"{base_url}/query?typ=tel&vcid={credential_said}",
        ]
        if registry_said:
            endpoints.append(f"{base_url}/tels/{registry_said}")

        for endpoint in endpoints:
            try:
                result = await _query_witness_endpoint(
                    endpoint, credential_said, registry_said or ""
                )
                if result is not None:
                    return result
            except Exception as exc:
                last_error = f"{endpoint}: {exc}"
                logger.debug(
                    "Witness query failed for %s at %s: %s",
                    credential_said,
                    endpoint,
                    exc,
                )

    return RevocationResult(
        status=CredentialStatus.UNKNOWN,
        credential_said=credential_said,
        registry_said=registry_said or "",
        error=last_error or "All witness queries returned no TEL events",
        source="witness",
    )


async def _query_witness_endpoint(
    endpoint: str,
    credential_said: str,
    registry_said: str,
) -> Optional[RevocationResult]:
    """Query a single witness endpoint and parse the response.

    Parameters
    ----------
    endpoint : str
        The full URL to query.
    credential_said : str
        The credential SAID (for result construction).
    registry_said : str
        The registry SAID (for result construction).

    Returns
    -------
    RevocationResult or None
        A result if TEL events were found and parsed; ``None`` if the
        endpoint returned no usable data.

    Raises
    ------
    Exception
        On network errors or timeouts (propagated to caller).
    """
    logger.debug("Querying witness endpoint: %s", endpoint)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(TEL_CLIENT_TIMEOUT_SECONDS),
    ) as client:
        response = await client.get(endpoint)

    if response.status_code < 200 or response.status_code >= 300:
        logger.debug(
            "Witness endpoint %s returned HTTP %d",
            endpoint,
            response.status_code,
        )
        return None

    text = response.text
    if not text or not text.strip():
        return None

    events = _extract_tel_events(text)
    if not events:
        return None

    # Filter events for the target credential.
    relevant = [
        e for e in events
        if not e.credential_said or e.credential_said == credential_said
    ]
    if not relevant:
        # Events present but for a different credential.
        relevant = events  # Use all events as best-effort.

    status, iss_event, rev_event = _determine_status(relevant)

    return RevocationResult(
        status=status,
        credential_said=credential_said,
        registry_said=registry_said,
        issuance_event=iss_event,
        revocation_event=rev_event,
        source="witness",
    )


# ======================================================================
# Core functions — dossier TEL parsing
# ======================================================================


def parse_dossier_tel(
    dossier_data: bytes,
    credential_said: str,
    registry_said: Optional[str] = None,
) -> RevocationResult:
    """Parse TEL events from a dossier byte stream.

    Attempts to extract TEL events from the raw dossier payload that
    match the given credential SAID.  This provides an "inline"
    revocation check without requiring a witness query.

    Parameters
    ----------
    dossier_data : bytes
        The raw dossier payload.
    credential_said : str
        The SAID of the credential to check.
    registry_said : str or None
        The registry SAID (for result filtering).

    Returns
    -------
    RevocationResult
        The revocation status from inline TEL data.  Returns UNKNOWN
        if no relevant TEL events are found in the dossier.
    """
    if not dossier_data:
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said or "",
            error="Empty dossier data",
            source="dossier",
        )

    try:
        text = dossier_data.decode("utf-8")
    except UnicodeDecodeError:
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said or "",
            error="Dossier data is not valid UTF-8",
            source="dossier",
        )

    events = _extract_tel_events(text)
    if not events:
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said or "",
            error="No TEL events found in dossier",
            source="dossier",
        )

    # Filter events for the target credential.
    relevant = [
        e for e in events
        if e.credential_said == credential_said
    ]

    # If registry_said is provided, further filter.
    if registry_said and relevant:
        registry_filtered = [
            e for e in relevant
            if not e.registry_said or e.registry_said == registry_said
        ]
        if registry_filtered:
            relevant = registry_filtered

    if not relevant:
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said or "",
            error=f"No TEL events matching credential {credential_said}",
            source="dossier",
        )

    status, iss_event, rev_event = _determine_status(relevant)

    return RevocationResult(
        status=status,
        credential_said=credential_said,
        registry_said=registry_said or "",
        issuance_event=iss_event,
        revocation_event=rev_event,
        source="dossier",
    )


# ======================================================================
# Core functions — fallback strategy
# ======================================================================


async def check_revocation_with_fallback(
    credential_said: str,
    registry_said: Optional[str] = None,
    dossier_data: Optional[bytes] = None,
    oobi_url: Optional[str] = None,
) -> RevocationResult:
    """Check revocation status using dossier-first, witness-fallback strategy.

    The strategy is:

    1. If *dossier_data* is provided, check inline TEL first.
       - If REVOKED, return immediately (revocation is permanent and
         authoritative).
       - If ACTIVE, continue to witness check for freshest status.
    2. Query witnesses for live status.
    3. Return the best result (prefer witness over dossier for ACTIVE).

    Parameters
    ----------
    credential_said : str
        The SAID of the credential to check.
    registry_said : str or None
        The registry SAID.
    dossier_data : bytes or None
        Raw dossier payload for inline TEL extraction.
    oobi_url : str or None
        Additional witness URL.

    Returns
    -------
    RevocationResult
        The revocation status from the best available source.
    """
    dossier_result: Optional[RevocationResult] = None

    # Step 1: Try dossier TEL.
    if dossier_data:
        dossier_result = parse_dossier_tel(
            dossier_data, credential_said, registry_said
        )
        # Revocation is permanent — no need to query witnesses.
        if dossier_result.status == CredentialStatus.REVOKED:
            logger.debug(
                "Credential %s REVOKED per dossier TEL; skipping witness query",
                credential_said,
            )
            return dossier_result

    # Step 2: Query witnesses for live status.
    witness_result = await check_revocation(
        credential_said, registry_said, oobi_url
    )

    # Step 3: Return best result.
    # Prefer witness result if it gave a definitive answer.
    if witness_result.status in (
        CredentialStatus.ACTIVE,
        CredentialStatus.REVOKED,
    ):
        return witness_result

    # Witness returned UNKNOWN/ERROR — fall back to dossier result if available.
    if dossier_result and dossier_result.status != CredentialStatus.UNKNOWN:
        logger.debug(
            "Witness query inconclusive for %s; using dossier result (%s)",
            credential_said,
            dossier_result.status.value,
        )
        return dossier_result

    # Both inconclusive — return the witness result (with its error).
    return witness_result


# ======================================================================
# Core functions — chain revocation
# ======================================================================


async def check_chain_revocation(
    chain_info: List[Tuple[str, str]],
    dossier_data: Optional[bytes] = None,
    oobi_url: Optional[str] = None,
) -> ChainRevocationResult:
    """Check revocation status for an entire credential chain.

    Checks all credentials concurrently using :func:`asyncio.gather`.
    The chain is considered REVOKED if ANY credential is revoked, and
    ACTIVE only if ALL credentials are active and the check is complete.

    Parameters
    ----------
    chain_info : list[tuple[str, str]]
        A list of ``(credential_said, registry_said)`` tuples
        representing the credentials in the chain.
    dossier_data : bytes or None
        Raw dossier payload for inline TEL extraction.
    oobi_url : str or None
        Additional witness URL.

    Returns
    -------
    ChainRevocationResult
        Aggregated chain status.
    """
    if not chain_info:
        return ChainRevocationResult(
            chain_status=CredentialStatus.UNKNOWN,
            check_complete=False,
            errors=["Empty credential chain"],
        )

    # Check all credentials concurrently.
    tasks = [
        check_revocation_with_fallback(
            credential_said=cred_said,
            registry_said=reg_said or None,
            dossier_data=dossier_data,
            oobi_url=oobi_url,
        )
        for cred_said, reg_said in chain_info
    ]

    results: List[RevocationResult] = await asyncio.gather(*tasks)

    # Aggregate results.
    revoked: List[str] = []
    errors: List[str] = []
    all_definitive = True

    for result in results:
        if result.status == CredentialStatus.REVOKED:
            revoked.append(result.credential_said)
        elif result.status in (CredentialStatus.UNKNOWN, CredentialStatus.ERROR):
            all_definitive = False
            if result.error:
                errors.append(
                    f"{result.credential_said}: {result.error}"
                )

    # Determine chain status.
    if revoked:
        chain_status = CredentialStatus.REVOKED
    elif all_definitive:
        chain_status = CredentialStatus.ACTIVE
    else:
        chain_status = CredentialStatus.UNKNOWN

    check_complete = all_definitive and not revoked

    return ChainRevocationResult(
        chain_status=chain_status,
        credential_results=results,
        revoked_credentials=revoked,
        check_complete=check_complete and len(revoked) == 0,
        errors=errors,
    )
