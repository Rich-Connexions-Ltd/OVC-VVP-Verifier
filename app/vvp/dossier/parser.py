# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Dossier parsing — multi-format detector (JSON array, Provenant wrapper, CESR stream)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import List

from app.vvp.acdc import ACDC, parse_acdc
from app.vvp.exceptions import DossierParseError

logger = logging.getLogger(__name__)


def _is_keri_event(obj: dict) -> bool:
    """Return True iff *obj* is positively identified as a KERI protocol event.

    Uses **positive markers only**.  Objects that are not positively
    identified as KERI are treated as potential ACDCs and attempted via
    :func:`parse_acdc` (which will fail with a validation error if the
    object is malformed, preserving normal error-surfacing behaviour).

    Discriminators (any one sufficient):

    1. ``"t"`` key present — KERI events always carry a message-type field;
       ACDC credentials never use ``"t"`` (normative per KERI spec).
    2. ``"v"`` starts with ``"KERI10"`` — KERI versioned messages use
       ``KERI10`` prefix; ACDC streams use ``ACDC10``.
    """
    if "t" in obj:
        return True
    if isinstance(obj.get("v"), str) and obj["v"].startswith("KERI10"):
        return True
    return False


@dataclass
class DossierParseResult:
    """Result of parsing a dossier CESR stream.

    Attributes
    ----------
    acdcs : list[ACDC]
        Parsed ACDC credential objects.
    tel_events : list[dict]
        KERI Transaction Event Log events found in the stream.
        Retained for future inline revocation evaluation; not consumed
        by the current verification pipeline.
    """
    acdcs: List[ACDC]
    tel_events: List[dict] = field(default_factory=list)


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


def parse_dossier(raw: bytes) -> DossierParseResult:
    """Parse raw dossier bytes into a structured parse result.

    Format detection strategy:

    1. **JSON array** — starts with ``[``.  Each element is parsed as
       an ACDC dict.
    2. **JSON object** — starts with ``{``.  Checked for:
       a. Provenant wrapper (has ``"credentials"`` key).
       b. Bare single ACDC.
    3. **CESR / mixed stream** — bracket-counting extraction of embedded
       JSON objects.  Objects positively identified as KERI/TEL events
       (via :func:`_is_keri_event`) are separated into ``tel_events``
       and retained for future inline revocation evaluation rather than
       being passed to :func:`parse_acdc`.

    Parameters
    ----------
    raw : bytes
        The raw dossier payload.

    Returns
    -------
    DossierParseResult
        Parsed ACDC credentials and retained KERI/TEL events.

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
                return DossierParseResult(acdcs=acdcs, tel_events=[])

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
                    return DossierParseResult(acdcs=acdcs, tel_events=[])
                # Wrapper present but no valid creds — fall through.

            # 2b. Bare single ACDC (has "d", "i", "s", "a" fields).
            if all(k in data for k in ("d", "i", "s", "a")):
                try:
                    acdc = parse_acdc(data)
                    logger.debug("Parsed single ACDC dossier: %s", acdc.said)
                    return DossierParseResult(acdcs=[acdc], tel_events=[])
                except ValueError as exc:
                    logger.debug("Single ACDC parse failed: %s", exc)

    # ------------------------------------------------------------------
    # Strategy 3: CESR / mixed stream — bracket-counting extraction
    # ------------------------------------------------------------------
    json_objects = _extract_json_objects(stripped)
    tel_events: List[dict] = []
    if json_objects:
        for obj in json_objects:
            if not all(k in obj for k in ("d", "i", "s")):
                logger.debug("Skipping non-credential object (missing d/i/s)")
                continue
            if _is_keri_event(obj):
                tel_events.append(obj)
                continue
            try:
                acdcs.append(parse_acdc(obj))
            except ValueError as exc:
                logger.debug("ACDC parse failed: %s", exc)

    if tel_events:
        logger.info(
            "Dossier contains %d inline TEL events (retained)", len(tel_events)
        )
    if not acdcs:
        raise DossierParseError(
            "No valid ACDC credentials found in dossier payload"
        )
    logger.debug(
        "Parsed %d ACDCs from CESR/mixed stream dossier", len(acdcs)
    )
    return DossierParseResult(acdcs=acdcs, tel_events=tel_events)
