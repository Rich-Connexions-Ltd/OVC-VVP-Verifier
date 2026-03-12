# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""RFC 3261 SIP message parser.

Parses raw bytes received on a UDP socket into ``SIPRequest`` or
``SIPResponse`` dataclass instances.  Handles:

- Request-line / Status-line detection and parsing
- Header parsing with multi-line folding (RFC 3261 §7.3.1)
- Header/body separation at the blank-line boundary (CRLFCRLF)
- UTF-8 decoding with lenient error handling for display-names

Limitations (acceptable for VVP use-case):
- Compact header forms (single-letter abbreviations) are NOT expanded.
- Only the top-most value of multi-valued headers (e.g. Via) is retained;
  this is sufficient because the builder copies Via verbatim.
- No support for multipart MIME bodies.

Usage:
    >>> from app.sip.parser import parse_request, parse_response
    >>> req = parse_request(raw_bytes)
    >>> resp = parse_response(raw_bytes)
"""

from __future__ import annotations

from app.sip.models import SIPRequest, SIPResponse


class SIPParseError(Exception):
    """Raised when a SIP message cannot be parsed.

    Attributes:
        message: Human-readable description of the parse failure.
        raw_data: The original bytes that failed to parse (may be truncated).
    """

    def __init__(self, message: str, raw_data: bytes | None = None) -> None:
        super().__init__(message)
        self.raw_data = raw_data


# Maximum message size we will attempt to parse (64 KiB).
# SIP over UDP is bounded by MTU in practice, but we set a generous ceiling.
_MAX_MESSAGE_SIZE = 65536


# =============================================================================
# Public API
# =============================================================================


def parse_request(data: bytes) -> SIPRequest:
    """Parse raw bytes into a ``SIPRequest``.

    Args:
        data: Raw bytes received from a UDP socket.

    Returns:
        A populated ``SIPRequest`` instance.

    Raises:
        SIPParseError: If the data cannot be parsed as a valid SIP request.
    """
    if len(data) > _MAX_MESSAGE_SIZE:
        raise SIPParseError(
            f"Message exceeds maximum size ({len(data)} > {_MAX_MESSAGE_SIZE})",
            raw_data=data[:256],
        )

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception as exc:
        raise SIPParseError(f"UTF-8 decode failed: {exc}", raw_data=data[:256]) from exc

    # Split headers from body at the first blank line.
    head, body = _split_head_body(text)

    lines = head.split("\n")
    if not lines:
        raise SIPParseError("Empty message", raw_data=data[:256])

    # Parse the request line: METHOD SP Request-URI SP SIP-Version
    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        raise SIPParseError(
            f"Malformed request line: {request_line!r}", raw_data=data[:256]
        )

    method, uri, version = parts

    if not version.startswith("SIP/"):
        raise SIPParseError(
            f"Invalid SIP version in request line: {version!r}", raw_data=data[:256]
        )

    headers = _parse_headers(lines[1:])

    return SIPRequest(
        method=method,
        uri=uri,
        version=version,
        headers=headers,
        body=body,
    )


def parse_response(data: bytes) -> SIPResponse:
    """Parse raw bytes into a ``SIPResponse``.

    Args:
        data: Raw bytes received from a UDP socket.

    Returns:
        A populated ``SIPResponse`` instance.

    Raises:
        SIPParseError: If the data cannot be parsed as a valid SIP response.
    """
    if len(data) > _MAX_MESSAGE_SIZE:
        raise SIPParseError(
            f"Message exceeds maximum size ({len(data)} > {_MAX_MESSAGE_SIZE})",
            raw_data=data[:256],
        )

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception as exc:
        raise SIPParseError(f"UTF-8 decode failed: {exc}", raw_data=data[:256]) from exc

    head, body = _split_head_body(text)

    lines = head.split("\n")
    if not lines:
        raise SIPParseError("Empty message", raw_data=data[:256])

    # Parse the status line: SIP-Version SP Status-Code SP Reason-Phrase
    status_line = lines[0].strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise SIPParseError(
            f"Malformed status line: {status_line!r}", raw_data=data[:256]
        )

    version = parts[0]
    if not version.startswith("SIP/"):
        raise SIPParseError(
            f"Invalid SIP version in status line: {version!r}", raw_data=data[:256]
        )

    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise SIPParseError(
            f"Non-integer status code: {parts[1]!r}", raw_data=data[:256]
        ) from exc

    # Reason phrase may contain spaces; everything after the status code.
    reason = parts[2] if len(parts) == 3 else ""

    headers = _parse_headers(lines[1:])

    return SIPResponse(
        status_code=status_code,
        reason=reason,
        version=version,
        headers=headers,
        body=body,
    )


# =============================================================================
# Internal helpers
# =============================================================================


def _split_head_body(text: str) -> tuple[str, str]:
    """Split a SIP message into its header section and body.

    The boundary is the first occurrence of a blank line (CRLFCRLF).
    We also handle bare-LF line endings for robustness.
    """
    # Normalize line endings: CRLF -> LF (we rejoin with CRLF on serialization).
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")

    separator = "\n\n"
    idx = normalized.find(separator)
    if idx == -1:
        # No body — entire message is headers.
        return normalized, ""

    head = normalized[:idx]
    body = normalized[idx + len(separator):]
    return head, body


def _parse_headers(lines: list[str]) -> dict[str, str]:
    """Parse header lines into a name->value dictionary.

    Handles RFC 3261 multi-line header folding: continuation lines start
    with whitespace (SP or HTAB) and are appended to the previous header
    value separated by a single space.

    When the same header name appears multiple times, the LAST value wins.
    This is acceptable for VVP because we only care about single-valued
    headers (Call-ID, From, To, CSeq) and the top-most Via.
    """
    headers: dict[str, str] = {}
    current_name: str | None = None
    current_value: str = ""

    for raw_line in lines:
        line = raw_line.rstrip()

        if not line:
            # Blank line — end of headers.
            break

        # Continuation line (folded header): starts with SP or HTAB.
        if line[0] in (" ", "\t"):
            if current_name is not None:
                current_value += " " + line.strip()
            # Orphan continuation line (no preceding header) — skip silently.
            continue

        # Commit the previous header before starting a new one.
        if current_name is not None:
            headers[current_name] = current_value

        # Parse "Header-Name: value".
        colon_idx = line.find(":")
        if colon_idx == -1:
            # Malformed header line — skip silently for robustness.
            current_name = None
            current_value = ""
            continue

        current_name = line[:colon_idx].strip()
        current_value = line[colon_idx + 1:].strip()

    # Commit the last header.
    if current_name is not None:
        headers[current_name] = current_value

    return headers
