# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""SIP request and response dataclasses.

Models the essential structure of SIP messages as defined in RFC 3261.
These dataclasses represent parsed SIP messages in memory and support
serialization back to SIP wire format (CRLF-delimited text over UDP).

Usage:
    >>> req = SIPRequest(method="INVITE", uri="sip:alice@example.com",
    ...                  headers={"Call-ID": "abc123", "From": "<sip:bob@x.com>"})
    >>> req.call_id
    'abc123'
    >>> data = req.to_bytes()  # Ready to send over UDP

Wire format (RFC 3261 §7):
    - Request:  METHOD Request-URI SIP/2.0 CRLF headers CRLF CRLF body
    - Response: SIP/2.0 Status-Code Reason-Phrase CRLF headers CRLF CRLF body
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# SIP line terminator per RFC 3261 §7.
CRLF = "\r\n"


# =============================================================================
# SIP Request
# =============================================================================


@dataclass
class SIPRequest:
    """A parsed SIP request message.

    Attributes:
        method: SIP method (INVITE, ACK, BYE, CANCEL, OPTIONS, etc.).
        uri: Request-URI (e.g. "sip:alice@example.com").
        version: SIP version string.  Always "SIP/2.0" in practice.
        headers: Header name -> value mapping.  Header names are stored in
            their canonical (Title-Case) form as received on the wire.
            For headers that may appear multiple times (e.g. Via), only the
            top-most value is retained by the parser; the builder copies
            whichever value it finds here.
        body: Message body (SDP, etc.).  Empty string when absent.
        source_addr: (host, port) tuple of the remote peer that sent this
            request.  Populated by the transport layer; defaults to ("", 0)
            when constructed manually.
    """

    method: str
    uri: str
    version: str = "SIP/2.0"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    source_addr: tuple[str, int] = ("", 0)

    # -----------------------------------------------------------------
    # Convenience header accessors
    # -----------------------------------------------------------------

    @property
    def call_id(self) -> Optional[str]:
        """Return the Call-ID header value, or ``None`` if absent."""
        return self.headers.get("Call-ID")

    @property
    def from_header(self) -> Optional[str]:
        """Return the From header value, or ``None`` if absent."""
        return self.headers.get("From")

    @property
    def to_header(self) -> Optional[str]:
        """Return the To header value, or ``None`` if absent."""
        return self.headers.get("To")

    @property
    def via(self) -> Optional[str]:
        """Return the top-most Via header value, or ``None`` if absent."""
        return self.headers.get("Via")

    @property
    def contact(self) -> Optional[str]:
        """Return the Contact header value, or ``None`` if absent."""
        return self.headers.get("Contact")

    @property
    def cseq(self) -> Optional[str]:
        """Return the CSeq header value, or ``None`` if absent."""
        return self.headers.get("CSeq")

    # -----------------------------------------------------------------
    # Serialization
    # -----------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize this request to SIP wire format.

        Returns:
            UTF-8 encoded bytes ready to send over UDP/TCP.

        The wire format is::

            METHOD Request-URI SIP/2.0\\r\\n
            Header-Name: value\\r\\n
            ...\\r\\n
            \\r\\n
            body
        """
        # Request line
        lines: list[str] = [f"{self.method} {self.uri} {self.version}"]

        # Headers
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")

        # If there is a body, add Content-Length if not already present.
        if self.body and "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")

        # Blank line separates headers from body.
        message = CRLF.join(lines) + CRLF + CRLF + self.body
        return message.encode("utf-8")

    def __str__(self) -> str:
        return f"SIPRequest({self.method} {self.uri}, Call-ID={self.call_id})"


# =============================================================================
# SIP Response
# =============================================================================


@dataclass
class SIPResponse:
    """A parsed SIP response message.

    Attributes:
        status_code: Three-digit status code (e.g. 200, 302, 400).
        reason: Reason phrase (e.g. "OK", "Moved Temporarily").
        version: SIP version string.
        headers: Header name -> value mapping (same conventions as SIPRequest).
        body: Message body.  Empty string when absent.
    """

    status_code: int
    reason: str
    version: str = "SIP/2.0"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    # -----------------------------------------------------------------
    # Serialization
    # -----------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize this response to SIP wire format.

        Returns:
            UTF-8 encoded bytes ready to send over UDP/TCP.

        The wire format is::

            SIP/2.0 Status-Code Reason-Phrase\\r\\n
            Header-Name: value\\r\\n
            ...\\r\\n
            \\r\\n
            body
        """
        # Status line
        lines: list[str] = [f"{self.version} {self.status_code} {self.reason}"]

        # Headers
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")

        # Content-Length for non-empty bodies.
        if self.body and "Content-Length" not in self.headers:
            lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")

        # Blank line separates headers from body.
        message = CRLF.join(lines) + CRLF + CRLF + self.body
        return message.encode("utf-8")

    def __str__(self) -> str:
        return f"SIPResponse({self.status_code} {self.reason})"
