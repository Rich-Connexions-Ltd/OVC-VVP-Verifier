# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""AsyncIO UDP transport for SIP messages.

Provides ``SIPTransport``, an asyncio-based UDP server that:

1. Listens on a configurable host:port for inbound SIP messages.
2. Parses each datagram into a ``SIPRequest`` using the RFC 3261 parser.
3. Dispatches the request to an async handler callback.
4. Sends the handler's ``SIPResponse`` (if any) back to the sender.

Architecture:
    The transport layer is intentionally decoupled from verification logic.
    It only knows about bytes-in / bytes-out and delegates all SIP semantics
    to the handler callback.  This makes it straightforward to test the
    transport in isolation and to swap handlers for different deployment
    scenarios (e.g. verification vs. signing).

Thread safety:
    All operations run on a single asyncio event loop.  The handler callback
    is awaited (not run in a thread pool), so it must be async and should
    avoid blocking I/O.

Usage:
    >>> async def my_handler(request: SIPRequest, addr: tuple) -> Optional[SIPResponse]:
    ...     return build_error_response(request, 200, "OK")
    ...
    >>> transport = SIPTransport("0.0.0.0", 5071, my_handler)
    >>> await transport.start()
    >>> # ... transport is now receiving datagrams ...
    >>> await transport.stop()
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

from app.sip.models import SIPRequest, SIPResponse
from app.sip.parser import SIPParseError, parse_request

logger = logging.getLogger(__name__)

# Type alias for the handler callback.
# Receives a parsed SIPRequest and the sender's (host, port) address.
# Returns an optional SIPResponse to send back.  Returning None means
# no response is sent (e.g. for non-INVITE methods the handler ignores).
HandlerCallback = Callable[[SIPRequest, tuple[str, int]], Awaitable[Optional[SIPResponse]]]


class SIPTransport:
    """AsyncIO UDP server for SIP message exchange.

    This class manages the lifecycle of an asyncio ``DatagramProtocol``
    endpoint.  Inbound datagrams are parsed as SIP requests, dispatched
    to the handler callback, and responses are serialized back to the
    sender.

    Attributes:
        host: The local address to bind to (e.g. "0.0.0.0").
        port: The local UDP port to listen on.
        handler: Async callback invoked for each parsed SIP request.
    """

    def __init__(
        self,
        host: str,
        port: int,
        handler_callback: HandlerCallback,
    ) -> None:
        """Initialize the SIP transport.

        Args:
            host: Local bind address.
            port: Local bind port.
            handler_callback: Async function called for each inbound SIP
                request.  Signature:
                ``async def handler(request: SIPRequest, addr: tuple) -> Optional[SIPResponse]``
        """
        self.host = host
        self.port = port
        self.handler = handler_callback

        # Populated by start().
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[_SIPProtocol] = None
        self._running = False

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Create the UDP endpoint and begin listening.

        Raises:
            OSError: If the address/port is already in use.
            RuntimeError: If the transport is already running.
        """
        if self._running:
            raise RuntimeError(
                f"SIP transport already running on {self.host}:{self.port}"
            )

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SIPProtocol(self.handler),
            local_addr=(self.host, self.port),
        )

        self._transport = transport
        self._protocol = protocol
        self._running = True

        # Resolve the actual bound address (useful when port=0).
        actual_addr = transport.get_extra_info("sockname")
        logger.info(
            "SIP UDP transport listening on %s:%s", actual_addr[0], actual_addr[1]
        )

    async def stop(self) -> None:
        """Close the UDP endpoint and stop listening.

        Safe to call multiple times.  After calling ``stop()``, the
        transport can be restarted with a new call to ``start()``.
        """
        if self._transport is not None:
            self._transport.close()
            logger.info("SIP UDP transport stopped")

        self._transport = None
        self._protocol = None
        self._running = False

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Return True if the transport is actively listening."""
        return self._running

    @property
    def local_address(self) -> Optional[tuple[str, int]]:
        """Return the (host, port) the transport is bound to, or None.

        When the transport was started with port=0, this returns the
        OS-assigned ephemeral port — useful for tests.
        """
        if self._transport is not None:
            sockname = self._transport.get_extra_info("sockname")
            if sockname:
                return (sockname[0], sockname[1])
        return None

    # -----------------------------------------------------------------
    # Send (for outbound requests, e.g. in a B2BUA scenario)
    # -----------------------------------------------------------------

    async def send(self, response: SIPResponse, addr: tuple[str, int]) -> None:
        """Send a SIP response to a specific address.

        This is primarily useful for sending responses outside the normal
        request/response cycle (e.g. delayed responses, retransmissions).

        Args:
            response: The SIP response to send.
            addr: The (host, port) destination address.

        Raises:
            RuntimeError: If the transport is not running.
        """
        if self._transport is None:
            raise RuntimeError("SIP transport is not running")

        data = response.to_bytes()
        self._transport.sendto(data, addr)
        logger.debug(
            "Sent %d bytes to %s:%s (%s %s)",
            len(data), addr[0], addr[1], response.status_code, response.reason,
        )


# =============================================================================
# asyncio DatagramProtocol implementation
# =============================================================================


class _SIPProtocol(asyncio.DatagramProtocol):
    """Internal asyncio protocol that bridges UDP datagrams to the handler.

    This protocol is created by ``SIPTransport.start()`` and should not be
    instantiated directly.
    """

    def __init__(self, handler: HandlerCallback) -> None:
        self._handler = handler
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        """Called when the UDP endpoint is ready."""
        self._transport = transport
        logger.debug("SIP protocol connection established")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called for each inbound UDP datagram.

        Parses the datagram as a SIP request, dispatches it to the handler
        callback, and sends the response (if any) back to the sender.

        Parse errors are logged and silently dropped — we do not send an
        error response for unparseable messages because we cannot reliably
        construct a valid SIP response without dialog headers.
        """
        logger.debug("Received %d bytes from %s:%s", len(data), addr[0], addr[1])

        # Parse the inbound message.
        try:
            request = parse_request(data)
        except SIPParseError as exc:
            logger.warning(
                "Failed to parse SIP message from %s:%s: %s", addr[0], addr[1], exc
            )
            return

        # Stamp the source address on the request.
        request.source_addr = addr

        # Dispatch to the handler asynchronously.
        asyncio.ensure_future(self._dispatch(request, addr))

    async def _dispatch(
        self, request: SIPRequest, addr: tuple[str, int]
    ) -> None:
        """Invoke the handler and send the response."""
        try:
            response = await self._handler(request, addr)
        except Exception:
            logger.exception(
                "Handler raised exception for %s from %s:%s",
                request.method, addr[0], addr[1],
            )
            # Build a minimal 500 response.  Import here to avoid circular
            # dependency at module level (builder imports models, not transport).
            from app.sip.builder import build_error_response

            response = build_error_response(request, 500, "Server Internal Error")

        if response is not None and self._transport is not None:
            response_data = response.to_bytes()
            self._transport.sendto(response_data, addr)
            logger.debug(
                "Sent %s %s (%d bytes) to %s:%s",
                response.status_code, response.reason,
                len(response_data), addr[0], addr[1],
            )

    def error_received(self, exc: Exception) -> None:
        """Called when a send/receive operation fails at the OS level."""
        logger.error("SIP transport error: %s", exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the UDP endpoint is closed."""
        if exc:
            logger.warning("SIP transport connection lost: %s", exc)
        else:
            logger.debug("SIP transport connection closed")
