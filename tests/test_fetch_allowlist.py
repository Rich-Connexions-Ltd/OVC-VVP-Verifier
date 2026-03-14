# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Tests for destination allowlist authorization in app/vvp/fetch.py.

Covers:
- Allowed origin (host:port) passes
- Unapproved host rejected before network access
- Empty/unset allowlist rejects all (fail-closed)
- Multiple origins each accepted individually
- Non-standard port mismatch rejected
- Mixed-case hostname normalization
"""

from unittest.mock import patch

import pytest

from app.vvp.fetch import FetchError, authorize_destination


class TestAuthorizeDestination:
    """Test the authorize_destination() function."""

    def test_allowed_origin_passes(self):
        """An origin in the allowlist should not raise."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:443"})):
            authorize_destination("https://example.com/oobi/abc123")

    def test_unapproved_host_rejected(self):
        """A syntactically valid but unapproved host should be rejected."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:443"})):
            with pytest.raises(FetchError, match="Destination not authorized"):
                authorize_destination("https://evil.com/oobi/abc123")

    def test_empty_allowlist_rejects_all(self):
        """An empty allowlist should reject all destinations (fail-closed)."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset()):
            with pytest.raises(FetchError, match="No allowed fetch origins configured"):
                authorize_destination("https://example.com/data")

    def test_multiple_origins_each_accepted(self):
        """Each origin in a multi-origin allowlist should be accepted."""
        origins = frozenset({"witness1.rcnx.io:443", "witness2.rcnx.io:5631"})
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", origins):
            authorize_destination("https://witness1.rcnx.io/oobi/abc")
            authorize_destination("https://witness2.rcnx.io:5631/oobi/def")

    def test_port_mismatch_rejected(self):
        """An allowed host on a non-matching port should be rejected."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:443"})):
            with pytest.raises(FetchError, match="Destination not authorized"):
                authorize_destination("https://example.com:8080/data")

    def test_mixed_case_hostname_normalized(self):
        """Hostname comparison should be case-insensitive."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:443"})):
            authorize_destination("https://EXAMPLE.COM/oobi/abc")

    def test_http_default_port_80(self):
        """HTTP URLs should default to port 80."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:80"})):
            authorize_destination("http://example.com/data")

    def test_https_default_port_443(self):
        """HTTPS URLs should default to port 443."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"example.com:443"})):
            authorize_destination("https://example.com/data")

    def test_explicit_port_matches(self):
        """An explicit port in the URL should match the allowlist."""
        with patch("app.vvp.fetch.VVP_ALLOWED_FETCH_ORIGINS", frozenset({"witness.rcnx.io:5631"})):
            authorize_destination("http://witness.rcnx.io:5631/oobi/abc")
