# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/exceptions.py
# Source commit: 398d40d (2026-03-14)

"""KERI-specific exceptions mapped to VVP error codes.

Per spec §5.4:
- Cryptographic failures → INVALID (non-recoverable)
- Resolution failures → INDETERMINATE (recoverable)
"""

import re
import urllib.parse
from typing import Optional

from app.vvp.models import ErrorCode


# ---------------------------------------------------------------------------
# Log redaction utility
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_TN_RE = re.compile(r"\+\d{7,15}")


def redact_for_log(value: str, kind: str = "generic") -> str:
    """Redact sensitive data for log output.

    Args:
        value: The value to redact.
        kind: Type hint — "jwt", "tn", "url", or "generic".

    Returns:
        Redacted string safe for logging.
    """
    if not value:
        return value

    if kind == "jwt":
        if len(value) > 16:
            return f"{value[:8]}...{value[-4:]}"
        return "***"

    if kind == "tn":
        return f"tn:redacted:{len(value)}chars"

    if kind == "url":
        parsed = urllib.parse.urlparse(value)
        return f"{parsed.scheme}://{parsed.hostname}/..."

    # Generic: redact embedded JWTs and TNs
    result = _JWT_RE.sub(lambda m: f"{m.group()[:8]}...{m.group()[-4:]}", value)
    result = _TN_RE.sub("tn:redacted", result)
    return result


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------

class KeriError(Exception):
    """Base exception for KERI operations.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = redact_for_log(message)
        super().__init__(self.message)


class SignatureInvalidError(KeriError):
    """Signature is cryptographically invalid.

    Maps to PASSPORT_SIG_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "Signature verification failed"):
        super().__init__(ErrorCode.PASSPORT_SIG_INVALID, message)


class ResolutionFailedError(KeriError):
    """Transient failure resolving key state.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    """

    def __init__(self, message: str = "KERI resolution failed"):
        super().__init__(ErrorCode.KERI_RESOLUTION_FAILED, message)


class StateInvalidError(KeriError):
    """Key state is cryptographically invalid.

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "KERI state invalid"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class KELChainInvalidError(StateInvalidError):
    """KEL chain validation failed."""

    def __init__(self, message: str = "KEL chain validation failed"):
        super().__init__(message)


class KeyNotYetValidError(StateInvalidError):
    """No establishment event exists at or before reference time T."""

    def __init__(self, message: str = "No valid key state at reference time"):
        super().__init__(message)


class DelegationNotSupportedError(ResolutionFailedError):
    """Delegated event detected but delegation chain is invalid."""

    def __init__(self, message: str = "Delegation chain validation failed"):
        super().__init__(message)


class OOBIContentInvalidError(KeriError):
    """OOBI response has invalid content type or malformed data."""

    def __init__(self, message: str = "Invalid OOBI content"):
        super().__init__(ErrorCode.VVP_OOBI_CONTENT_INVALID, message)


class CESRFramingError(KeriError):
    """CESR attachment group framing error."""

    def __init__(self, message: str = "CESR framing error"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class CESRMalformedError(KeriError):
    """CESR stream contains malformed or unknown data."""

    def __init__(self, message: str = "CESR malformed"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class UnsupportedSerializationKind(KeriError):
    """CESR version string indicates unsupported serialization kind."""

    def __init__(self, kind: str = "unknown"):
        message = (
            f"Serialization kind '{kind}' not supported. "
            f"Only JSON is supported in this version."
        )
        super().__init__(ErrorCode.KERI_RESOLUTION_FAILED, message)
