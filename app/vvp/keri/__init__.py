# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/
# Source commit: 398d40d (2026-03-14)

"""KERI subsystem for Tier 2 key state resolution.

This package provides KEL (Key Event Log) resolution for transferable
KERI AIDs. It resolves key state at a reference time T by fetching
KELs from witness OOBI endpoints, validating the event chain, and
extracting the authoritative signing keys.

Public API:
    resolve_key_state()          — Main entry point for Tier 2 resolution
    resolve_delegation_chain()   — Delegation chain validation
    parse_kel_stream()           — KEL event parsing (JSON/CESR)
    validate_kel_chain()         — KEL chain validation rules
    dereference_oobi()           — OOBI HTTP fetch
    KeyState                     — Resolved key state dataclass
    KELEvent                     — Parsed KEL event dataclass

signature.py calls only resolve_key_state() and resolve_delegation_chain()
— it does not import parser internals, CESR helpers, or cache.
"""

from .exceptions import (
    KeriError,
    SignatureInvalidError,
    ResolutionFailedError,
    StateInvalidError,
    KELChainInvalidError,
    KeyNotYetValidError,
    DelegationNotSupportedError,
    OOBIContentInvalidError,
    CESRFramingError,
    CESRMalformedError,
    UnsupportedSerializationKind,
)
from .key_parser import VerificationKey, parse_kid_to_verkey

__all__ = [
    # Exceptions
    "KeriError",
    "SignatureInvalidError",
    "ResolutionFailedError",
    "StateInvalidError",
    "KELChainInvalidError",
    "KeyNotYetValidError",
    "DelegationNotSupportedError",
    "OOBIContentInvalidError",
    "CESRFramingError",
    "CESRMalformedError",
    "UnsupportedSerializationKind",
    # Key parser
    "VerificationKey",
    "parse_kid_to_verkey",
]
