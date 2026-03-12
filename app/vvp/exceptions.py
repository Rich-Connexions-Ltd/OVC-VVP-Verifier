# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""VVP Verifier exceptions mapped to error codes per §4.2A."""


class VVPError(Exception):
    """Base exception for VVP verification errors."""
    pass


class VVPIdentityError(VVPError):
    """VVP-Identity header parsing error."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "VVPIdentityError":
        return cls(code="VVP_IDENTITY_MISSING", message="VVP-Identity header is missing or empty")

    @classmethod
    def invalid(cls, reason: str) -> "VVPIdentityError":
        return cls(code="VVP_IDENTITY_INVALID", message=f"VVP-Identity header is invalid: {reason}")

    @classmethod
    def malformed(cls, reason: str) -> "VVPIdentityError":
        return cls(code="VVP_IDENTITY_INVALID", message=f"VVP-Identity header is malformed: {reason}")

    @classmethod
    def invalid_field(cls, field: str, reason: str) -> "VVPIdentityError":
        return cls(code="VVP_IDENTITY_INVALID", message=f"VVP-Identity field '{field}' {reason}")

    @classmethod
    def iat_future(cls, iat: int, now: int, skew: int) -> "VVPIdentityError":
        return cls(
            code="VVP_IDENTITY_INVALID",
            message=f"VVP-Identity iat ({iat}) is too far in the future (now={now}, max_skew={skew}s)",
        )


class PassportError(VVPError):
    """PASSporT JWT parsing/validation error."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "PassportError":
        return cls(code="PASSPORT_MISSING", message="PASSporT JWT is missing or empty")

    @classmethod
    def parse_failed(cls, reason: str) -> "PassportError":
        return cls(code="PASSPORT_PARSE_FAILED", message=f"PASSporT parse failed: {reason}")

    @classmethod
    def malformed(cls, reason: str) -> "PassportError":
        return cls(code="PASSPORT_PARSE_FAILED", message=f"PASSporT is malformed: {reason}")

    @classmethod
    def forbidden_alg(cls, alg: str) -> "PassportError":
        return cls(code="PASSPORT_FORBIDDEN_ALG", message=f"PASSporT uses forbidden algorithm: {alg}")

    @classmethod
    def forbidden_algorithm(cls, alg: str) -> "PassportError":
        return cls(code="PASSPORT_FORBIDDEN_ALG", message=f"PASSporT uses forbidden algorithm: {alg}")

    @classmethod
    def unsupported_algorithm(cls, alg: str) -> "PassportError":
        return cls(code="PASSPORT_PARSE_FAILED", message=f"PASSporT uses unsupported algorithm: {alg}")

    @classmethod
    def invalid_ppt(cls, ppt: str) -> "PassportError":
        return cls(code="PASSPORT_PARSE_FAILED", message=f"PASSporT has invalid ppt: {ppt}")

    @classmethod
    def invalid_field(cls, field: str, reason: str) -> "PassportError":
        return cls(code="PASSPORT_PARSE_FAILED", message=f"PASSporT field '{field}' {reason}")

    @classmethod
    def binding_mismatch(cls, field: str, passport_val: str, identity_val: str) -> "PassportError":
        return cls(
            code="PASSPORT_PARSE_FAILED",
            message=f"PASSporT binding mismatch on '{field}': passport={passport_val!r}, identity={identity_val!r}",
        )

    @classmethod
    def iat_drift(cls, passport_iat: int, identity_iat: int, max_drift: int) -> "PassportError":
        return cls(
            code="PASSPORT_PARSE_FAILED",
            message=f"PASSporT iat drift too large: passport={passport_iat}, identity={identity_iat}, max_drift={max_drift}s",
        )

    @classmethod
    def exp_inconsistency(cls, passport_exp: int, identity_exp: int, max_drift: int) -> "PassportError":
        return cls(
            code="PASSPORT_PARSE_FAILED",
            message=f"PASSporT exp inconsistency: passport={passport_exp}, identity={identity_exp}, max_drift={max_drift}s",
        )

    @classmethod
    def exp_omission(cls) -> "PassportError":
        return cls(
            code="PASSPORT_PARSE_FAILED",
            message="PASSporT omits exp but VVP-Identity provides it",
        )

    @classmethod
    def excessive_validity(cls, validity: int, max_validity: int) -> "PassportError":
        return cls(
            code="PASSPORT_EXPIRED",
            message=f"PASSporT validity period {validity}s exceeds maximum {max_validity}s",
        )

    @classmethod
    def expired(cls, exp: int, now: int, skew: int) -> "PassportError":
        return cls(
            code="PASSPORT_EXPIRED",
            message=f"PASSporT expired: exp={exp}, now={now}, clock_skew={skew}s",
        )

    @classmethod
    def token_too_old(cls, iat: int, now: int, max_age: int, skew: int) -> "PassportError":
        return cls(
            code="PASSPORT_EXPIRED",
            message=f"PASSporT too old: iat={iat}, now={now}, max_age={max_age}s, clock_skew={skew}s",
        )


class SignatureInvalidError(VVPError):
    """Ed25519 signature verification failure."""
    pass


class DossierFetchError(VVPError):
    """Dossier HTTP fetch failure."""
    pass


class DossierParseError(VVPError):
    """Dossier content parsing failure."""
    pass


class DossierGraphError(VVPError):
    """Dossier DAG validation failure."""
    pass
