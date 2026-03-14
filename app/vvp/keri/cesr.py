# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
# Ported from VVP monorepo services/verifier/app/vvp/keri/cesr.py
# Source commit: 398d40d (2026-03-14)

"""
CESR Stream Parser for Tier 2 KEL resolution.

Parses CESR (Composable Event Streaming Representation) encoded streams
containing KERI events and their attachments (signatures, receipts).

Count code reference (CESR V1.0):
- `-A##`: Controller indexed signatures
- `-B##`: Witness indexed signatures
- `-C##`: Non-transferable receipt couples
- `-D##`: Transferable receipt quadruples
- `-V##`: Attachment group
"""

import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from .exceptions import (
    ResolutionFailedError,
    CESRFramingError,
    CESRMalformedError,
    UnsupportedSerializationKind,
)

_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_LOOKUP: dict = {c: i for i, c in enumerate(_B64_CHARS)}
_VERSION_RE = re.compile(r"^([A-Z]{4})(\d)(\d)([A-Z]{4})([0-9a-f]{6})(_)$")


class CountCode(Enum):
    CONTROLLER_IDX_SIGS = "-A"
    WITNESS_IDX_SIGS = "-B"
    NON_TRANS_RECEIPT = "-C"
    TRANS_RECEIPT_QUAD = "-D"
    ATTACHMENT_GROUP = "-V"


COUNT_CODE_SIZES = {
    "-A": (2, 2, 4), "-B": (2, 2, 4), "-C": (2, 2, 4),
    "-D": (2, 2, 4), "-E": (2, 2, 4), "-F": (2, 2, 4),
    "-G": (2, 2, 4), "-H": (2, 2, 4), "-I": (2, 2, 4),
    "-V": (2, 2, 4), "--V": (3, 5, 8), "-_AAA": (5, 3, 8),
}

SIGNATURE_SIZES = {
    "0A": 64, "0B": 64, "0C": 64, "0D": 64,
    "1AAA": 64, "2AAA": 64, "AA": 64,
}


@dataclass
class CESRVersion:
    protocol: str
    major: int
    minor: int
    kind: str
    size: int


@dataclass
class TransferableReceipt:
    prefix: str
    sequence: int
    digest: str
    signature: bytes


@dataclass
class CESRAttachment:
    code: Optional[CountCode]
    count: int
    data: bytes


@dataclass
class WitnessReceipt:
    witness_aid: str
    signature: bytes
    index: Optional[int] = None


@dataclass
class CESRMessage:
    event_bytes: bytes
    event_dict: dict
    controller_sigs: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: bytes = b""


def _b64_to_int(b64_chars: str) -> int:
    value = 0
    for char in b64_chars:
        value = value * 64 + _B64_LOOKUP[char]
    return value


def parse_version_string(data: bytes, offset: int = 0) -> Tuple[CESRVersion, int]:
    if offset + 17 > len(data):
        raise CESRMalformedError(f"Truncated version string: need 17 bytes, have {len(data) - offset}")
    try:
        vs = data[offset:offset + 17].decode("ascii")
    except UnicodeDecodeError as e:
        raise CESRMalformedError(f"Version string contains non-ASCII bytes: {e}")
    match = _VERSION_RE.match(vs)
    if not match:
        raise CESRMalformedError(f"Invalid version string format: {vs!r}")
    proto, major, minor, kind, size_hex, term = match.groups()
    if kind not in ("JSON",):
        raise UnsupportedSerializationKind(kind)
    return CESRVersion(protocol=proto, major=int(major), minor=int(minor), kind=kind, size=int(size_hex, 16)), offset + 17


def _parse_count_code(data: bytes, offset: int) -> Tuple[str, int, int]:
    if offset >= len(data):
        raise ResolutionFailedError("Unexpected end of CESR stream")
    if data[offset:offset + 5] == b"-_AAA":
        if offset + 8 > len(data):
            raise ResolutionFailedError("Truncated CESR version string")
        return "-_AAA", 0, offset + 8
    if data[offset:offset + 2] == b"--":
        hard = data[offset:offset + 3].decode("ascii")
        if hard in COUNT_CODE_SIZES:
            _, ss, fs = COUNT_CODE_SIZES[hard]
            if offset + fs > len(data):
                raise ResolutionFailedError(f"Truncated count code {hard}")
            soft = data[offset + 3:offset + fs].decode("ascii")
            count = _b64_to_int(soft)
            return hard, count, offset + fs
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated count code")
    hard = data[offset:offset + 2].decode("ascii")
    if hard not in COUNT_CODE_SIZES:
        raise CESRMalformedError(f"Unknown counter code: {hard}")
    _, ss, fs = COUNT_CODE_SIZES[hard]
    if offset + fs > len(data):
        raise ResolutionFailedError(f"Truncated count code {hard}")
    soft = data[offset + 2:offset + fs].decode("ascii")
    count = _b64_to_int(soft)
    return hard, count, offset + fs


def _parse_indexed_signature(data: bytes, offset: int) -> Tuple[bytes, int, int]:
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated signature")
    code_2 = data[offset:offset + 2].decode("ascii")
    if code_2 in ("0A", "0B", "0C", "0D", "AA", "AB", "AC", "AD"):
        index_char = code_2[1]
        signer_index = ord(index_char) - ord("A")
        sig_end = offset + 88
        if sig_end > len(data):
            raise ResolutionFailedError("Truncated Ed25519 signature")
        full_qb64 = data[offset:sig_end].decode("ascii")
        try:
            full_decoded = base64.urlsafe_b64decode(full_qb64)
        except Exception as e:
            raise ResolutionFailedError(f"Invalid signature encoding: {e}")
        sig_bytes = full_decoded[2:]
        return sig_bytes, sig_end, signer_index
    if offset + 4 <= len(data):
        code_4 = data[offset:offset + 4].decode("ascii")
        if code_4 in ("1AAA", "2AAA"):
            sig_end = offset + 88
            if sig_end > len(data):
                raise ResolutionFailedError("Truncated Ed25519 indexed signature")
            full_qb64 = data[offset:sig_end].decode("ascii")
            try:
                full_decoded = base64.urlsafe_b64decode(full_qb64)
            except Exception as e:
                raise ResolutionFailedError(f"Invalid signature encoding: {e}")
            signer_index = full_decoded[0] & 0x3F
            sig_bytes = full_decoded[2:]
            return sig_bytes, sig_end, signer_index
    raise ResolutionFailedError(f"Unknown signature derivation code at offset {offset}")


def _parse_receipt_couple(data: bytes, offset: int) -> Tuple[WitnessReceipt, int]:
    if offset + 1 > len(data):
        raise ResolutionFailedError("Truncated receipt couple")
    aid_char = chr(data[offset])
    if aid_char == "B":
        aid_end = offset + 44
        if aid_end > len(data):
            raise ResolutionFailedError("Truncated witness AID")
        witness_aid = data[offset:aid_end].decode("ascii")
        offset = aid_end
    elif aid_char == "D":
        raise CESRMalformedError(
            "Transferable AID prefix 'D' not allowed in -C non-transferable receipt couple."
        )
    else:
        raise CESRMalformedError(f"Invalid AID prefix in receipt couple: {aid_char}")
    sig_bytes, offset, _index = _parse_indexed_signature(data, offset)
    return WitnessReceipt(witness_aid=witness_aid, signature=sig_bytes), offset


def _parse_trans_receipt_quadruple(data: bytes, offset: int) -> Tuple[TransferableReceipt, int]:
    if offset + 44 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing prefix")
    prefix_char = chr(data[offset])
    if prefix_char not in ("D", "E"):
        raise CESRMalformedError(f"Invalid transferable prefix in receipt: {prefix_char}")
    prefix = data[offset:offset + 44].decode("ascii")
    offset += 44
    if offset + 24 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing sequence")
    snu_code = data[offset:offset + 2].decode("ascii")
    if snu_code != "0A":
        raise CESRMalformedError(f"Invalid sequence number code in receipt: {snu_code}")
    snu_b64 = data[offset + 2:offset + 24].decode("ascii")
    padded = snu_b64 + "=" * (-len(snu_b64) % 4)
    try:
        snu_bytes = base64.urlsafe_b64decode(padded)
        sequence = int.from_bytes(snu_bytes, "big")
    except Exception as e:
        raise CESRMalformedError(f"Invalid sequence number encoding: {e}")
    offset += 24
    if offset + 44 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing digest")
    digest_char = chr(data[offset])
    if digest_char != "E":
        raise CESRMalformedError(f"Invalid digest prefix in receipt: {digest_char}")
    digest = data[offset:offset + 44].decode("ascii")
    offset += 44
    sig_bytes, offset, _index = _parse_indexed_signature(data, offset)
    return TransferableReceipt(prefix=prefix, sequence=sequence, digest=digest, signature=sig_bytes), offset


def _find_json_end(data: bytes, offset: int) -> int:
    depth = 0
    in_string = False
    escape = False
    i = offset
    while i < len(data):
        c = data[i]
        if escape:
            escape = False
            i += 1
            continue
        if c == ord("\\"):
            escape = True
            i += 1
            continue
        if c == ord('"'):
            in_string = not in_string
            i += 1
            continue
        if in_string:
            i += 1
            continue
        if c == ord("{"):
            depth += 1
        elif c == ord("}"):
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    if depth > 0:
        raise ResolutionFailedError("Unterminated JSON object in CESR stream")
    return i


def parse_cesr_stream(data: bytes) -> List[CESRMessage]:
    """Parse a CESR stream into messages with attachments.

    Args:
        data: Raw CESR byte stream.

    Returns:
        List of CESRMessage objects with parsed events and attachments.

    Raises:
        ResolutionFailedError: If parsing fails.
        CESRMalformedError: If stream contains unknown/invalid data.
    """
    if not data:
        return []

    messages = []
    offset = 0

    if data[:5] == b"-_AAA":
        _, _, offset = _parse_count_code(data, 0)

    while offset < len(data):
        while offset < len(data) and data[offset:offset + 1] in (b" ", b"\n", b"\r", b"\t"):
            offset += 1
        if offset >= len(data):
            break

        if data[offset:offset + 1] == b"{":
            json_end = _find_json_end(data, offset)
            event_bytes = data[offset:json_end]
            offset = json_end
            try:
                event_dict = json.loads(event_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ResolutionFailedError(f"Invalid JSON in CESR stream: {e}")
            message = CESRMessage(event_bytes=event_bytes, event_dict=event_dict, raw=event_bytes)

            while offset < len(data):
                while offset < len(data) and data[offset:offset + 1] in (b" ", b"\n", b"\r", b"\t"):
                    offset += 1
                if offset >= len(data):
                    break
                if data[offset:offset + 1] != b"-":
                    break
                try:
                    code, count, new_offset = _parse_count_code(data, offset)
                except ResolutionFailedError:
                    break
                offset = new_offset

                if code == "-A":
                    for _ in range(count):
                        sig, offset, _idx = _parse_indexed_signature(data, offset)
                        message.controller_sigs.append(sig)
                elif code == "-B":
                    for _ in range(count):
                        sig, offset, sig_index = _parse_indexed_signature(data, offset)
                        message.witness_receipts.append(
                            WitnessReceipt(witness_aid="", signature=sig, index=sig_index)
                        )
                elif code == "-C":
                    for _ in range(count):
                        receipt, offset = _parse_receipt_couple(data, offset)
                        message.witness_receipts.append(receipt)
                elif code == "-D":
                    for _ in range(count):
                        trans_receipt, offset = _parse_trans_receipt_quadruple(data, offset)
                        message.witness_receipts.append(
                            WitnessReceipt(witness_aid=trans_receipt.prefix, signature=trans_receipt.signature)
                        )
                elif code == "-V":
                    group_size = count * 4
                    group_end = offset + group_size
                    while offset < group_end:
                        if data[offset:offset + 1] != b"-":
                            break
                        inner_code, inner_count, new_offset = _parse_count_code(data, offset)
                        offset = new_offset
                        if inner_code == "-A":
                            for _ in range(inner_count):
                                sig, offset, _idx = _parse_indexed_signature(data, offset)
                                message.controller_sigs.append(sig)
                        elif inner_code == "-B":
                            for _ in range(inner_count):
                                sig, offset, sig_index = _parse_indexed_signature(data, offset)
                                message.witness_receipts.append(
                                    WitnessReceipt(witness_aid="", signature=sig, index=sig_index)
                                )
                        elif inner_code == "-C":
                            for _ in range(inner_count):
                                receipt, offset = _parse_receipt_couple(data, offset)
                                message.witness_receipts.append(receipt)
                        elif inner_code == "-D":
                            for _ in range(inner_count):
                                trans_receipt, offset = _parse_trans_receipt_quadruple(data, offset)
                                message.witness_receipts.append(
                                    WitnessReceipt(witness_aid=trans_receipt.prefix, signature=trans_receipt.signature)
                                )
                        else:
                            offset = group_end
                            break
                    if offset < group_end:
                        offset = group_end
                elif code == "--V":
                    offset += count
                elif code == "-_AAA":
                    pass
                else:
                    raise CESRMalformedError(f"Unknown counter code '{code}' at offset {offset}")

            messages.append(message)

        elif data[offset:offset + 1] == b"-":
            code, count, new_offset = _parse_count_code(data, offset)
            offset = new_offset
            if code == "-V":
                offset += count * 4
            elif code == "--V":
                offset += count
        else:
            raise ResolutionFailedError(
                f"Unexpected byte in CESR stream at offset {offset}: {data[offset:offset + 10]!r}"
            )

    return messages


def is_cesr_stream(data: bytes) -> bool:
    """Check if data appears to be a CESR stream."""
    if not data:
        return False
    if data[:5] == b"-_AAA":
        return True
    if data[0:1] == b"-":
        return True
    if data[0:1] == b"{":
        try:
            json_end = _find_json_end(data, 0)
            if json_end < len(data):
                remaining = data[json_end:].lstrip()
                if remaining and remaining[0:1] == b"-":
                    return True
        except ResolutionFailedError:
            pass
    return False


def decode_pss_signature(cesr_sig: str) -> bytes:
    """Decode PASSporT-Specific Signature from VVP CESR format.

    Args:
        cesr_sig: CESR-encoded signature string (88 characters).

    Returns:
        Raw 64-byte Ed25519 signature.

    Raises:
        ResolutionFailedError: If format is invalid.
    """
    if not cesr_sig:
        raise ResolutionFailedError("Empty CESR signature")
    if len(cesr_sig) != 88:
        raise ResolutionFailedError(f"Invalid CESR signature length: {len(cesr_sig)}, expected 88")
    code = cesr_sig[:2]
    valid_codes = ("0A", "0B", "0C", "0D", "AA")
    if code not in valid_codes:
        raise ResolutionFailedError(f"Invalid CESR signature derivation code: {code}")
    sig_b64 = cesr_sig[2:]
    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        sig_bytes = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise ResolutionFailedError(f"Invalid CESR signature encoding: {e}")
    if len(sig_bytes) != 64:
        raise ResolutionFailedError(f"Invalid signature length after decode: {len(sig_bytes)}, expected 64")
    return sig_bytes
