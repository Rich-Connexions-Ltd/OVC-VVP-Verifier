# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Static schema SAID registry for VVP credential types.

Maps well-known vLEI credential types to their governance-approved
schema SAIDs.  The verifier uses this registry to determine the
credential type from a schema SAID encountered in an ACDC, and to
validate that the SAID is recognized.

Credential types whose SAID sets are empty (``frozenset()``) are
"pending governance" — the type is known to the system but no SAIDs
have been ratified yet.  ``is_known_schema`` returns ``True`` for
these types regardless of the SAID presented, allowing forward
compatibility while governance catches up.

References
----------
- GLEIF vLEI Ecosystem Governance Framework
- VVP Verifier Specification v1.5 §6 — Schema validation
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional

__all__ = [
    "KNOWN_SCHEMAS",
    "get_credential_type",
    "is_known_schema",
]


# ---------------------------------------------------------------------------
# Schema SAID registry
# ---------------------------------------------------------------------------

KNOWN_SCHEMAS: Dict[str, FrozenSet[str]] = {
    "QVI": frozenset({
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    }),
    "LE": frozenset({
        "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
        "EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6",
    }),
    "OOR_AUTH": frozenset({
        "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E",
    }),
    "OOR": frozenset({
        "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
    }),
    "ECR_AUTH": frozenset({
        "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",
    }),
    "ECR": frozenset({
        "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
    }),
    "APE": frozenset(),  # Pending governance
    "DE": frozenset({
        "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",
    }),
    "TNAlloc": frozenset({
        "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # Base TN Allocation
    }),
}


# ---------------------------------------------------------------------------
# Reverse lookup: SAID -> credential type
# ---------------------------------------------------------------------------

_SAID_TO_TYPE: Dict[str, str] = {}
for _cred_type, _saids in KNOWN_SCHEMAS.items():
    for _said in _saids:
        _SAID_TO_TYPE[_said] = _cred_type


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_credential_type(schema_said: str) -> Optional[str]:
    """Look up the credential type for a schema SAID.

    Parameters
    ----------
    schema_said : str
        The SAID of the schema (e.g. from the ACDC ``s`` field).

    Returns
    -------
    str or None
        The credential type name (e.g. ``"QVI"``, ``"LE"``), or
        ``None`` if the SAID is not in the registry.
    """
    return _SAID_TO_TYPE.get(schema_said)


def is_known_schema(cred_type: str, said: str) -> bool:
    """Check whether a schema SAID is recognized for a credential type.

    Returns ``True`` in two cases:

    1. The *said* is explicitly listed in ``KNOWN_SCHEMAS[cred_type]``.
    2. The *cred_type* exists but has an empty SAID set (pending
       governance), in which case **any** SAID is accepted.

    Returns ``False`` if *cred_type* is not in ``KNOWN_SCHEMAS`` at all.

    Parameters
    ----------
    cred_type : str
        The credential type name (e.g. ``"QVI"``, ``"APE"``).
    said : str
        The schema SAID to validate.

    Returns
    -------
    bool
        ``True`` if the SAID is accepted for this credential type.
    """
    known_saids = KNOWN_SCHEMAS.get(cred_type)
    if known_saids is None:
        return False
    # Empty set means pending governance — accept any SAID
    if len(known_saids) == 0:
        return True
    return said in known_saids
