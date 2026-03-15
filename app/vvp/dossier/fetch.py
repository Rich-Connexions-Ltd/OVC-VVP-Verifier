# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""Dossier fetching with SSRF guards and size limits."""

from __future__ import annotations

import logging

from app.core.config import DOSSIER_MAX_SIZE_BYTES
from app.vvp.fetch import FetchError, safe_get
from app.vvp.exceptions import DossierFetchError

logger = logging.getLogger(__name__)


async def fetch_dossier(url: str) -> bytes:
    """Fetch a dossier from *url* via SSRF-safe HTTP GET.

    Parameters
    ----------
    url : str
        The evidence URL from the VVP-Identity ``evd`` field.

    Returns
    -------
    bytes
        The raw response body.

    Raises
    ------
    DossierFetchError
        On network errors, timeouts, non-2xx status codes, or if the
        response body exceeds :data:`DOSSIER_MAX_SIZE_BYTES`.
    """
    if not url or not url.strip():
        raise DossierFetchError("Dossier URL is empty")

    logger.debug("Fetching dossier from %s", url)
    try:
        return await safe_get(url, max_size=DOSSIER_MAX_SIZE_BYTES)
    except FetchError as exc:
        raise DossierFetchError(str(exc)) from exc
