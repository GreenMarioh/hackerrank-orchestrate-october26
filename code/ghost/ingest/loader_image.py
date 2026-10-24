"""
loader_image.py — Loads image evidence files (PNG screenshots) into normalized Observations.

Follows the zero-embedded-truth rule:
- Routes through ghost.llm.ModelClient (default_client).
- If no LLM_API_KEY is configured in .env or SKIP_IMAGES is set, skips image extraction
  with a clear warning and records an explicit UnparsedEvidenceRecord.
- Absolutely NO hardcoded per-file evidence values are embedded in code.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from ghost.config import get_llm_api_key, is_skip_images
from ghost.llm import default_client
from ghost.models import Observation, UnparsedEvidenceRecord

logger = logging.getLogger(__name__)


def load_image_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[UnparsedEvidenceRecord]]:
    """
    Extracts Observations from a PNG screenshot using ModelClient.
    Zero per-file values are hardcoded in this loader.
    """
    observations: list[Observation] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    if not file_path.exists():
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "File does not exist"))
        return observations, unparsed

    api_key = get_llm_api_key()
    skip = is_skip_images()

    # Check if image is already cached in default_client
    cache = default_client._load_vision_cache()
    import hashlib
    img_bytes = file_path.read_bytes()
    sha256 = hashlib.sha256(img_bytes).hexdigest()

    if sha256 not in cache and (not api_key or skip):
        warning_msg = (
            f"Skipping vision extraction for {file_id} ({file_path.name}): "
            f"{'SKIP_IMAGES=1' if skip else 'no LLM_API_KEY configured in environment'}. "
            f"Image evidence will not produce observations without API key or pre-existing cache."
        )
        logger.warning(warning_msg)
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), warning_msg))
        return observations, unparsed

    try:
        prompt_path = Path("code/prompts/image_extract.md")
        prompt_text = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""
        cached_data, cache_hit = default_client.extract_image(
            file_path, prompt_text, purpose="image_extraction"
        )
    except Exception as exc:
        err_msg = f"Vision model extraction failed: {exc}"
        logger.warning("Vision call failed for %s: %s", file_id, exc)
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), err_msg, str(exc)))
        return observations, unparsed

    # Process extracted records from response
    system_id = cached_data.get("system_id", "image_service")
    category = cached_data.get("category")
    records = cached_data.get("records", [])

    for idx, rec in enumerate(records):
        rid = rec.get("resource_id") or f"img_{file_id}_{idx}"
        fields: dict[str, Any] = dict(rec)
        if rec.get("email"):
            fields["email"] = rec["email"].lower()
        if "enabled" in rec:
            fields["enabled"] = rec["enabled"]
        if "restore_allowed" in rec:
            fields["restore_allowed"] = rec["restore_allowed"]

        obs_id = f"{file_id}:img:{rid}:{idx}"
        observations.append(
            Observation(
                obs_id=obs_id,
                file_id=file_id,
                captured_at=manifest_captured_at,
                system_id=system_id,
                store="image",
                resource_id=rid,
                category=category,
                fields=fields,
                present=True,
            )
        )

    if not observations and not unparsed:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Vision extraction returned 0 records"))

    return observations, unparsed
