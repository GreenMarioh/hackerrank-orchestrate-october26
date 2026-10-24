"""
loader_image.py — Loads image evidence files (PNG screenshots) into normalized Observations.

Follows the zero-embedded-truth rule:
- Strictly calls the vision model with prompts/image_extract.md.
- Caches responses by SHA-256 of the raw image bytes in .cache/vision_cache.json.
- If no LLM_API_KEY is configured or SKIP_IMAGES is set, skips image extraction
  with a clear warning and records an explicit UnparsedEvidenceRecord.
- Absolutely NO hardcoded per-file evidence values are embedded in code.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from ghost.config import CACHE_DIR, LLM_API_KEY, LLM_MODEL, SKIP_IMAGES
from ghost.models import Observation, UnparsedEvidenceRecord

logger = logging.getLogger(__name__)


def _get_cache_path() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / "vision_cache.json"


def _load_vision_cache() -> dict[str, Any]:
    cache_file = _get_cache_path()
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read vision cache at %s: %s", cache_file, exc)
            return {}
    return {}


def _save_vision_cache(cache: dict[str, Any]) -> None:
    cache_file = _get_cache_path()
    try:
        cache_file.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write vision cache at %s: %s", cache_file, exc)


def load_image_evidence(
    file_path: Path,
    file_id: str,
    manifest_captured_at: datetime,
) -> tuple[list[Observation], list[UnparsedEvidenceRecord]]:
    """
    Extracts Observations from a PNG screenshot using vision model or cache.
    Zero per-file values are hardcoded in this loader.
    """
    observations: list[Observation] = []
    unparsed: list[UnparsedEvidenceRecord] = []

    try:
        img_bytes = file_path.read_bytes()
        sha256 = hashlib.sha256(img_bytes).hexdigest()
    except Exception as exc:
        unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), "Image read error", str(exc)))
        return observations, unparsed

    cache = _load_vision_cache()
    cached_data = cache.get(sha256)

    # If not in cache and vision API is configured, call the model
    if not cached_data:
        if not LLM_API_KEY or SKIP_IMAGES:
            warning_msg = (
                f"Skipping vision extraction for {file_id} ({file_path.name}): "
                f"{'SKIP_IMAGES=1' if SKIP_IMAGES else 'no LLM_API_KEY configured in environment'}. "
                f"Image evidence will not produce observations without API key or pre-existing cache."
            )
            logger.warning(warning_msg)
            unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), warning_msg))
            return observations, unparsed

        # Call vision model
        try:
            from google import genai
            from PIL import Image

            client = genai.Client(api_key=LLM_API_KEY)
            prompt_path = Path("code/prompts/image_extract.md")
            prompt_text = prompt_path.read_text(encoding="utf-8")
            img = Image.open(str(file_path))

            model_name = LLM_MODEL or "gemini-2.0-flash"
            response = client.models.generate_content(
                model=model_name,
                contents=[img, prompt_text],
                config={"temperature": 0.0},
            )
            resp_text = response.text or "{}"

            # Extract JSON block
            if "```json" in resp_text:
                resp_text = resp_text.split("```json")[1].split("```")[0].strip()
            elif "```" in resp_text:
                resp_text = resp_text.split("```")[1].split("```")[0].strip()

            cached_data = json.loads(resp_text)
            cache[sha256] = cached_data
            _save_vision_cache(cache)
        except Exception as exc:
            err_msg = f"Vision model extraction failed: {exc}"
            logger.warning("Vision call failed for %s: %s", file_id, exc)
            unparsed.append(UnparsedEvidenceRecord(file_id, str(file_path), err_msg, str(exc)))
            return observations, unparsed

    # Process extracted records from cache/response
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
