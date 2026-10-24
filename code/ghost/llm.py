"""
llm.py — Single centralized wrapper for all LLM model calls.

Tracks:
- Provider (default: "google")
- Model name
- Input tokens and output tokens from API response metadata
- Purpose of call (e.g. "image_extraction", "intent_classification")
- Cache hit vs cache miss
- Cumulative usage stats for evaluation/usage_report.md

Security:
- Never prints, logs, or exposes API keys or tokens.
- Reads API key via get_llm_api_key() from environment / .env.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghost.config import CACHE_DIR, get_llm_api_key, get_llm_model

logger = logging.getLogger(__name__)


@dataclass
class ModelCallRecord:
    timestamp: str
    provider: str
    model: str
    purpose: str
    cache_hit: bool
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    call_id: str = ""


class ModelClient:
    """
    Central wrapper managing model calls, token usage logging, and caching.
    """

    def __init__(self, provider: str = "google", cache_dir: Path = CACHE_DIR) -> None:
        self.provider = provider
        self.cache_dir = cache_dir
        self.records: list[ModelCallRecord] = []
        self._vision_cache: dict[str, Any] | None = None
        self._text_cache: dict[str, Any] | None = None

    @property
    def vision_cache_path(self) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / "vision_cache.json"

    @property
    def text_cache_path(self) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / "text_cache.json"

    def _load_vision_cache(self) -> dict[str, Any]:
        if self._vision_cache is None:
            if self.vision_cache_path.exists():
                try:
                    self._vision_cache = json.loads(self.vision_cache_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    logger.warning("Failed to read vision cache: %s", exc)
                    self._vision_cache = {}
            else:
                self._vision_cache = {}
        return self._vision_cache

    def _save_vision_cache(self) -> None:
        if self._vision_cache is not None:
            try:
                self.vision_cache_path.write_text(json.dumps(self._vision_cache, indent=2), encoding="utf-8")
            except Exception as exc:
                logger.warning("Failed to save vision cache: %s", exc)

    def extract_image(
        self,
        image_path: Path,
        prompt_text: str,
        purpose: str = "image_extraction",
    ) -> tuple[dict[str, Any], bool]:
        """
        Extracts structured data from an image file.
        Returns: (extracted_dict, cache_hit)
        Raises:
            FileNotFoundError if image does not exist.
            ValueError if no API key is available and image is not in cache.
        """
        img_bytes = image_path.read_bytes()
        sha256 = hashlib.sha256(img_bytes).hexdigest()

        cache = self._load_vision_cache()
        if sha256 in cache:
            record = ModelCallRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                provider=self.provider,
                model=get_llm_model(),
                purpose=purpose,
                cache_hit=True,
                input_tokens=0,
                output_tokens=0,
                total_tokens=0,
                call_id=f"cache_{sha256[:8]}",
            )
            self.records.append(record)
            return cache[sha256], True

        api_key = get_llm_api_key()
        if not api_key:
            raise ValueError(f"No LLM_API_KEY configured to analyze {image_path.name}")

        model_name = get_llm_model()

        # Execute API call with google.genai
        from google import genai
        from PIL import Image

        client = genai.Client(api_key=api_key)
        img = Image.open(str(image_path))

        response = client.models.generate_content(
            model=model_name,
            contents=[img, prompt_text],
            config={"temperature": 0.0},
        )

        in_tok = 0
        out_tok = 0
        tot_tok = 0
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            in_tok = getattr(response.usage_metadata, "prompt_token_count", 0) or 0
            out_tok = getattr(response.usage_metadata, "candidates_token_count", 0) or 0
            tot_tok = getattr(response.usage_metadata, "total_token_count", 0) or (in_tok + out_tok)

        record = ModelCallRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider=self.provider,
            model=model_name,
            purpose=purpose,
            cache_hit=False,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=tot_tok,
            call_id=f"call_{sha256[:8]}",
        )
        self.records.append(record)

        resp_text = response.text or "{}"
        if "```json" in resp_text:
            resp_text = resp_text.split("```json")[1].split("```")[0].strip()
        elif "```" in resp_text:
            resp_text = resp_text.split("```")[1].split("```")[0].strip()

        data = json.loads(resp_text)
        cache[sha256] = data
        self._save_vision_cache()

        return data, False

    def get_usage_summary(self) -> dict[str, Any]:
        """
        Returns token and call counts aggregated for usage_report.md.
        """
        total_calls = len(self.records)
        api_calls = sum(1 for r in self.records if not r.cache_hit)
        cache_hits = sum(1 for r in self.records if r.cache_hit)
        total_in = sum(r.input_tokens for r in self.records)
        total_out = sum(r.output_tokens for r in self.records)
        total_tokens = sum(r.total_tokens for r in self.records)

        by_model: dict[str, dict[str, int]] = {}
        for r in self.records:
            if r.model not in by_model:
                by_model[r.model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            by_model[r.model]["calls"] += 1
            by_model[r.model]["input_tokens"] += r.input_tokens
            by_model[r.model]["output_tokens"] += r.output_tokens
            by_model[r.model]["total_tokens"] += r.total_tokens

        return {
            "total_calls": total_calls,
            "api_calls": api_calls,
            "cache_hits": cache_hits,
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "total_tokens": total_tokens,
            "by_model": by_model,
        }


# Global singleton instance
default_client = ModelClient()
