"""Pydantic output schemas cho AI responses trong Metis."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple, Type

from pydantic import BaseModel, Field


class TodaysIntelBrief(BaseModel):
    executive_summary: str = Field(default="")
    priority_items: List[str] = Field(default_factory=list)
    watchlist: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list)


class TodaysIntelReport(BaseModel):
    title: str = Field(default="")
    scope: str = Field(default="")
    executive_assessment: str = Field(default="")
    key_judgments: List[str] = Field(default_factory=list)
    threat_landscape: str = Field(default="")
    vulnerability_and_exploit_assessment: str = Field(default="")
    ransomware_assessment: str = Field(default="")
    actor_and_malware_assessment: str = Field(default="")
    regional_or_sector_relevance: str = Field(default="")
    priority_developments: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    collection_gaps: List[str] = Field(default_factory=list)
    confidence: str = Field(default="Không xác định")


def _recover_json(raw: str) -> Tuple[Any, bool]:
    """Parse JSON với khả năng phục hồi khi bị truncate."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE).strip()
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text or "{}"), False
    except ValueError:
        pass
    recovered = text
    recovered = re.sub(r',\s*"[^"]*"?\s*:\s*"[^"]*$', '', recovered)
    recovered = re.sub(r',\s*"[^"]*"?\s*:\s*\[[^\]]*$', '', recovered)
    if recovered and not recovered.rstrip().endswith(","):
        d_br = recovered.count("[") - recovered.count("]")
        d_cu = recovered.count("{") - recovered.count("}")
        recovered = recovered.rstrip().rstrip(",")
        recovered += "]" * max(0, d_br)
        recovered += "}" * max(0, d_cu)
    try:
        return json.loads(recovered), True
    except ValueError:
        pass
    partial: Dict[str, Any] = {}
    for m in re.finditer(r'"(\w+)"\s*:\s*"((?:[^"\\]|\\.)*)"', text):
        partial[m.group(1)] = m.group(2)
    if partial:
        return partial, True
    return {}, True


def _pydantic_validate(schema_class: Type[BaseModel], data: dict) -> BaseModel:
    """Tương thích Pydantic v1 và v2."""
    try:
        return schema_class.model_validate(data)  # Pydantic v2
    except AttributeError:
        return schema_class.parse_obj(data)  # Pydantic v1


def validate_schema(
    raw: str,
    schema_class: Type[BaseModel],
    fallback_fn: Any = None,
) -> Tuple[BaseModel, bool]:
    """Parse raw JSON string → validate Pydantic schema.

    Returns (instance, was_recovered). Nếu fail, dùng fallback_fn hoặc tạo instance mặc định.
    """
    data, recovered = _recover_json(raw or "{}")

    if not isinstance(data, dict):
        data = {}
        recovered = True

    try:
        instance = _pydantic_validate(schema_class, data)
        return instance, recovered
    except Exception:
        if fallback_fn is not None:
            try:
                instance = fallback_fn(data)
                return instance, True
            except Exception:
                pass
        return schema_class(), True
