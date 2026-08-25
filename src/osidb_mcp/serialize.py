"""JSON-friendly serialization for bindings models and responses."""

from __future__ import annotations

import datetime
import json
from enum import Enum
from typing import Any
from uuid import UUID

DEFAULT_MAX_PAYLOAD_BYTES = 65536


def to_jsonable(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if hasattr(obj, "to_dict"):
        return to_jsonable(obj.to_dict())
    return str(obj)


def _payload_size(obj: Any) -> int:
    return len(json.dumps(obj, default=str).encode("utf-8"))


def maybe_truncate(
    payload: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
) -> dict[str, Any]:
    """If JSON encoding exceeds ``max_bytes``, shrink ``results`` and set ``truncated``.

    When a single result row still exceeds the budget, the first row is kept so
    the caller gets a sample rather than an empty list.
    """
    if _payload_size(payload) <= max_bytes:
        return payload

    out = dict(payload)
    out["truncated"] = True
    results = out.get("results")
    if not isinstance(results, list) or not results:
        return out

    lo, hi = 0, len(results)
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        trial = dict(out)
        trial["results"] = results[:mid]
        if _payload_size(trial) <= max_bytes:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1

    if best == 0:
        out["results"] = results[:1]
    else:
        out["results"] = results[:best]
    return out


def compact_affect_row(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "uuid": item.get("uuid"),
        "ps_module": item.get("ps_module"),
        "ps_component": item.get("ps_component"),
        "affectedness": item.get("affectedness"),
        "resolution": item.get("resolution"),
    }


def compact_tracker_row(item: dict[str, Any]) -> dict[str, Any]:
    typ = item.get("type")
    if typ is None:
        typ = item.get("type_")
    return {
        "uuid": item.get("uuid"),
        "type": typ,
        "external_system_id": item.get("external_system_id"),
        "status": item.get("status"),
    }


def paginated_summary(
    response: Any,
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Common pagination envelope for list endpoints."""
    results = getattr(response, "results", ()) or ()
    out: dict[str, Any] = {
        "count": getattr(response, "count", None),
        "limit": limit,
        "offset": offset,
        "results": [to_jsonable(r) for r in results],
    }
    next_url = getattr(response, "next_", None)
    if next_url:
        out["next"] = next_url
        out["next_offset"] = offset + len(results)
    return maybe_truncate(out)


def cap_payload(
    payload: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
) -> dict[str, Any]:
    """Shrink oversized JSON payloads so MCP tool results stay under a token budget."""
    return maybe_truncate(payload, max_bytes=max_bytes)
