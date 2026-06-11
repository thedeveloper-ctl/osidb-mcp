"""MCP tool implementations for OSIDB flaw workflow state transitions.

Uses raw HTTP calls to avoid osidb-bindings model validation issues
(e.g. unrecognized FlawLabelType values in responses).
"""

from __future__ import annotations

from typing import Any

import requests

from osidb_mcp.errors import http_error_payload
from osidb_mcp.session_holder import get_session


def _error_response(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, requests.RequestException):
        return {"ok": False, **http_error_payload(exc)}
    return {"ok": False, "error": "osidb_error", "detail": str(exc)}


def _workflow_action(flaw_id: str, action: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a workflow action via raw HTTP POST.

    Uses direct requests instead of session.flaws.promote/reject/etc. to avoid
    osidb-bindings Pydantic response parsing which crashes on unrecognized enum
    values (e.g. FlawLabelType "bu" not in bindings <=5.10).
    """
    session = get_session()
    client = session.get_client_with_new_access_token()

    kwargs: dict[str, Any] = {
        "headers": client.get_headers(),
        "verify": client.verify_ssl,
        "auth": client.get_auth(),
        "timeout": client.get_timeout(),
    }
    if json_body is not None:
        kwargs["json"] = json_body

    try:
        resp = requests.post(
            f"{client.base_url}/osidb/api/v1/flaws/{flaw_id}/{action}",
            **kwargs,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, **http_error_payload(exc)}

    return {"ok": True, "classification": resp.json()}


def flaw_promote(flaw_id: str) -> dict[str, Any]:
    """Promote a flaw to the next workflow state.

    Advances the flaw one step forward in the workflow:
    NEW -> TRIAGE -> PRE_SECONDARY_ASSESSMENT -> SECONDARY_ASSESSMENT -> DONE.

    Each transition has prerequisites (e.g. owner assigned, title set,
    trackers filed). OSIDB returns 400 if requirements are not met.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    return _workflow_action(flaw_id, "promote")


def flaw_reject(flaw_id: str, reason: str) -> dict[str, Any]:
    """Reject a flaw (move to REJECTED state).

    Only flaws in NEW or TRIAGE state can be rejected.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).
        reason: Explanation for the rejection (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    return _workflow_action(flaw_id, "reject", {"reason": reason})


def flaw_reset(flaw_id: str) -> dict[str, Any]:
    """Reset a flaw back to NEW state.

    Can be called from NEW, TRIAGE, or DONE states.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    return _workflow_action(flaw_id, "reset")


def flaw_revert(flaw_id: str) -> dict[str, Any]:
    """Revert a flaw to the previous workflow state.

    Moves the flaw one step backward:
    DONE -> SECONDARY_ASSESSMENT -> PRE_SECONDARY_ASSESSMENT -> TRIAGE -> NEW.

    Cannot revert from NEW (already initial state).

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    return _workflow_action(flaw_id, "revert")
