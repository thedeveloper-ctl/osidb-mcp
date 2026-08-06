"""MCP tool implementations for OSIDB flaw workflow state transitions.

DEPRECATION NOTICE (OSIDB >= 5.12):
Workflow state is now classified automatically by OSIDB based on flaw data
completeness.  The promote/reject/reset/revert endpoints are retained for
backward compatibility but are no-ops on modern servers.  To advance a flaw
through the workflow, update its data (flaw_update, affect_add, tracker_create)
and add a workflow label named ``approved`` via flaw_label_add to reach DONE.
"""

from __future__ import annotations

from typing import Any

import requests
from osidb_bindings.session import get_sync_function as _get_sync_function

from osidb_mcp.errors import http_error_payload
from osidb_mcp.serialize import to_jsonable
from osidb_mcp.session_holder import get_session

_DEPRECATION_MSG = (
    "This endpoint is deprecated on OSIDB >= 5.12. Workflow state is now "
    "classified automatically based on flaw data completeness. To advance "
    "a flaw, update its fields (flaw_update / affect_add / tracker_create) "
    "and add a workflow label named 'approved' via flaw_label_add to reach DONE."
)


def _error_response(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, requests.RequestException):
        return {"ok": False, **http_error_payload(exc)}
    return {"ok": False, "error": "osidb_error", "detail": str(exc)}


def _inject_deprecation(result: dict[str, Any]) -> dict[str, Any]:
    result["deprecated"] = True
    result["deprecation_message"] = _DEPRECATION_MSG
    return result


def flaw_promote(flaw_id: str) -> dict[str, Any]:
    """[DEPRECATED] Promote a flaw to the next workflow state.

    On OSIDB >= 5.12 this endpoint is a no-op.  Workflow classification is
    now automatic based on flaw data completeness.  To advance a flaw,
    populate required fields via flaw_update / affect_add / tracker_create,
    then add a workflow label named 'approved' via flaw_label_add to reach DONE.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification``, ``deprecated``, ``deprecation_message``.
    """
    session = get_session()
    try:
        result = session.flaws.promote(flaw_id)
        return _inject_deprecation({"ok": True, "classification": to_jsonable(result)})
    except Exception as exc:
        return _error_response(exc)


def flaw_reject(flaw_id: str, reason: str) -> dict[str, Any]:
    """[DEPRECATED] Reject a flaw.

    On OSIDB >= 5.12 this endpoint is a no-op; the reason argument is ignored.
    Rejection is now handled automatically via workflow classification or by
    adding a label named 'rejected' with type 'workflow'.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).
        reason: Explanation for the rejection (ignored on modern OSIDB).

    Returns:
        JSON dict with ``ok``, ``classification``, ``deprecated``, ``deprecation_message``.
    """
    session = get_session()
    try:
        # Bypass session.flaws.reject() which raises UndefinedRequestBody
        # because the OSIDB >= 5.12 bindings no longer define a REQUEST_BODY_TYPE
        # for the reject endpoint.  Call the low-level binding directly (no body).
        method_module = session.flaws._get_method_module(
            resource_name="flaws",
            method="reject_create",
        )
        sync_fn = _get_sync_function(method_module)
        result = sync_fn(
            flaw_id,
            client=session.get_client_with_new_access_token(),
        )
        return _inject_deprecation({"ok": True, "classification": to_jsonable(result)})
    except Exception as exc:
        return _error_response(exc)


def flaw_reset(flaw_id: str) -> dict[str, Any]:
    """[DEPRECATED] Reset a flaw workflow state.

    On OSIDB >= 5.12 this endpoint is a no-op.  Workflow classification is
    now automatic and cannot be manually reset.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification``, ``deprecated``, ``deprecation_message``.
    """
    session = get_session()
    try:
        result = session.flaws.reset(flaw_id)
        return _inject_deprecation({"ok": True, "classification": to_jsonable(result)})
    except Exception as exc:
        return _error_response(exc)


def flaw_revert(flaw_id: str) -> dict[str, Any]:
    """[DEPRECATED] Revert a flaw to the previous workflow state.

    On OSIDB >= 5.12 this endpoint is a no-op.  Workflow classification is
    now automatic and cannot be manually reverted.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification``, ``deprecated``, ``deprecation_message``.
    """
    session = get_session()
    try:
        result = session.flaws.revert(flaw_id)
        return _inject_deprecation({"ok": True, "classification": to_jsonable(result)})
    except Exception as exc:
        return _error_response(exc)
