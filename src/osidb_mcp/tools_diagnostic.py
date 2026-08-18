"""Composite diagnostic and tracking tools for flaw workflow advancement."""

from __future__ import annotations

from typing import Any

import requests

from osidb_mcp.errors import http_error_payload
from osidb_mcp.serialize import to_jsonable
from osidb_mcp.session_holder import current_settings, get_session


_IMPACT_PRIORITY_MAP: dict[str, str] = {
    "CRITICAL": "Critical",
    "IMPORTANT": "High",
    "MODERATE": "Medium",
    "LOW": "Low",
}

_REQUIRED_FIELDS_NEW_TO_TRIAGE = (
    "components", "cwe_id", "impact", "reported_dt", "source", "title",
)


def _error_response(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, requests.RequestException):
        return {"ok": False, **http_error_payload(exc)}
    return {"ok": False, "error": "osidb_error", "detail": str(exc)}


def _check_missing_fields(flaw: dict[str, Any]) -> list[dict[str, str]]:
    """Check which fields are missing or empty on the flaw payload."""
    missing = []
    for field in _REQUIRED_FIELDS_NEW_TO_TRIAGE:
        val = flaw.get(field)
        if val is None or val == "" or val == []:
            missing.append({"field": field, "status": "empty_or_missing"})

    impact = flaw.get("impact", "")
    if impact and impact != "LOW":
        cve_desc = flaw.get("cve_description")
        if not cve_desc:
            missing.append({"field": "cve_description", "status": "required_for_non_LOW_impact"})

    if not flaw.get("owner"):
        missing.append({"field": "owner", "status": "empty (needed for MANUAL workflow)"})

    return missing


def _analyze_affects(affects: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze affect resolution status."""
    total = len(affects)
    resolved = 0
    unresolved = []
    delegated_without_tracker = []

    for aff in affects:
        affectedness = aff.get("affectedness", "")
        resolution = aff.get("resolution", "")
        trackers = aff.get("trackers", [])

        if affectedness == "NEW" and not resolution:
            unresolved.append({
                "uuid": aff.get("uuid"),
                "ps_module": aff.get("ps_module"),
                "ps_component": aff.get("ps_component"),
                "ps_update_stream": aff.get("ps_update_stream"),
                "issue": "affectedness=NEW, no resolution set",
            })
        elif affectedness == "AFFECTED" and resolution == "DELEGATED":
            if not trackers:
                delegated_without_tracker.append({
                    "uuid": aff.get("uuid"),
                    "ps_module": aff.get("ps_module"),
                    "ps_component": aff.get("ps_component"),
                    "ps_update_stream": aff.get("ps_update_stream"),
                    "issue": "AFFECTED:DELEGATED but no tracker filed",
                })
            else:
                resolved += 1
        else:
            resolved += 1

    return {
        "total": total,
        "resolved": resolved,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved[:10] if unresolved else None,
        "delegated_without_tracker_count": len(delegated_without_tracker),
        "delegated_without_tracker": delegated_without_tracker[:10] if delegated_without_tracker else None,
    }


def _get_workflow_next_state(session: Any, flaw_id: str) -> dict[str, Any]:
    """Call the workflows API with verbose+next to get advancement requirements."""
    client = session.get_client_with_new_access_token()
    try:
        resp = requests.get(
            f"{client.base_url}/workflows/api/v1/workflows/{flaw_id}",
            params={"verbose": "true", "next": "true"},
            headers=client.get_headers(),
            verify=client.verify_ssl,
            auth=client.get_auth(),
            timeout=client.get_timeout(),
        )
        resp.raise_for_status()
        return {"ok": True, "data": resp.json()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _get_alerts(session: Any, parent_uuid: str, parent_model: str) -> list[dict[str, Any]]:
    """Fetch alerts for a parent object."""
    client = session.get_client_with_new_access_token()
    try:
        resp = requests.get(
            f"{client.base_url}/osidb/api/v1/alerts",
            params={
                "parent_uuid": parent_uuid,
                "parent_model": parent_model,
                "limit": 100,
            },
            headers=client.get_headers(),
            verify=client.verify_ssl,
            auth=client.get_auth(),
            timeout=client.get_timeout(),
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except Exception:
        return []


def flaw_workflow_diagnostic(
    flaw_id: str,
    *,
    include_affect_alerts: bool = False,
) -> dict[str, Any]:
    """Run a full workflow diagnostic on a flaw to determine what blocks advancement.

    Performs a composite analysis:
    1. Fetches flaw details (fields, affects, trackers)
    2. Checks required fields against workflow stage requirements
    3. Fetches flaw-level alerts (validation errors)
    4. Optionally fetches affect-level alerts
    5. Calls the workflow API (verbose+next) for requirement acceptance status
    6. Checks for Jira task_key existence

    Returns a structured diagnostic report with:
    - Current workflow state and classification
    - Missing/empty required fields
    - Affect analysis (resolved vs unresolved, tracker gaps)
    - Alert summary (blocking errors)
    - Next-state requirements (satisfied/unsatisfied)
    - Whether a Jira tracking ticket exists
    - Suggested priority for Jira ticket creation

    Args:
        flaw_id: Flaw CVE id or internal OSIDB UUID (required).
        include_affect_alerts: If True, also fetch alerts for each affect
            (can be slow for flaws with many affects). Default False.
    """
    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id)
        flaw_data = to_jsonable(flaw)
    except Exception as exc:
        return _error_response(exc)

    flaw_uuid = flaw_data.get("uuid", flaw_id)

    try:
        affects_resp = session.affects.retrieve_list(
            flaw_uuid=flaw_uuid, limit=100,
        )
        affects = [to_jsonable(a) for a in (affects_resp.results or [])]
    except Exception:
        affects = []

    try:
        trackers_resp = session.trackers.retrieve_list(
            affects__flaw__uuid=flaw_uuid, limit=100,
        )
        trackers = [to_jsonable(t) for t in (trackers_resp.results or [])]
    except Exception:
        trackers = []

    missing_fields = _check_missing_fields(flaw_data)

    affect_analysis = _analyze_affects(affects)

    flaw_alerts = _get_alerts(session, flaw_uuid, "Flaw")

    affect_alerts_summary: list[dict[str, Any]] = []
    if include_affect_alerts and affects:
        for aff in affects[:20]:
            aff_uuid = aff.get("uuid")
            if aff_uuid:
                aff_alerts = _get_alerts(session, aff_uuid, "Affect")
                if aff_alerts:
                    affect_alerts_summary.append({
                        "affect_uuid": aff_uuid,
                        "ps_module": aff.get("ps_module"),
                        "ps_component": aff.get("ps_component"),
                        "alerts": aff_alerts,
                    })

    workflow_result = _get_workflow_next_state(session, flaw_uuid)

    workflow_info: dict[str, Any] = {}
    next_state_requirements: list[dict[str, Any]] = []
    if workflow_result.get("ok"):
        wf_data = workflow_result["data"]
        classification = wf_data.get("classification", {})
        workflow_info = {
            "current_state": classification.get("state"),
            "workflow_name": classification.get("workflow"),
        }

        workflows = wf_data.get("workflows", [])
        current_wf_name = classification.get("workflow")
        current_state_name = classification.get("state")

        for wf in workflows:
            if wf.get("name") == current_wf_name:
                states = wf.get("states", [])
                current_idx = -1
                for i, st in enumerate(states):
                    if st.get("name") == current_state_name:
                        current_idx = i
                        break
                if current_idx >= 0 and current_idx < len(states) - 1:
                    next_st = states[current_idx + 1]
                    workflow_info["next_state"] = next_st.get("name")
                    workflow_info["next_state_accepts"] = next_st.get("accepts", False)
                    for req in next_st.get("requirements", []):
                        next_state_requirements.append({
                            "name": req.get("name") or req.get("condition", ""),
                            "description": req.get("description", ""),
                            "accepts": req.get("accepts", False),
                        })
                elif current_idx == len(states) - 1:
                    workflow_info["next_state"] = None
                    workflow_info["detail"] = "Already at terminal state"
                break
    else:
        workflow_info = {"error": workflow_result.get("error", "Failed to fetch workflow")}

    task_key = flaw_data.get("task_key", "")
    impact = flaw_data.get("impact", "")

    diagnostic: dict[str, Any] = {
        "ok": True,
        "flaw_uuid": flaw_uuid,
        "cve_id": flaw_data.get("cve_id") or None,
        "title": flaw_data.get("title"),
        "workflow": workflow_info,
        "missing_fields": missing_fields if missing_fields else None,
        "affects": affect_analysis,
        "trackers_count": len(trackers),
        "flaw_alerts": flaw_alerts if flaw_alerts else None,
        "flaw_alerts_count": len(flaw_alerts),
        "next_state_requirements": next_state_requirements if next_state_requirements else None,
        "has_jira_task": bool(task_key),
        "task_key": task_key or None,
        "suggested_jira_priority": _IMPACT_PRIORITY_MAP.get(impact, "Medium"),
    }

    if affect_alerts_summary:
        diagnostic["affect_alerts"] = affect_alerts_summary

    unsatisfied = [r for r in next_state_requirements if not r.get("accepts")]
    diagnostic["blockers_summary"] = {
        "unsatisfied_requirements": len(unsatisfied),
        "missing_field_count": len(missing_fields),
        "unresolved_affects": affect_analysis["unresolved_count"],
        "delegated_without_tracker": affect_analysis["delegated_without_tracker_count"],
        "blocking_alerts": len([a for a in flaw_alerts if a.get("alert_type") == "ERROR"]),
    }

    return diagnostic


def flaw_create_tracking_ticket(
    flaw_id: str,
    project: str = "OSIM",
    *,
    issue_type: str = "Task",
    labels: list[str] | None = None,
    assignee: str | None = None,
    extra_description: str | None = None,
) -> dict[str, Any]:
    """Create a Jira tracking ticket for a flaw that has no task_key.

    For legacy flaws created before OSIDB-Jira sync was set up, this creates
    a Jira issue for tracking/audit purposes. Note: this does NOT link the
    ticket back to OSIDB's task_key (that requires OSIDB's native sync).

    To trigger OSIDB's native Jira task creation instead, use
    ``flaw_update(flaw_id, create_jira_task=True)``.

    Args:
        flaw_id: Flaw CVE id or internal OSIDB UUID (required).
        project: Jira project key (default "OSIM").
        issue_type: Jira issue type (default "Task").
        labels: Labels to apply to the Jira ticket.
            Default: ["legacy-cleanup"].
        assignee: Jira username to assign. If None, no assignment.
        extra_description: Additional text to append to the ticket description.
    """
    settings = current_settings()

    missing_cfg: list[str] = []
    if not settings.jira_url:
        missing_cfg.append("JIRA_URL")
    if not settings.jira_access_token:
        missing_cfg.append("JIRA_ACCESS_TOKEN")
    if not settings.jira_api_email:
        missing_cfg.append("JIRA_API_EMAIL")
    if missing_cfg:
        return {
            "ok": False,
            "error": "jira_not_configured",
            "detail": f"Missing env vars: {', '.join(missing_cfg)}",
        }

    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id)
        flaw_data = to_jsonable(flaw)
    except Exception as exc:
        return _error_response(exc)

    task_key = flaw_data.get("task_key", "")
    if task_key:
        return {
            "ok": False,
            "error": "task_key_exists",
            "detail": f"Flaw already has a Jira task: {task_key}. "
                      "Use flaw_update(create_jira_task=True) to recreate, "
                      "or work directly with the existing ticket.",
            "task_key": task_key,
        }

    flaw_uuid = flaw_data.get("uuid", flaw_id)
    cve_id = flaw_data.get("cve_id") or "NO-CVE"
    title = flaw_data.get("title", "")
    impact = flaw_data.get("impact", "")
    components = flaw_data.get("components", [])
    workflow_state = flaw_data.get("classification", {}).get("state", "UNKNOWN")
    created_dt = flaw_data.get("created_dt", "")

    summary = f"[{cve_id}] {title}"
    if len(summary) > 255:
        summary = summary[:252] + "..."

    osim_link = f"https://osim.prodsec.redhat.com/flaws/{flaw_uuid}"
    component_str = ", ".join(components) if components else "N/A"

    description_parts = [
        f"OSIDB flaw cleanup / tracking ticket",
        f"",
        f"Flaw UUID: {flaw_uuid}",
        f"CVE: {cve_id}",
        f"Component: {component_str}",
        f"Impact: {impact or 'NOT SET'}",
        f"Workflow State: {workflow_state}",
        f"Created: {created_dt}",
        f"OSIM Link: {osim_link}",
    ]
    if extra_description:
        description_parts.append(f"\n{extra_description}")

    description = "\n".join(description_parts)

    if labels is None:
        labels = ["legacy-cleanup"]

    priority = _IMPACT_PRIORITY_MAP.get(impact, "Medium")

    jira_payload: dict[str, Any] = {
        "fields": {
            "project": {"key": project},
            "issuetype": {"name": issue_type},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}],
                    }
                ],
            },
            "priority": {"name": priority},
            "labels": labels,
        }
    }

    if assignee:
        jira_payload["fields"]["assignee"] = {"name": assignee}

    url = f"{settings.jira_url.rstrip('/')}/rest/api/3/issue"
    headers = {"Content-Type": "application/json"}
    auth = (settings.jira_api_email, settings.jira_access_token)

    try:
        import certifi
        ca_bundle = certifi.where()
    except ImportError:
        ca_bundle = True  # type: ignore[assignment]

    try:
        resp = requests.post(
            url, json=jira_payload, headers=headers, auth=auth,
            timeout=30, verify=ca_bundle,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ok": True,
            "ticket_key": data.get("key"),
            "ticket_id": data.get("id"),
            "ticket_url": f"{settings.jira_url.rstrip('/')}/browse/{data.get('key')}",
            "flaw_uuid": flaw_uuid,
            "cve_id": cve_id,
            "note": "This ticket is for tracking only. It is NOT linked to OSIDB task_key. "
                    "To create the native OSIDB link, use flaw_update(flaw_id, create_jira_task=True).",
        }
    except Exception as exc:
        return _error_response(exc)
