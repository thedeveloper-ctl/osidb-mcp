"""MCP tool implementations for AEGIS AI-assisted CVE analysis.

AEGIS is an internal AI/ML service that provides automated analysis
features for CVE triage (statement suggestions, component analysis, etc.).
"""

from __future__ import annotations

from typing import Any

import requests

from osidb_mcp.errors import http_error_payload
from osidb_mcp.session_holder import current_settings, get_session


def _aegis_base_url() -> str | None:
    return current_settings().aegis_url


def _aegis_request(
    method: str, path: str, params: dict[str, str] | None = None, json_body: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Make an authenticated request to the AEGIS API."""
    base = _aegis_base_url()
    if not base:
        return {"ok": False, "error": "aegis_not_configured", "detail": "AEGIS_URL not configured"}

    session = get_session()
    client = session.get_client_with_new_access_token()

    kwargs: dict[str, Any] = {
        "headers": client.get_headers(),
        "verify": client.verify_ssl,
        "auth": client.get_auth(),
        "timeout": client.get_timeout(),
    }
    if params:
        kwargs["params"] = params
    if json_body is not None:
        kwargs["json"] = json_body

    try:
        resp = requests.request(method, f"{base}{path}", **kwargs)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, **http_error_payload(exc)}

    try:
        data = resp.json()
    except ValueError:
        data = {"raw_text": resp.text[:4000]}

    return {"ok": True, "result": data}


def aegis_get_cve_analysis(feature_name: str, cve_id: str) -> dict[str, Any]:
    """Retrieve a cached/pre-computed AEGIS analysis for a CVE.

    AEGIS provides AI-assisted analysis features for CVE triage such as
    statement suggestions, impact assessment, and more.

    Args:
        feature_name: The analysis feature to query (e.g. "suggest-statement",
            "suggest-impact", "suggest-title").
        cve_id: The CVE identifier (e.g. "CVE-2024-21626").

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    return _aegis_request(
        "GET",
        "/api/v1/analysis/cve",
        params={"feature": feature_name, "cve_id": cve_id},
    )


def aegis_run_cve_analysis(feature_name: str, body: dict[str, Any]) -> dict[str, Any]:
    """Trigger a new AEGIS analysis for a CVE feature.

    Submits CVE metadata to AEGIS for AI-assisted analysis. The body should
    contain relevant flaw data for the analysis engine to process.

    Args:
        feature_name: The analysis feature to run (e.g. "suggest-statement",
            "suggest-impact", "suggest-title").
        body: JSON object with CVE metadata. Typical fields include:
            cve_id, title, comment_zero, cve_description, statement,
            components, comments, references, embargoed, impact,
            cvss_scores, affects.

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    return _aegis_request(
        "POST",
        f"/api/v1/analysis/cve/{feature_name}",
        json_body=body,
    )


def aegis_get_component_analysis(feature_name: str, component_name: str) -> dict[str, Any]:
    """Retrieve AEGIS component-level analysis.

    Queries AEGIS for analysis results scoped to a specific component.

    Args:
        feature_name: The analysis feature to query.
        component_name: The component name to analyze.

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    return _aegis_request(
        "GET",
        "/api/v1/analysis/component",
        params={"feature": feature_name, "component_name": component_name},
    )


def aegis_get_kpi_metrics(feature_name: str, order: str = "desc") -> dict[str, Any]:
    """Retrieve AEGIS KPI metrics for a feature.

    Returns key performance indicators for a given analysis feature,
    useful for evaluating model quality and coverage.

    Args:
        feature_name: The analysis feature to get KPIs for.
        order: Sort order for results - "asc" or "desc" (default: "desc").

    Returns:
        JSON dict with ``ok`` and ``result`` containing KPI data.
    """
    return _aegis_request(
        "GET",
        "/api/v1/analysis/kpi/cve",
        params={"feature": feature_name, "order": order},
    )
