"""Unit tests for AEGIS integration tools (no live AEGIS instance)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_aegis import (
    aegis_get_component_analysis,
    aegis_get_cve_analysis,
    aegis_get_kpi_metrics,
    aegis_run_cve_analysis,
)


AEGIS_URL = "https://aegis.example.com"


def _mock_client():
    client = MagicMock()
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0
    return client


def _mock_settings(aegis_url: str | None = AEGIS_URL):
    settings = MagicMock()
    settings.aegis_url = aegis_url
    return settings


# ---------------------------------------------------------------------------
# aegis_get_cve_analysis
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_cve_analysis_success(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"statement": "This CVE affects..."}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["result"]["statement"] == "This CVE affects..."
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[0][0] == "GET"
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/cve"
    assert call_args[1]["params"] == {"feature": "suggest-statement", "cve_id": "CVE-2024-1234"}


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_cve_analysis_http_error(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.status_code = 403
    resp.text = "Forbidden"
    mock_request.side_effect = requests.HTTPError(response=resp)

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 403


# ---------------------------------------------------------------------------
# aegis_run_cve_analysis
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_run_cve_analysis_success(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"suggestion": "A buffer overflow in..."}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    body = {"cve_id": "CVE-2024-1234", "title": "Buffer overflow", "components": ["curl"]}
    result = aegis_run_cve_analysis(feature_name="suggest-statement", body=body)

    assert result["ok"] is True
    assert result["result"]["suggestion"] == "A buffer overflow in..."
    call_args = mock_request.call_args
    assert call_args[0][0] == "POST"
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/cve/suggest-statement"
    assert call_args[1]["json"] == body


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_run_cve_analysis_server_error(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.status_code = 500
    resp.text = "Internal Server Error"
    mock_request.side_effect = requests.HTTPError(response=resp)

    result = aegis_run_cve_analysis(feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"})

    assert result["ok"] is False
    assert result["status_code"] == 500


# ---------------------------------------------------------------------------
# aegis_get_component_analysis
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_component_analysis_success(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"component": "curl", "risk": "high"}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_component_analysis(feature_name="risk-score", component_name="curl")

    assert result["ok"] is True
    assert result["result"]["component"] == "curl"
    call_args = mock_request.call_args
    assert call_args[1]["params"] == {"feature": "risk-score", "component_name": "curl"}


# ---------------------------------------------------------------------------
# aegis_get_kpi_metrics
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_kpi_metrics_success(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"accuracy": 0.92, "coverage": 0.85}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_kpi_metrics(feature_name="suggest-statement", order="asc")

    assert result["ok"] is True
    assert result["result"]["accuracy"] == 0.92
    call_args = mock_request.call_args
    assert call_args[1]["params"] == {"feature": "suggest-statement", "order": "asc"}


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_kpi_metrics_default_order(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"accuracy": 0.90}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_kpi_metrics(feature_name="suggest-impact")

    assert result["ok"] is True
    call_args = mock_request.call_args
    assert call_args[1]["params"]["order"] == "desc"


# ---------------------------------------------------------------------------
# Edge cases: not configured
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.current_settings")
def test_not_configured_returns_error(mock_settings: MagicMock) -> None:
    mock_settings.return_value = _mock_settings(aegis_url=None)

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is False
    assert result["error"] == "aegis_not_configured"
    assert "not configured" in result["detail"]


# ---------------------------------------------------------------------------
# Edge cases: non-JSON response
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_non_json_response_returns_raw_text(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.side_effect = ValueError("No JSON")
    resp.text = "<html>Service Unavailable</html>"
    mock_request.return_value = resp

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["result"]["raw_text"] == "<html>Service Unavailable</html>"


# ---------------------------------------------------------------------------
# Edge cases: connection error
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.get_session")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_connection_error(
    mock_settings: MagicMock, mock_get_session: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    mock_request.side_effect = requests.ConnectionError("Connection refused")

    result = aegis_run_cve_analysis(feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"})

    assert result["ok"] is False
    assert "error" in result
