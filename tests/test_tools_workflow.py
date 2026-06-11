"""Unit tests for workflow tools (no live OSIDB)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_workflow import (
    flaw_promote,
    flaw_reject,
    flaw_reset,
    flaw_revert,
)


def _mock_client():
    client = MagicMock()
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0
    return client


# ---------------------------------------------------------------------------
# flaw_promote tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_promote_success(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"state": "TRIAGE", "workflow": "DEFAULT"}
    resp.raise_for_status.return_value = None
    mock_post.return_value = resp

    result = flaw_promote(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "TRIAGE"
    mock_post.assert_called_once()
    assert "/flaws/aaa58a80-dd9c-43dd-ba19-61fa88a66714/promote" in mock_post.call_args[0][0]


@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_promote_missing_requirements(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    """Promote fails when prerequisites are not met (e.g. no owner)."""
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Flaw has no owner"}'
    mock_post.side_effect = requests.HTTPError(response=resp)

    result = flaw_promote(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 400


# ---------------------------------------------------------------------------
# flaw_reject tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reject_success(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"state": "REJECTED", "workflow": "DEFAULT"}
    resp.raise_for_status.return_value = None
    mock_post.return_value = resp

    result = flaw_reject(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reason="Not a valid vulnerability",
    )

    assert result["ok"] is True
    assert result["classification"]["state"] == "REJECTED"
    call_kwargs = mock_post.call_args[1]
    assert call_kwargs["json"] == {"reason": "Not a valid vulnerability"}


@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reject_http_error(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Cannot reject from DONE state"}'
    mock_post.side_effect = requests.HTTPError(response=resp)

    result = flaw_reject(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reason="Invalid",
    )

    assert result["ok"] is False
    assert result["status_code"] == 400


# ---------------------------------------------------------------------------
# flaw_reset tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reset_success(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"state": "NEW", "workflow": "DEFAULT"}
    resp.raise_for_status.return_value = None
    mock_post.return_value = resp

    result = flaw_reset(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "NEW"
    assert "/flaws/aaa58a80-dd9c-43dd-ba19-61fa88a66714/reset" in mock_post.call_args[0][0]


@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reset_http_error(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    mock_post.side_effect = requests.ConnectionError("timeout")

    result = flaw_reset(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_revert tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_revert_success(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.json.return_value = {"state": "TRIAGE", "workflow": "DEFAULT"}
    resp.raise_for_status.return_value = None
    mock_post.return_value = resp

    result = flaw_revert(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "TRIAGE"
    assert "/flaws/aaa58a80-dd9c-43dd-ba19-61fa88a66714/revert" in mock_post.call_args[0][0]


@patch("osidb_mcp.tools_workflow.requests.post")
@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_revert_already_initial_state(mock_get_session: MagicMock, mock_post: MagicMock) -> None:
    """Revert from NEW fails since there is no previous state."""
    mock_get_session.return_value.get_client_with_new_access_token.return_value = _mock_client()

    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Cannot revert from initial state"}'
    mock_post.side_effect = requests.HTTPError(response=resp)

    result = flaw_revert(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 400
