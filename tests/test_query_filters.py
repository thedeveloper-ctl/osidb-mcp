import datetime

from osidb_mcp.query_filters import (
    FLAWS_EXTRA_KEYS,
    FLAWS_QUERY_PARAM_TYPES,
    merge_extra_query,
    parse_date,
    parse_dt,
)
from osidb_mcp.tools_read import (
    _attach_flaw_list_identity_hint,
    _envelope_osidb_flaw_uuid_when_no_cve,
    _flaw_has_usable_cve_id,
    get_cve_summary,
)


def test_merge_extra_allowlisted():
    base = {"limit": 10, "offset": 0}
    out = merge_extra_query(
        base,
        {"title": "x"},
        allowlist=FLAWS_EXTRA_KEYS,
        param_types=FLAWS_QUERY_PARAM_TYPES,
    )
    assert out["title"] == "x"
    assert out["limit"] == 10


def test_merge_extra_rejects_unknown():
    base = {"limit": 1}
    try:
        merge_extra_query(
            base,
            {"not_a_real_osidb_key": 1},
            allowlist=FLAWS_EXTRA_KEYS,
            param_types=FLAWS_QUERY_PARAM_TYPES,
        )
    except ValueError as e:
        assert "not allowed" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_merge_extra_coerces_datetime_strings():
    out = merge_extra_query(
        {"limit": 10},
        {
            "cve_id__isempty": True,
            "created_dt__gte": "2026-05-01T00:00:00Z",
            "reported_dt__gte": "2026-05-01",
        },
        allowlist=FLAWS_EXTRA_KEYS,
        param_types=FLAWS_QUERY_PARAM_TYPES,
    )
    assert out["cve_id__isempty"] is True
    assert isinstance(out["created_dt__gte"], datetime.datetime)
    assert out["created_dt__gte"].isoformat().startswith("2026-05-01")
    assert isinstance(out["reported_dt__gte"], datetime.datetime)


def test_merge_extra_coerces_date_only_strings():
    out = merge_extra_query(
        {"limit": 10},
        {"created_dt__date__gte": "2026-05-01"},
        allowlist=FLAWS_EXTRA_KEYS,
        param_types=FLAWS_QUERY_PARAM_TYPES,
    )
    assert out["created_dt__date__gte"] == datetime.date(2026, 5, 1)


def test_parse_dt_accepts_z_suffix():
    assert parse_dt("2026-05-01T00:00:00Z") == datetime.datetime(
        2026, 5, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
    )


def test_parse_date_from_date_string():
    assert parse_date("2026-05-01") == datetime.date(2026, 5, 1)


def test_get_cve_summary_invalid_group_by():
    r = get_cve_summary(group_by="nope")
    assert r["ok"] is False
    assert "group_by" in r.get("detail", "")


def test_flaw_has_usable_cve_id():
    assert _flaw_has_usable_cve_id({"cve_id": "CVE-2024-1"})
    assert not _flaw_has_usable_cve_id({"cve_id": ""})
    assert not _flaw_has_usable_cve_id({"cve_id": None, "uuid": "550e8400-e29b-41d4-a716-446655440000"})


def test_envelope_osidb_flaw_uuid_when_no_cve():
    out = _envelope_osidb_flaw_uuid_when_no_cve(
        {"ok": True, "flaw": {"uuid": "abc", "cve_id": None}}
    )
    assert out["osidb_flaw_uuid"] == "abc"


def test_envelope_skips_when_cve_present():
    out = _envelope_osidb_flaw_uuid_when_no_cve(
        {"ok": True, "flaw": {"uuid": "abc", "cve_id": "CVE-2024-1"}}
    )
    assert "osidb_flaw_uuid" not in out


def test_attach_flaw_list_identity_hint():
    out = _attach_flaw_list_identity_hint({"ok": True, "results": []})
    assert "identifier_hint" in out
