"""Tool profile registration tests (no live OSIDB)."""

from osidb_mcp.config import AccessMode, Profile, Settings
from osidb_mcp.server import CORE_READ_TOOLS, create_server, registered_tool_names


def _settings(**overrides) -> Settings:
    defaults = dict(
        base_url="https://osidb.example.com",
        auth="kerberos",
        username=None,
        password=None,
        verify_ssl=True,
        user_agent=None,
        access_mode=AccessMode.readonly,
        profile=Profile.full,
        enable_exploits=False,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def test_core_profile_registers_only_core_reads():
    mcp = create_server(_settings(profile=Profile.core, access_mode=AccessMode.readwrite))
    names = registered_tool_names(mcp)
    assert names == CORE_READ_TOOLS
    assert "flaw_create" not in names
    assert "flaws_list" not in names
    assert "exploits_epss" not in names


def test_lifecycle_profile_adds_write_tools():
    mcp = create_server(
        _settings(profile=Profile.lifecycle, access_mode=AccessMode.readwrite)
    )
    names = registered_tool_names(mcp)
    assert CORE_READ_TOOLS <= names
    assert "flaw_create" in names
    assert "flaw_label_add" in names
    assert "flaws_list" not in names
    assert "exploits_epss" not in names


def test_full_profile_has_more_tools_than_core():
    full = registered_tool_names(create_server(_settings(profile=Profile.full)))
    core = registered_tool_names(create_server(_settings(profile=Profile.core)))
    assert len(full) > len(core)
    assert "flaws_list" in full
    assert "exploits_epss" in full


def test_aegis_only_when_url_set():
    without = registered_tool_names(create_server(_settings(profile=Profile.full)))
    with_url = registered_tool_names(
        create_server(_settings(profile=Profile.full, aegis_url="https://aegis.example.com"))
    )
    assert "aegis_get_cve_analysis" not in without
    assert "aegis_get_cve_analysis" in with_url
