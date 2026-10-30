# Changelog

## 0.4.0

- **OSIDB 5.21:** Acknowledgment creates and updates send `affiliation` (blank allowed) and `from_upstream` (default false). `flaw_label_add` rejects a missing `type`. Affect PUT bodies omit `flaw` and keep `embargoed`, `ps_update_stream`, and `updated_dt`. Flaw list tools accept `aegis_processed`, `workflow_state_isempty`, and `workflow_name_isempty`. Bindings pin is `osidb-bindings>=5.20.0,<6`. The 5.21 bindings package is not on PyPI yet, so those three filters use a raw GET until the generated client knows them.
- **Tool profiles:** `OSIDB_MCP_PROFILE` is `core`, `lifecycle`, or `full` (default `full`, same catalog as before). `core` advertises 12 triage read tools. `lifecycle` adds the write tools used for vuln lifecycle work. Set this in Cursor `mcp.json` env to cut idle MCP tool-name tokens.
- **Exploits tools:** Registered for `full` by default. Use `OSIDB_MCP_ENABLE_EXPLOITS=true` to enable them on a smaller profile.
- **AEGIS tools:** Still registered only when `AEGIS_URL` is set.
- **Compact payloads:** Default list `limit` is 20 (still capped at 100). Flaw list tools default to a short `include_fields` set. `get_flaw_details` returns compact affect/tracker rows (`compact=true`). Oversized JSON is truncated at 64 KiB.
- **OSIDB 5.16:** `search_flaws` / `flaws_list` accept `flaw_labels`. `workflow_get` supports `history=true`. Label add/update accept optional `reason`. `product_family` labels are rejected as read-only. `owner` docs use email (OSIM), not Jira username.
- **Dropped `identifier_hint`** from list/search payloads (uuid is already on each row).
- **Fix `workflow_get(next=True)`:** pass `next_` to osidb-bindings (`next` is a Python keyword in the generated client).

## 0.3.0

- **Labels v2 API migration:** Label CRUD operations (`flaw_label_add`, `flaw_label_update`, `flaw_label_remove`, `flaw_labels_list`, `flaw_label_get`) now use the OSIDB v2 labels API (`/osidb/api/v2/flaws/{id}/labels`) instead of the deprecated v1 endpoints. The `label` parameter on `flaw_label_add` is renamed to `name` to match the v2 schema.
- **Workflow `next` parameter:** `workflow_get` now supports `next=True` to return the next state and its requirement acceptance status, matching what OSIM uses for the next-state requirements panel.
- **Audit tools always available:** `audit_list` and `audit_get` are now registered in both `readonly` and `readwrite` modes (they are read-only operations).
- **`flaw_create` new fields:** `owner` (Jira username for immediate assignment) and `nist_cvss_validation` are now accepted on flaw creation, matching the full OSIDB `FlawPostRequest` schema.
- **Removed deprecated workflow tools:** `flaw_promote`, `flaw_reject`, `flaw_reset`, and `flaw_revert` have been removed entirely. They were no-ops on OSIDB >= 5.12. Use `flaw_label_add(name='approved', label_type='workflow')` to reach DONE, or `flaw_label_add(name='rejected', label_type='workflow')` to reject. Workflow state is now auto-classified based on flaw data completeness.
- **Documentation:** README write tools table updated to reflect all 38 write tools (was 8). TOOLS.md updated with workflow model documentation, write tool reference, and audit tool sections. CHANGELOG covers all changes since 0.2.0.

## 0.2.1

- **Fix `extra_query` dates:** ISO date/datetime strings in `extra_query` (e.g. `created_dt__gte`, `reported_dt__gte`, `created_dt__date__gte`) are now parsed before calling `osidb-bindings`, which expects Python `datetime`/`date` objects. Fixes `'str' object has no attribute 'isoformat'` when filtering flaws by creation or report date.
- **Docs:** README documents Homebrew install via [vdanen/osidb-mcp](https://github.com/vdanen/homebrew-osidb-mcp).

## 0.2.0

- **Access mode:** `OSIDB_MCP_ACCESS_MODE` supports only `readonly` (default). `readwrite` is **rejected at startup** with a clear error until mutation MCP tools exist; removes misleading “warn and continue” behavior.
- **New read tools:** `flaw_acknowledgments_list`, `flaw_labels_list`, `flaw_package_versions_list` (flaw-scoped lists); `affect_get`, `tracker_get` (single resource by id); `labels_list` (global OSIDB labels); `affect_cvss_scores_list` (per-affect CVSS rows).
- **Security documentation:** add [SECURITY.md](SECURITY.md) — threat model, OWASP-oriented checklist, dual-MCP recommendation for future read/write servers.
- **Docs:** README / TOOLS.md updated for new tools and `readonly`-only access mode.
- **Tests:** config/access-mode regression test for rejected `readwrite`.
- **Live test harness:** optional `live_tests/` + `make livetest` (`pytest -vv -s`); CVE-2014-0160 fixtures; stderr count inventory + optional `OSIDB_LIVE_MIN_*` floors; credential patterns gitignored; documented in `live_tests/README.md`.

## 0.1.4

- **Flaw identity without CVE:** `flaw_get` adds top-level `osidb_flaw_uuid` when `cve_id` is empty; `flaws_list` / `flaws_search` add `identifier_hint` for agents; MCP server instructions document CVE vs `uuid`.
- **Fix `get_flaw_details`:** when a flaw has no CVE, load affects and trackers via `flaw__uuid` / `affects__flaw__uuid` instead of misusing `flaw__cve_id`.
- **New filters:** `affects_list` — `flaw_uuid` / `flaw_uuid_in`; `trackers_list` — `affects_flaw_uuid` / `affects_flaw_uuid_in`; `query_affects` forwards UUID params.
- README / TOOLS.md: flaw identifier section and tool doc updates; tests for identity helpers.

## 0.1.3

- Add `search_component`, `query_affects`, `get_pending_exploit_actions`; `search_flaws` adds major-incident filters.
- README: full MCP tools table and “when to use which” guidance; TOOLS.md reference for tool details and example prompts.

## 0.1.2

- Add `osidb-mcp --version` / `-V` (no credentials or `OSIDB_BASE_URL` required).

## 0.1.1

- Add high-level MCP tools aligned with common CVE servers: `search_flaws`, `get_flaw_details`, `get_cve_summary`.

## 0.1.0

- Initial release: stdio MCP server, `readonly` access mode (OSIDB session via `osidb-bindings`, Kerberos or basic auth). `readwrite` was later rejected at startup until mutation tools exist.
