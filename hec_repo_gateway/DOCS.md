# HEC Repo Gateway 0.2.0

Ingress-only HTTP API. No published host port. Only Supervisor Ingress source
172.30.32.2 is accepted, as required by HA Apps documentation. Keep protected mode
and default AppArmor enabled. No SSH, Docker socket, privileged mode or shell API.

GET /health checks both required directories and filesystem write flags without
writing source files. Missing or read-only mounts mean BLOCKED; do not bypass.
GET /tools lists operations. POST /call takes JSON:
`{"tool":"read_source","arguments":{"path":"/homeassistant/example.py"}}`.
Use HEC MCP `ha_manage_app(slug=<discovered slug>, path="/call", method="POST",
body=<JSON object>)` through Ingress. Call ha_get_app to discover the actual slug.

## Arguments

- repo_status: {} for mount status, or {session} for isolated Git status.
- repo_search: {root, query}; literal search, at most 100 file metadata results.
- read_source/appdaemon_read: {path}, optionally {session}; returns content/hash.
- controlled_patch_source/appdaemon_patch: {path, sha256, old, new}, optionally
  {session}; unique literal replacement, optimistic hash guard, backup and audit.
- snapshot_create: {paths}; captures 1-20 exact source files into isolated Git.
- fixture_create: {}; creates a fresh fixture repository in /data/sessions.
- run_focused_tests: {session, paths, expected_value?}; Python AST validation and
  fixed fixture assertion, never executes arbitrary source or tests from mounts.
- run_full_hec_regression: {}; rejects all arguments. Runs only
  `/homeassistant/HEC/share/build52_61_testenv/bin/pytest -q hec_audit_offline`
  with cwd `/homeassistant`, shell disabled and 300s timeout. Returns captured
  stdout/stderr, exit_code and parsed final counts; PASS requires exactly
  763 passed, zero failures and exit code 0. Start/end are audited.

- git_diff/git_diff_check/git_stage_exact: {session, paths}.
- git_commit_no_push: {session, paths, message}; exact staged set and clean
  matching worktree required. Git operates ONLY on isolated repositories.
- live_readback: {}; fixed GET sensor.hec_runtime via Supervisor Core API.

## Safety and scope

Roots: /homeassistant and /addon_configs/a0d7b954_appdaemon/apps. Readable text
extensions: py, yaml, yml, json, md, txt. Dot paths, traversal, symlinks, multi-link
files and protected names are denied. Source writes default to empty editable_paths.
An explicit exact editable_paths entry is required for each production patch.
GoodWe, BUILD names, tariff/taryfa, secrets and credentials are denied for writes
in both filenames and original/replacement content. Never whitelist active tariff
BUILD files. GOODWE_WRITE=0 is mandatory. No service calls or write hardware API.

Git uses fixed argument arrays without shell, clean environment, no hooks or
remotes, no push and no broad staging. /data/audit.jsonl records operations,
paths and hashes, never source content or Supervisor credentials. Backups and
sessions persist in /data; protect HA backups accordingly.

The app exposes an HTTP API through the existing HEC MCP proxy; it is not a
standalone MCP transport. In a normal ChatGPT chat, connect the existing HEC Home
Assistant MCP app and use ha_get_app + ha_manage_app. Availability in ChatGPT must
be tested there; installation alone does not demonstrate a new-chat end-to-end PASS.
