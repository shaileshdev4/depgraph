# DepGraph tools

Deterministic API helpers — no LLM in this layer.

| Module | Role |
|--------|------|
| `github_api.jac` | Fetch `package-lock.json` from GitHub |
| `lockfile_parser.jac` | Parse npm lockfile v2/v3 |
| `osv_api.jac` | Primary npm CVE lookup ([OSV.dev](https://osv.dev)) |
| `nvd_api.jac` | Filtered NVD keyword fallback |
| `cve_lookup.jac` | Unified `lookup_package_cves()` |
| `env_util.jac` | Load `.env` |
| `jac_coerce.py` | Python `as_list()` for dict/list payloads |
