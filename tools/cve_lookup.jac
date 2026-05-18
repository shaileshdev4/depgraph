"""Unified CVE lookup: OSV for npm, filtered NVD fallback."""

import from tools.nvd_api { nvd_search_cve }
import from tools.osv_api { osv_query_npm }

sem lookup_package_cves = "Return CVE dicts for a package; prefers OSV on npm.";

def lookup_package_cves(
    package_name: str,
    version: str,
    ecosystem: str = "npm"
) -> list[dict] {
    if ecosystem == "npm" and version {
        osv_hits = osv_query_npm(package_name, version);
        if osv_hits {
            return osv_hits;
        }
        return [];
    }
    return nvd_search_cve(package_name, version);
}
