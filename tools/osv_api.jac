"""OSV.dev vulnerability lookup (accurate per ecosystem + version)."""

import from tools.env_util { ensure_dotenv_loaded }
import from tools.jac_coerce { as_list }

sem osv_query_npm = "Query OSV for npm package@version; returns normalized CVE dicts.";

glob osv_cache: dict[str, list[dict]] = {};

def _severity_from_score(score: float) -> str {
    if score >= 9.0 {
        return "CRITICAL";
    }
    if score >= 7.0 {
        return "HIGH";
    }
    if score >= 4.0 {
        return "MEDIUM";
    }
    if score > 0.0 {
        return "LOW";
    }
    return "UNKNOWN";
}

def osv_query_npm(package_name: str, version: str) -> list[dict] {
    cache_key = f"npm:{package_name.lower()}@{version}";
    if cache_key in osv_cache {
        return osv_cache[cache_key];
    }

    ensure_dotenv_loaded();
    import requests;

    url = "https://api.osv.dev/v1/query";
    payload = {
        "package": {"name": package_name, "ecosystem": "npm"},
        "version": version
    };
    resp = requests.post(url, json=payload, timeout=30);
    if resp.status_code != 200 {
        osv_cache[cache_key] = [];
        return [];
    }
    body = resp.json();
    vulns = as_list(body.get("vulns", []));
    results: list[dict] = [];
    for item in vulns {
        if not isinstance(item, dict) {
            continue;
        }
        cve_id = str(item.get("id", ""));
        if not cve_id {
            continue;
        }
        score = 0.0;
        db = item.get("database_specific", {});
        if isinstance(db, dict) and "cvss_score" in db {
            score = float(str(db["cvss_score"]));
        }
        summary = str(item.get("summary", ""));
        if not summary {
            details = str(item.get("details", ""));
            summary = details[0:500];
        }
        results.append(
            {
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": _severity_from_score(score),
                "description": summary[0:500],
                "fixed_version": "",
                "source": "osv"
            }
        );
    }
    osv_cache[cache_key] = results;
    return results;
}
