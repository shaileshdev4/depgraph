"""NVD CVE lookup (deterministic REST, no LLM)."""

import from tools.env_util { ensure_dotenv_loaded }

sem nvd_search_cve = "Search NVD for CVEs related to a package name; returns normalized dicts.";

glob nvd_cache: dict[str, list[dict]] = {};

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

def nvd_search_cve(package_name: str, version: str = "") -> list[dict] {
    cache_key = f"{package_name.lower()}@{version}";
    if cache_key in nvd_cache {
        return nvd_cache[cache_key];
    }

    ensure_dotenv_loaded();
    import os;
    import requests;

    api_key = os.environ.get("NVD_API_KEY", "");
    headers = {};
    if api_key {
        headers["apiKey"] = api_key;
    }
    query = package_name;
    if version {
        query = f"{package_name} {version}";
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    params = {"keywordSearch": query, "resultsPerPage": 15};
    resp = requests.get(url, params=params, headers=headers, timeout=45);
    if resp.status_code != 200 {
        return [];
    }
    body = resp.json();
    vulns = body.get("vulnerabilities", []);
    results: list[dict] = [];
    for item in vulns {
        cve = item.get("cve", {});
        cve_id = cve.get("id", "");
        if not cve_id {
            continue;
        }
        score = 0.0;
        metrics = cve.get("metrics", {});
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            metric_list = metrics.get(metric_key, []);
            if metric_list {
                cvss_data = metric_list[0].get("cvssData", {});
                score = float(str(cvss_data.get("baseScore", 0.0)));
                break;
            }
        }
        descriptions = cve.get("descriptions", []);
        desc = "";
        for d in descriptions {
            if d.get("lang") == "en" {
                desc = d.get("value", "");
                break;
            }
        }
        results.append(
            {
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": _severity_from_score(score),
                "description": desc[:500],
                "fixed_version": ""
            }
        );
    }
    nvd_cache[cache_key] = results;
    return results;
}
