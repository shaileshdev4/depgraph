"""Parse dependency manifests into unified {packages, edges} for DepGraph."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

HIGH_RISK_KEYWORDS = (
    "jwt", "auth", "crypto", "passport", "bcrypt", "serialize",
    "eval", "exec", "shell", "xml", "yaml", "parse", "request",
    "axios", "express", "lodash", "moment", "vm2", "node-serialize",
    "log4", "token", "cookie", "session", "oauth", "ssl", "tls",
    "https", "http", "fetch", "got", "body-parser",
    "spring", "jackson", "fastjson", "log4j", "struts",
)


def _normalize_version_spec(spec: str) -> str:
    s = str(spec).strip()
    if not s or s == "*":
        return ""
    for prefix in ("^", "~"):
        if s.startswith(prefix):
            s = s[1:].strip()
            break
    for prefix in (">=", "<=", ">", "<", "="):
        if s.startswith(prefix):
            s = s[len(prefix) :].strip()
            break
    if s.startswith("=="):
        s = s[2:].strip()
    if "||" in s:
        s = s.split("||", 1)[0].strip()
    if " - " in s:
        s = s.split(" - ")[-1].strip()
    return s


def _package_risk_score(name: str, version: str, depth: int, is_direct: bool) -> int:
    score = 0
    if depth == 0:
        score += 100
    elif depth == 1:
        score += 80
    else:
        depth_bonus = 10 - depth
        if depth_bonus > 0:
            score += depth_bonus * 10
    name_lower = name.lower()
    if any(kw in name_lower for kw in HIGH_RISK_KEYWORDS):
        score += 50
    ver = str(version).strip()
    if ver:
        parts = ver.split(".")
        try:
            major = int(parts[0])
            if major == 0:
                score += 40
            elif major == 1:
                score += 20
            elif major == 2:
                score += 10
        except ValueError:
            pass
    if is_direct:
        score += 15
    return score


def _filter_top_risk_packages(
    packages: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    max_packages: int,
) -> dict[str, Any]:
    if len(packages) <= max_packages:
        return {
            "packages": packages,
            "edges": edges,
            "truncated": False,
            "original_package_count": len(packages),
            "method": "none",
        }
    key_to_score: dict[str, int] = {}
    for pkg in packages:
        key = str(pkg["key"])
        key_to_score[key] = _package_risk_score(
            str(pkg["name"]),
            str(pkg["version"]),
            int(pkg.get("depth", 0)),
            bool(pkg.get("is_direct", False)),
        )
    selected: list[dict[str, Any]] = []
    selected_keys: set[str] = set()
    while len(selected) < max_packages:
        best_key = ""
        best_score = -1
        for pkg_key, entry_score in key_to_score.items():
            if pkg_key in selected_keys:
                continue
            if entry_score > best_score:
                best_score = entry_score
                best_key = pkg_key
        if not best_key:
            break
        for pkg in packages:
            if str(pkg["key"]) == best_key:
                selected.append(pkg)
                selected_keys.add(best_key)
                break
    kept_edges = [
        e
        for e in edges
        if str(e["from_key"]) in selected_keys and str(e["to_key"]) in selected_keys
    ]
    return {
        "packages": selected,
        "edges": kept_edges,
        "truncated": True,
        "original_package_count": len(packages),
        "method": "risk_score",
    }


def _ok_result(
    packages: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    manifest_kind: str,
    max_packages: int,
) -> dict[str, Any]:
    filtered = _filter_top_risk_packages(packages, edges, max_packages)
    return {
        "ok": True,
        "packages": filtered["packages"],
        "edges": filtered["edges"],
        "package_count": len(filtered["packages"]),
        "truncated": filtered["truncated"],
        "original_package_count": filtered["original_package_count"],
        "filter_method": filtered["method"],
        "manifest_kind": manifest_kind,
    }


# --- npm (mirrors lockfile_parser.jac) ---


def _lock_path_name(lock_path: str) -> str:
    if not lock_path:
        return ""
    if lock_path.startswith("node_modules/"):
        return lock_path.split("node_modules/")[-1]
    return lock_path


def parse_npm_package_json(manifest_text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        data = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    if not isinstance(data, dict):
        return {"ok": False, "error": "package.json root must be an object"}

    root_name = str(data.get("name", "root"))
    root_version = _normalize_version_spec(str(data.get("version", "0.0.0"))) or "0.0.0"
    root_key = f"{root_name}@{root_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": root_name,
            "version": root_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []
    deps = data.get("dependencies") or {}
    if not isinstance(deps, dict):
        deps = {}
    for dep_name, dep_spec in deps.items():
        dep_version = _normalize_version_spec(str(dep_spec)) or str(dep_spec)
        dep_key = f"{dep_name}@{dep_version}"
        packages.append(
            {
                "key": dep_key,
                "name": str(dep_name),
                "version": dep_version,
                "is_direct": True,
                "depth": 1,
                "lock_path": f"node_modules/{dep_name}",
            }
        )
        edges.append(
            {
                "from_key": root_key,
                "to_key": dep_key,
                "required_version": str(dep_spec),
            }
        )
    if len(packages) <= 1:
        return {"ok": False, "error": "package.json has no dependencies field entries"}
    return _ok_result(packages, edges, "package_json", max_packages)


def parse_npm_lockfile(lock_text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        data = json.loads(lock_text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    raw_packages = data.get("packages")
    if not raw_packages:
        return {"ok": False, "error": "No packages field — need package-lock.json v2/v3"}

    packages: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    name_to_key: dict[str, str] = {}

    for lock_path, meta in raw_packages.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version", "")
        if not version:
            continue
        lock_path_str = str(lock_path)
        name = meta.get("name") or _lock_path_name(lock_path_str)
        if not name:
            continue
        key = f"{name}@{version}"
        is_direct = False
        if lock_path_str == "":
            is_direct = True
        elif lock_path_str.startswith("node_modules/"):
            rest = lock_path_str.removeprefix("node_modules/")
            is_direct = "/" not in rest
        depth = 0 if lock_path_str == "" else lock_path_str.count("node_modules/")
        if key not in index:
            index[key] = len(packages)
            name_to_key[str(name)] = key
            packages.append(
                {
                    "key": key,
                    "name": name,
                    "version": version,
                    "is_direct": is_direct,
                    "depth": depth,
                    "lock_path": lock_path_str,
                }
            )

    for lock_path, meta in raw_packages.items():
        if not isinstance(meta, dict):
            continue
        from_version = meta.get("version", "")
        if not from_version:
            continue
        lock_path_str = str(lock_path)
        from_name = meta.get("name") or _lock_path_name(lock_path_str)
        if not from_name:
            continue
        from_key = f"{from_name}@{from_version}"
        if from_key not in index:
            continue
        deps = meta.get("dependencies") or {}
        if not isinstance(deps, dict):
            continue
        for dep_name in deps:
            dep_str = str(dep_name)
            to_key = name_to_key.get(dep_str, "")
            if to_key:
                edges.append(
                    {
                        "from_key": from_key,
                        "to_key": to_key,
                        "required_version": str(deps[dep_name]),
                    }
                )

    return _ok_result(packages, edges, "lockfile", max_packages)


# --- PyPI ---


def _resolve_poetry_dep(name: str, name_to_keys: dict[str, list[str]]) -> str:
    keys = name_to_keys.get(name, [])
    if not keys:
        return ""
    return keys[0]


def parse_poetry_lock(text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid poetry.lock JSON: {exc}"}
    entries = data.get("package")
    if not isinstance(entries, list) or not entries:
        return {"ok": False, "error": "poetry.lock has no package array"}

    packages: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    name_to_keys: dict[str, list[str]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        version = str(entry.get("version", "")).strip()
        if not name or not version:
            continue
        category = str(entry.get("category", "main"))
        is_direct = category == "main" and not entry.get("optional", False)
        depth = 0 if is_direct and len(packages) == 0 else (1 if is_direct else 2)
        key = f"{name}@{version}"
        packages.append(
            {
                "key": key,
                "name": name,
                "version": version,
                "is_direct": is_direct,
                "depth": depth,
                "lock_path": name,
            }
        )
        name_to_keys.setdefault(name, []).append(key)

    if not packages:
        return {"ok": False, "error": "poetry.lock contained no packages"}

    root = packages[0]
    root_key = str(root["key"])
    root["depth"] = 0
    root["is_direct"] = True

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        from_name = str(entry.get("name", ""))
        from_version = str(entry.get("version", ""))
        from_key = f"{from_name}@{from_version}"
        deps = entry.get("dependencies") or {}
        if not isinstance(deps, dict):
            continue
        for dep_name in deps:
            to_key = _resolve_poetry_dep(str(dep_name), name_to_keys)
            if to_key and to_key != from_key:
                edges.append(
                    {
                        "from_key": from_key,
                        "to_key": to_key,
                        "required_version": str(deps[dep_name]),
                    }
                )

    if not edges:
        for pkg in packages[1:]:
            if pkg.get("is_direct"):
                edges.append(
                    {
                        "from_key": root_key,
                        "to_key": str(pkg["key"]),
                        "required_version": str(pkg["version"]),
                    }
                )

    return _ok_result(packages, edges, "poetry_lock", max_packages)


def parse_pipfile_lock(text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid Pipfile.lock JSON: {exc}"}

    section = data.get("default") or data.get("develop")
    if not isinstance(section, dict) or not section:
        return {"ok": False, "error": "Pipfile.lock missing default/develop section"}

    root_name = "project"
    root_version = "0.0.0"
    root_key = f"{root_name}@{root_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": root_name,
            "version": root_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []

    for dep_name, meta in section.items():
        if not isinstance(meta, dict):
            continue
        version_raw = str(meta.get("version", ""))
        version = _normalize_version_spec(version_raw) or version_raw.strip("=")
        if not version:
            continue
        dep_key = f"{dep_name}@{version}"
        packages.append(
            {
                "key": dep_key,
                "name": str(dep_name),
                "version": version,
                "is_direct": True,
                "depth": 1,
                "lock_path": str(dep_name),
            }
        )
        edges.append(
            {
                "from_key": root_key,
                "to_key": dep_key,
                "required_version": version_raw,
            }
        )

    if len(packages) <= 1:
        return {"ok": False, "error": "Pipfile.lock default section is empty"}
    return _ok_result(packages, edges, "pipfile_lock", max_packages)


def _parse_pep508_name_version(spec: str) -> tuple[str, str]:
    raw = str(spec).strip().strip('"').strip("'")
    if not raw:
        return "", ""
    if ";" in raw:
        raw = raw.split(";", 1)[0].strip()
    if "[" in raw:
        raw = raw.split("[", 1)[0].strip()
    name = raw
    version = ""
    for op in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if op in raw:
            name, version = raw.split(op, 1)
            name = name.strip()
            version = version.strip()
            break
    if "," in version:
        version = version.split(",", 1)[0].strip()
    version = _normalize_version_spec(version) or (version if version else "0.0.0")
    return name, version


def parse_pyproject_toml(text: str, max_packages: int = 300) -> dict[str, Any]:
    import tomllib

    try:
        data = tomllib.loads(text)
    except Exception as exc:
        return {"ok": False, "error": f"Invalid pyproject.toml: {exc}"}

    project = data.get("project")
    if not isinstance(project, dict):
        return {"ok": False, "error": "pyproject.toml missing [project] table"}

    root_name = str(project.get("name", "project"))
    root_version = str(project.get("version", "0.0.0"))
    if not root_version or root_version == "dynamic":
        root_version = "0.0.0"
    root_key = f"{root_name}@{root_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": root_name,
            "version": root_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []

    deps = project.get("dependencies") or []
    if not isinstance(deps, list):
        deps = []

    for dep_spec in deps:
        dep_name, dep_version = _parse_pep508_name_version(str(dep_spec))
        if not dep_name:
            continue
        dep_key = f"{dep_name}@{dep_version}"
        packages.append(
            {
                "key": dep_key,
                "name": dep_name,
                "version": dep_version,
                "is_direct": True,
                "depth": 1,
                "lock_path": dep_name,
            }
        )
        edges.append(
            {
                "from_key": root_key,
                "to_key": dep_key,
                "required_version": str(dep_spec),
            }
        )

    if len(packages) <= 1:
        return {"ok": False, "error": "pyproject.toml [project] has no dependencies"}
    return _ok_result(packages, edges, "pyproject_toml", max_packages)


def parse_requirements_txt(text: str, max_packages: int = 300) -> dict[str, Any]:
    root_name = "project"
    root_version = "0.0.0"
    root_key = f"{root_name}@{root_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": root_name,
            "version": root_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []
    line_re = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([^\s#;]+)?",
        re.IGNORECASE,
    )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        dep_name = m.group(1)
        dep_version = _normalize_version_spec(m.group(2) or "") or "0.0.0"
        dep_key = f"{dep_name}@{dep_version}"
        packages.append(
            {
                "key": dep_key,
                "name": dep_name,
                "version": dep_version,
                "is_direct": True,
                "depth": 1,
                "lock_path": dep_name,
            }
        )
        edges.append(
            {
                "from_key": root_key,
                "to_key": dep_key,
                "required_version": line,
            }
        )

    if len(packages) <= 1:
        return {"ok": False, "error": "requirements.txt has no parseable dependencies"}
    return _ok_result(packages, edges, "requirements_txt", max_packages)


# --- Go ---


def parse_go_mod(text: str, max_packages: int = 300) -> dict[str, Any]:
    module_name = "module"
    module_version = "0.0.0"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            module_name = stripped.split(None, 1)[1].strip()
            break

    root_key = f"{module_name}@{module_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": module_name,
            "version": module_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []

    require_block = False
    req_re = re.compile(
        r"^([^\s]+)\s+(v[\d.]+[^\s]*)\s*(//\s*indirect)?",
    )
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            require_block = True
            continue
        if require_block:
            if stripped == ")":
                require_block = False
                continue
            m = req_re.match(stripped)
            if not m:
                continue
            mod_path = m.group(1)
            mod_ver = m.group(2)
            indirect = bool(m.group(3))
            dep_key = f"{mod_path}@{mod_ver}"
            packages.append(
                {
                    "key": dep_key,
                    "name": mod_path,
                    "version": mod_ver,
                    "is_direct": not indirect,
                    "depth": 1 if not indirect else 2,
                    "lock_path": mod_path,
                }
            )
            if not indirect:
                edges.append(
                    {
                        "from_key": root_key,
                        "to_key": dep_key,
                        "required_version": mod_ver,
                    }
                )
        elif stripped.startswith("require "):
            rest = stripped[len("require ") :].strip()
            m = req_re.match(rest)
            if m:
                mod_path = m.group(1)
                mod_ver = m.group(2)
                indirect = bool(m.group(3))
                dep_key = f"{mod_path}@{mod_ver}"
                packages.append(
                    {
                        "key": dep_key,
                        "name": mod_path,
                        "version": mod_ver,
                        "is_direct": not indirect,
                        "depth": 1 if not indirect else 2,
                        "lock_path": mod_path,
                    }
                )
                if not indirect:
                    edges.append(
                        {
                            "from_key": root_key,
                            "to_key": dep_key,
                            "required_version": mod_ver,
                        }
                    )

    if len(packages) <= 1:
        return {"ok": False, "error": "go.mod has no require directives"}
    return _ok_result(packages, edges, "go_mod", max_packages)


# --- Maven / Gradle ---


def parse_gradle_lockfile(text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid gradle.lockfile JSON: {exc}"}
    deps_root = data.get("dependencies")
    if not isinstance(deps_root, dict):
        return {"ok": False, "error": "gradle.lockfile missing dependencies object"}

    root_name = "project"
    root_version = "0.0.0"
    root_key = f"{root_name}@{root_version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": root_name,
            "version": root_version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    for _config, config_deps in deps_root.items():
        if not isinstance(config_deps, dict):
            continue
        for coord, meta in config_deps.items():
            if not isinstance(meta, dict):
                continue
            group = str(meta.get("group", ""))
            artifact = str(meta.get("name", ""))
            version = str(meta.get("version", ""))
            if not group and ":" in str(coord):
                group, artifact = str(coord).split(":", 1)
            if not version:
                continue
            name = f"{group}:{artifact}" if group else str(coord)
            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                {
                    "key": key,
                    "name": name,
                    "version": version,
                    "is_direct": True,
                    "depth": 1,
                    "lock_path": str(coord),
                }
            )
            edges.append(
                {
                    "from_key": root_key,
                    "to_key": key,
                    "required_version": version,
                }
            )

    if len(packages) <= 1:
        return {"ok": False, "error": "gradle.lockfile has no locked dependencies"}
    return _ok_result(packages, edges, "gradle_lockfile", max_packages)


def _pom_ns(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[-1]
    return tag


def parse_pom_xml(text: str, max_packages: int = 300) -> dict[str, Any]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return {"ok": False, "error": f"Invalid pom.xml: {exc}"}

    def find_text(parent: ET.Element, local: str) -> str:
        for child in parent:
            if _pom_ns(child.tag) == local and child.text:
                return child.text.strip()
        return ""

    artifact = find_text(root, "artifactId") or "project"
    group = find_text(root, "groupId")
    version = find_text(root, "version") or "0.0.0"
    if not group:
        parent = root.find(".//{*}parent")
        if parent is not None:
            group = find_text(parent, "groupId")
    name = f"{group}:{artifact}" if group else artifact
    root_key = f"{name}@{version}"
    packages: list[dict[str, Any]] = [
        {
            "key": root_key,
            "name": name,
            "version": version,
            "is_direct": True,
            "depth": 0,
            "lock_path": "",
        }
    ]
    edges: list[dict[str, Any]] = []

    for dep in root.iter():
        if _pom_ns(dep.tag) != "dependency":
            continue
        dep_group = find_text(dep, "groupId")
        dep_artifact = find_text(dep, "artifactId")
        dep_version = find_text(dep, "version")
        if not dep_artifact:
            continue
        if not dep_version:
            dep_version = "0.0.0"
        dep_name = f"{dep_group}:{dep_artifact}" if dep_group else dep_artifact
        dep_key = f"{dep_name}@{dep_version}"
        packages.append(
            {
                "key": dep_key,
                "name": dep_name,
                "version": dep_version,
                "is_direct": True,
                "depth": 1,
                "lock_path": dep_name,
            }
        )
        edges.append(
            {
                "from_key": root_key,
                "to_key": dep_key,
                "required_version": dep_version,
            }
        )

    if len(packages) <= 1:
        return {"ok": False, "error": "pom.xml has no dependency entries"}
    return _ok_result(packages, edges, "pom_xml", max_packages)


def parse_manifest(
    manifest_text: str,
    ecosystem: str,
    manifest_kind: str,
    max_packages: int = 300,
) -> dict[str, Any]:
    """Dispatch parse by ecosystem + manifest_kind."""
    eco = ecosystem.lower()
    kind = manifest_kind.lower()

    if eco == "npm":
        if kind == "package_json":
            return parse_npm_package_json(manifest_text, max_packages)
        return parse_npm_lockfile(manifest_text, max_packages)

    if eco == "pypi":
        if kind == "pipfile_lock":
            return parse_pipfile_lock(manifest_text, max_packages)
        if kind == "requirements_txt":
            return parse_requirements_txt(manifest_text, max_packages)
        if kind == "pyproject_toml":
            return parse_pyproject_toml(manifest_text, max_packages)
        return parse_poetry_lock(manifest_text, max_packages)

    if eco == "go":
        return parse_go_mod(manifest_text, max_packages)

    if eco == "maven":
        if kind == "pom_xml":
            return parse_pom_xml(manifest_text, max_packages)
        return parse_gradle_lockfile(manifest_text, max_packages)

    return {"ok": False, "error": f"Unsupported ecosystem: {ecosystem}"}
