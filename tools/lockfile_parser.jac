"""Deterministic npm package-lock.json parser (lockfile v2/v3)."""

sem parse_npm_lockfile = "Parse package-lock JSON into packages and dependency edges.";

def _lock_path_name(lock_path: str) -> str {
    if lock_path == "" {
        return "";
    }
    if lock_path.startswith("node_modules/") {
        return lock_path.split("node_modules/")[-1];
    }
    return lock_path;
}

def parse_npm_lockfile(lock_text: str) -> dict {
    import json;

    try {
        data = json.loads(lock_text);
    } except Exception as e {
        return {"ok": False, "error": f"Invalid JSON: {e}"};
    }
    raw_packages = data.get("packages", {});
    if not raw_packages {
        return {
            "ok": False,
            "error": "No packages field — need package-lock.json v2/v3"
        };
    }

    packages: list[dict] = [];
    edges: list[dict] = [];
    index: dict = {};

    for lock_path in raw_packages {
        lock_path_str: str = str(lock_path);
        meta = raw_packages[lock_path];
        if not isinstance(meta, dict) {
            continue;
        }
        version = meta.get("version", "");
        if not version {
            continue;
        }
        name = meta.get("name", _lock_path_name(lock_path_str));
        if not name {
            continue;
        }
        key = f"{name}@{version}";
        is_direct = False;
        if lock_path_str == "" {
            is_direct = True;
        } elif lock_path_str.startswith("node_modules/") {
            rest: str = str(lock_path_str.removeprefix("node_modules/"));
            is_direct = "/" not in rest;
        }
        depth = 0;
        if lock_path_str != "" {
            depth = lock_path_str.count("node_modules/");
        }
        if key not in index {
            index[key] = len(packages);
            packages.append(
                {
                    "key": key,
                    "name": name,
                    "version": version,
                    "is_direct": is_direct,
                    "depth": depth,
                    "lock_path": lock_path_str
                }
            );
        }
    }

    for lock_path in raw_packages {
        lock_path_str: str = str(lock_path);
        meta = raw_packages[lock_path];
        if not isinstance(meta, dict) {
            continue;
        }
        from_version = meta.get("version", "");
        if not from_version {
            continue;
        }
        from_name = meta.get("name", _lock_path_name(lock_path_str));
        if not from_name {
            continue;
        }
        from_key = f"{from_name}@{from_version}";
        if from_key not in index {
            continue;
        }
        deps = meta.get("dependencies", {});
        if not isinstance(deps, dict) {
            continue;
        }
        dep_keys = list(deps.keys());
        for dep_name in dep_keys {
            dep_spec = deps[dep_name];
            to_key = "";
            for candidate in packages {
                if candidate["name"] == str(dep_name) {
                    to_key = candidate["key"];
                    break;
                }
            }
            if not to_key {
                continue;
            }
            edges.append(
                {
                    "from_key": from_key,
                    "to_key": to_key,
                    "required_version": str(dep_spec)
                }
            );
        }
    }

    return {
        "ok": True,
        "packages": packages,
        "edges": edges,
        "package_count": len(packages)
    };
}
