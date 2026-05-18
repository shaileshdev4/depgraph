"""Classify package usage from GitHub import file paths (deterministic, no LLM)."""

def classify_usage_from_paths(
    package_name: str,
    importing_files: list[str]
) -> dict {
    import re;

    TEST_PATTERNS = [
        r"[/\\]test[s]?[/\\]",
        r"[/\\]spec[s]?[/\\]",
        r"[/\\]__tests__[/\\]",
        r"\.test\.[jt]sx?$",
        r"\.spec\.[jt]sx?$",
        r"[/\\]e2e[/\\]",
        r"[/\\]cypress[/\\]",
        r"[/\\]jest[/\\]",
        r"[/\\]mocha[/\\]",
    ];

    BUILD_PATTERNS = [
        r"[/\\]scripts[/\\]",
        r"webpack\.config",
        r"rollup\.config",
        r"vite\.config",
        r"babel\.config",
        r"\.eslintrc",
        r"jest\.config",
        r"[/\\]build[/\\]",
        r"[/\\]dist[/\\]",
    ];

    if not importing_files {
        return {
            "surface": "unknown",
            "is_prod": False,
            "importing_file_count": 0,
            "importing_files": [],
        };
    }

    test_count = 0;
    build_count = 0;
    prod_count = 0;

    for path in importing_files {
        is_test = False;
        is_build = False;
        for pattern in TEST_PATTERNS {
            if re.search(pattern, path, re.IGNORECASE) {
                is_test = True;
                break;
            }
        }
        if not is_test {
            for pattern in BUILD_PATTERNS {
                if re.search(pattern, path, re.IGNORECASE) {
                    is_build = True;
                    break;
                }
            }
        }
        if is_test {
            test_count += 1;
        } elif is_build {
            build_count += 1;
        } else {
            prod_count += 1;
        }
    }

    total = len(importing_files);

    if prod_count > 0 {
        surface = "production";
        is_prod = True;
    } elif build_count > 0 and test_count == 0 {
        surface = "build";
        is_prod = False;
    } elif test_count > 0 and prod_count == 0 {
        surface = "test";
        is_prod = False;
    } else {
        surface = "mixed";
        is_prod = prod_count > 0;
    }

    return {
        "surface": surface,
        "is_prod": is_prod,
        "importing_file_count": total,
        "importing_files": importing_files[0:6],
        "prod_count": prod_count,
        "test_count": test_count,
        "build_count": build_count,
    };
}
