"""Smoke tests for manifest parsers (run: python -m tools.test_manifest_parsers)."""

from __future__ import annotations

import json
import sys

from tools.manifest_parsers import (
    parse_go_mod,
    parse_gradle_lockfile,
    parse_npm_package_json,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)


def _assert_ok(result: dict, min_packages: int = 2) -> None:
    assert result.get("ok"), result.get("error", result)
    assert result["package_count"] >= min_packages


def test_npm_package_json() -> None:
    sample = json.dumps(
        {
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21", "axios": "1.6.0"},
        }
    )
    _assert_ok(parse_npm_package_json(sample))


def test_poetry_lock() -> None:
    sample = json.dumps(
        {
            "package": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "category": "main",
                    "dependencies": {"urllib3": ">=1.21.1,<3"},
                },
                {
                    "name": "urllib3",
                    "version": "2.0.7",
                    "category": "main",
                },
            ]
        }
    )
    _assert_ok(parse_poetry_lock(sample))


def test_requirements_txt() -> None:
    sample = "flask==3.0.0\nrequests>=2.28\n"
    _assert_ok(parse_requirements_txt(sample))


def test_go_mod() -> None:
    sample = """module github.com/example/demo

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/net v0.10.0 // indirect
)
"""
    _assert_ok(parse_go_mod(sample))


def test_pyproject_toml() -> None:
    sample = """
[project]
name = "requests"
dependencies = [
  "charset_normalizer>=2,<4",
  "urllib3>=1.26,<3",
]
"""
    _assert_ok(parse_pyproject_toml(sample))


def test_gradle_lockfile() -> None:
    sample = json.dumps(
        {
            "version": "1.2",
            "dependencies": {
                "compileClasspath": {
                    "org.springframework:spring-core": {
                        "group": "org.springframework",
                        "name": "spring-core",
                        "version": "6.1.0",
                        "locked": True,
                    }
                }
            },
        }
    )
    _assert_ok(parse_gradle_lockfile(sample))


def main() -> int:
    tests = [
        test_npm_package_json,
        test_poetry_lock,
        test_pyproject_toml,
        test_requirements_txt,
        test_go_mod,
        test_gradle_lockfile,
    ]
    for fn in tests:
        fn()
        print(f"ok: {fn.__name__}")
    print(f"All {len(tests)} parser smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
