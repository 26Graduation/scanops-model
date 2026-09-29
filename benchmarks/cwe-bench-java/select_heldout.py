#!/usr/bin/env python3
"""Freeze a deterministic 12-project held-out before running any model."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
SEED = "scanops-java-heldout-v1-2026-09-05"
PER_CWE = 3


def main() -> None:
    output = HERE / "heldout_v1.json"
    if output.exists():
        raise SystemExit(f"refusing to overwrite frozen split: {output}")
    rows = list(csv.DictReader((UPSTREAM / "data" / "project_info.csv").open()))
    dev_slugs = set(json.loads((HERE / "development_repos.json").read_text())["projects"])
    dev_urls = {r["github_url"] for r in rows if r["project_slug"] in dev_slugs}
    selected = []
    for cwe in ("CWE-022", "CWE-078", "CWE-079", "CWE-094"):
        pool = [r for r in rows if r["cwe_id"] == cwe and r["github_url"] not in dev_urls]
        pool.sort(key=lambda r: hashlib.sha256(
            f"{SEED}:{r['project_slug']}".encode()).hexdigest())
        selected.extend(pool[:PER_CWE])
    commit = subprocess.check_output(
        ["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"], text=True).strip()
    result = {
        "dataset": "iris-sast/cwe-bench-java",
        "upstream_commit": commit,
        "seed": SEED,
        "selection": "lowest SHA256(seed:project_slug), 3 per original benchmark CWE",
        "development_repository_urls_excluded": sorted(dev_urls),
        "projects": [{k: r[k] for k in (
            "project_slug", "cve_id", "cwe_id", "github_url", "buggy_commit_id")}
                     for r in selected],
    }
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
