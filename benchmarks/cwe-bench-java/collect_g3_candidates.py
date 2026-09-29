#!/usr/bin/env python3
"""Collect full-repository Java CPG candidates for the three frozen G3 development repos."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402


def java_files(repo: Path) -> list[dict]:
    ignored = {".git", "target", "build", ".gradle", ".idea"}
    result = []
    for path in sorted(repo.rglob("*.java")):
        if any(part in ignored for part in path.parts):
            continue
        result.append({"path": str(path.relative_to(repo)), "content": path.read_text(errors="replace")})
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    slugs = json.loads((HERE / "development_repos.json").read_text())["projects"]
    results = []
    for index, slug in enumerate(slugs, 1):
        files = java_files(UPSTREAM / "project-sources" / slug)
        run = run_repo_script(f"g3-candidates-{index}", "candidates", "Java", files, timeout=900)
        data = run.get("data") or {}
        results.append({
            "project_slug": slug, "n_java_files": len(files),
            "n_call_candidates": data.get("n_call_candidates"),
            "n_assign_candidates": data.get("n_assign_candidates"),
            "n_items": (data.get("n_call_candidates") or 0) + (data.get("n_assign_candidates") or 0),
            "elapsed": run.get("elapsed"), "rc": run.get("rc"),
            "timed_out": run.get("timed_out"), "error": data.get("error"),
            "data": data,
        })
        print(json.dumps({k: results[-1][k] for k in (
            "project_slug", "n_java_files", "n_items", "elapsed", "rc")}, ensure_ascii=False))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
