#!/usr/bin/env python3
"""Measure fixed-spec target-CWE alert persistence from buggy to final fix commits."""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402
from scanops.core.graph_spec_prod import (base_spec_text, sanitizer_spec_text,  # noqa: E402
                                           source_mode)
from run_g3_local import norm_cwe  # noqa: E402


def java_files_at(repo: Path, commit: str) -> list[dict]:
    archive = subprocess.check_output(
        ["git", "-C", str(repo), "archive", "--format=tar", commit])
    files = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
        for member in sorted(tf.getmembers(), key=lambda item: item.name):
            if not member.isfile() or not member.name.endswith(".java"):
                continue
            fp = tf.extractfile(member)
            if fp is not None:
                files.append({"path": member.name,
                              "content": fp.read().decode("utf-8", errors="replace")})
    return files


def fingerprint(finding: dict) -> tuple[str, str, str]:
    sink = re.sub(r"\s+", " ", str(finding.get("sink") or "")).strip()
    return str(finding.get("file") or ""), norm_cwe(finding.get("cwe", "")), sink


def active_target(findings: list[dict], cwe: str) -> list[dict]:
    return [finding for finding in findings
            if not finding.get("sanitized") and norm_cwe(finding.get("cwe", "")) == cwe]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--buggy-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    buggy = {run["project_slug"]: run for run in
             json.loads(args.buggy_results.read_text())["runs"]}
    info = {}
    with (UPSTREAM / "data" / "project_info.csv").open(newline="") as fp:
        for row in csv.DictReader(fp):
            if row["project_slug"] in buggy:
                info[row["project_slug"]] = row

    runs = []
    spec = base_spec_text("JAVASRC")
    for index, (slug, buggy_run) in enumerate(buggy.items(), 1):
        row = info[slug]
        cwe = norm_cwe(row["cwe_id"])
        final_fix = row["fix_commit_ids"].split(";")[-1]
        repo = UPSTREAM / "project-sources" / slug
        files = java_files_at(repo, final_fix)
        result = run_repo_script(
            f"g3-fixed-pair-{index}", "taint", "Java", files, spec_text=spec,
            san_text=sanitizer_spec_text("JAVASRC"), src_mode=source_mode("JAVASRC"),
            arm="S2C", timeout=1200)
        data = result.get("data") or {}
        before = active_target(buggy_run["raw_findings"], cwe)
        after = active_target(data.get("findings") or [], cwe)
        before_fp = {fingerprint(finding) for finding in before}
        after_fp = {fingerprint(finding) for finding in after}
        runs.append({"project_slug": slug, "cwe": cwe,
                     "buggy_commit": row["buggy_commit_id"], "final_fix_commit": final_fix,
                     "n_java_files_fixed": len(files), "buggy_target_alerts": len(before),
                     "fixed_target_alerts": len(after),
                     "exact_fingerprints_persisting": len(before_fp & after_fp),
                     "fixed_target_findings": after,
                     "runner": {"rc": result.get("rc"), "elapsed": result.get("elapsed"),
                                "timed_out": result.get("timed_out"),
                                "error": data.get("error"),
                                "rule_errors": data.get("rule_errors")}})
        print(json.dumps({k: runs[-1][k] for k in
              ("project_slug", "buggy_target_alerts", "fixed_target_alerts",
               "exact_fingerprints_persisting")}, ensure_ascii=False), flush=True)
    summary = {"schema": "scanops.cwe-bench-java.g3-buggy-fixed-pairs.v1",
               "engine": "fixed-java-cpg", "external_llm_invoked": False,
               "projects": len(runs),
               "buggy_target_alerts": sum(x["buggy_target_alerts"] for x in runs),
               "fixed_target_alerts": sum(x["fixed_target_alerts"] for x in runs),
               "projects_clean_after_fix": sum(x["fixed_target_alerts"] == 0 for x in runs),
               "exact_fingerprints_persisting": sum(
                   x["exact_fingerprints_persisting"] for x in runs)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "runs": runs},
                                   ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
