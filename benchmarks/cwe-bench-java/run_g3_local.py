#!/usr/bin/env python3
"""Run and score the frozen G3 Java development repositories without an external LLM.

The scorer uses CWE-Bench-Java's manually vetted fix_info.csv.  A finding is a
method-level hit when its sink line is inside a fixed method (or the fixed class
interval when the upstream row has no method interval) and its CWE matches the
project CWE.  Raw findings are retained so alternative aggregation is possible.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402
from scanops.core.graph_spec_prod import (  # noqa: E402
    base_spec_text,
    sanitizer_spec_text,
    source_mode,
)


def norm_cwe(value: str) -> str:
    try:
        return f"CWE-{int(value.upper().replace('CWE-', ''))}"
    except (AttributeError, ValueError):
        return value.upper()


def java_files(repo: Path) -> list[dict]:
    ignored = {".git", "target", "build", ".gradle", ".idea"}
    return [
        {"path": str(path.relative_to(repo)), "content": path.read_text(errors="replace")}
        for path in sorted(repo.rglob("*.java"))
        if not any(part in ignored for part in path.parts)
    ]


def truth() -> tuple[dict[str, str], dict[str, list[dict]]]:
    projects = {}
    with (UPSTREAM / "data" / "project_info.csv").open(newline="") as fp:
        for row in csv.DictReader(fp):
            projects[row["project_slug"]] = norm_cwe(row["cwe_id"])
    fixes: dict[str, list[dict]] = defaultdict(list)
    with (UPSTREAM / "data" / "fix_info.csv").open(newline="") as fp:
        for row in csv.DictReader(fp):
            start = row["method_start"] or row["class_start"]
            end = row["method_end"] or row["class_end"]
            if not start or not end:
                continue
            unit = {
                "file": row["file"], "class": row["class"], "method": row["method"],
                "signature": row["signature"], "start": int(start), "end": int(end),
            }
            if unit not in fixes[row["project_slug"]]:
                fixes[row["project_slug"]].append(unit)
    return projects, fixes


def score_project(slug: str, expected_cwe: str, units: list[dict], findings: list[dict]) -> dict:
    active = [f for f in findings if not f.get("sanitized")]
    matched_units: set[int] = set()
    false_alerts = []
    target_false_alerts = []
    unrelated_cwe_alerts = []
    for finding in active:
        if norm_cwe(finding.get("cwe", "")) != expected_cwe:
            unrelated_cwe_alerts.append(finding)
            false_alerts.append(finding)
            continue
        matches = [i for i, unit in enumerate(units)
                   if finding.get("file") == unit["file"]
                   and unit["start"] <= int(finding.get("line") or -1) <= unit["end"]
                   ]
        if matches:
            matched_units.update(matches)
        else:
            false_alerts.append(finding)
            target_false_alerts.append(finding)
    tp, fn, fp = len(matched_units), len(units) - len(matched_units), len(false_alerts)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "expected_cwe": expected_cwe, "truth_units": units,
        "matched_truth_unit_indexes": sorted(matched_units),
        "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1,
        "target_cwe_fp": len(target_false_alerts),
        "unrelated_cwe_alerts": len(unrelated_cwe_alerts),
        "project_detected": bool(matched_units), "n_active_findings": len(active),
        "false_alerts": false_alerts, "target_cwe_false_alerts": target_false_alerts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--project", action="append",
                        help="Run only this frozen development project slug (repeatable).")
    parser.add_argument("--dynamic-spec", type=Path,
                        help="Optional already-generated TSV; never invokes an external model.")
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    selected = json.loads((HERE / "development_repos.json").read_text())["projects"]
    if args.project:
        unknown = sorted(set(args.project) - set(selected))
        if unknown:
            raise SystemExit(f"project is not in frozen G3 development set: {unknown}")
        selected = [slug for slug in selected if slug in set(args.project)]
    project_cwes, fixes = truth()
    spec = base_spec_text("JAVASRC").rstrip() + "\n"
    if args.dynamic_spec:
        spec += args.dynamic_spec.read_text().rstrip() + "\n"
    runs = []
    for index, slug in enumerate(selected, 1):
        files = java_files(UPSTREAM / "project-sources" / slug)
        result = run_repo_script(
            f"g3-local-{index}", "taint", "Java", files, spec_text=spec,
            san_text=sanitizer_spec_text("JAVASRC"), src_mode=source_mode("JAVASRC"),
            arm="S2C", timeout=1200,
        )
        data = result.get("data") or {}
        findings = data.get("findings") or []
        scored = score_project(slug, project_cwes[slug], fixes[slug], findings)
        runs.append({
            "project_slug": slug, "n_java_files": len(files), "runner": {
                "rc": result.get("rc"), "elapsed": result.get("elapsed"),
                "timed_out": result.get("timed_out"), "error": data.get("error"),
                "rule_errors": data.get("rule_errors"),
            }, "score": scored, "raw_findings": findings,
        })
        print(json.dumps({"project_slug": slug, **{k: scored[k] for k in
              ("tp", "fp", "fn", "precision", "recall", "f1", "project_detected")}},
              ensure_ascii=False))
    tp = sum(x["score"]["tp"] for x in runs)
    fp = sum(x["score"]["fp"] for x in runs)
    target_fp = sum(x["score"]["target_cwe_fp"] for x in runs)
    fn = sum(x["score"]["fn"] for x in runs)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    summary = {
        "schema": "scanops.cwe-bench-java.g3.v1", "engine": "fixed-java-cpg",
        "external_llm_invoked": False, "src_mode": source_mode("JAVASRC"),
        "project_recall": sum(x["score"]["project_detected"] for x in runs) / len(runs),
        "method_metrics": {"tp": tp, "fp": fp, "fn": fn, "precision": precision,
                           "recall": recall,
                           "f1": 2 * precision * recall / (precision + recall)
                           if precision + recall else 0.0},
        "target_cwe_method_metrics": {
            "tp": tp, "fp": target_fp, "fn": fn,
            "precision": tp / (tp + target_fp) if tp + target_fp else 0.0,
            "recall": recall,
            "f1": (2 * (tp / (tp + target_fp)) * recall /
                   ((tp / (tp + target_fp)) + recall))
                  if tp + target_fp and (tp / (tp + target_fp)) + recall else 0.0,
        },
        "alert_burden": {
            "active_findings": sum(x["score"]["n_active_findings"] for x in runs),
            "unrelated_cwe_alerts": sum(x["score"]["unrelated_cwe_alerts"] for x in runs),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "runs": runs}, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
