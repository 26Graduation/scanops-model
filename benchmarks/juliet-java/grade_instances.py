#!/usr/bin/env python3
"""Grade Juliet at (file, enclosing method, CWE) vulnerability-instance granularity."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from grade_all import DIRS, ORDER
from grade_juliet import extract_ground_truth, find_methods, mask_java

BASE = Path(__file__).resolve().parent
TESTCASES = BASE / "juliet-source" / "src" / "testcases"


def enclosing_method(methods: list[tuple[str, int, int]], line: int) -> str | None:
    matches = [m for m in methods if m[1] <= line <= m[2]]
    if not matches:
        return None
    return min(matches, key=lambda m: m[2] - m[1])[0]


def grade_cwe(cwe: int, out_dir: Path, exclude_sanitized: bool) -> dict:
    cwe_id = f"CWE-{cwe}"
    source_dir = TESTCASES / DIRS[cwe]
    data = json.loads((out_dir / f"cwe{cwe}.json").read_text())
    findings = [x for x in data.get("findings", [])
                if x.get("cwe") == cwe_id and os.path.basename(x.get("file", "")) != "Main.java"]
    if exclude_sanitized:
        findings = [x for x in findings if not x.get("sanitized")]

    gt_instances: set[tuple[str, str, str]] = set()
    finding_instances: set[tuple[str, str, str]] = set()
    warnings = []
    method_cache: dict[str, list[tuple[str, int, int]]] = {}

    for java_file in source_dir.rglob("*.java"):
        rel = str(java_file.relative_to(source_dir))
        source = java_file.read_text(errors="replace")
        methods = find_methods(mask_java(source))
        method_cache[rel] = methods
        for line, _cwe, _marker in extract_ground_truth(str(java_file), cwe_id, warnings):
            method = enclosing_method(methods, line)
            if method:
                gt_instances.add((rel, method, cwe_id))

    unmapped_findings = 0
    for finding in findings:
        rel = finding.get("file", "")
        method = enclosing_method(method_cache.get(rel, []), int(finding.get("line") or -1))
        if method is None:
            method = f"<unmapped-line:{finding.get('line')}>"
            unmapped_findings += 1
        finding_instances.add((rel, method, cwe_id))

    tp_set = gt_instances & finding_instances
    fp_set = finding_instances - gt_instances
    fn_set = gt_instances - finding_instances
    tp, fp, fn = len(tp_set), len(fp_set), len(fn_set)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cwe": cwe_id, "gt_instances": len(gt_instances),
        "raw_findings": len(findings), "finding_instances": len(finding_instances),
        "duplicates_collapsed": len(findings) - len(finding_instances),
        "unmapped_findings": unmapped_findings,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "fp_examples": [list(x) for x in sorted(fp_set)[:20]],
        "fn_examples": [list(x) for x in sorted(fn_set)[:20]],
        "parse_warning_count": len(warnings),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--exclude-sanitized", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [grade_cwe(cwe, args.out_dir, args.exclude_sanitized) for cwe in ORDER]
    tp, fp, fn = (sum(x[k] for x in rows) for k in ("tp", "fp", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    report = {
        "unit": "repository/file/enclosing_method/CWE",
        "exclude_sanitized": args.exclude_sanitized,
        "totals": {
            "cwes": len(rows), "gt_instances": sum(x["gt_instances"] for x in rows),
            "raw_findings": sum(x["raw_findings"] for x in rows),
            "finding_instances": sum(x["finding_instances"] for x in rows),
            "duplicates_collapsed": sum(x["duplicates_collapsed"] for x in rows),
            "unmapped_findings": sum(x["unmapped_findings"] for x in rows),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
        },
        "per_cwe": rows,
    }
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report["totals"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
