#!/usr/bin/env python3
"""Compare Java engines on the exact same frozen G3 file rows.

The reference LLM report defines the evaluated files and file-level truth.  CPG
is positive only when an unsanitized finding in that file matches the project's
expected CWE.  This avoids comparing method-level CPG scores with file-level LLM
scores, which would be an invalid table.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def norm_cwe(value: str) -> str:
    try:
        return f"CWE-{int(value.upper().replace('CWE-', ''))}"
    except (AttributeError, ValueError):
        return str(value).upper()


def metrics(truth: dict[tuple[str, str], bool], predictions: dict[tuple[str, str], bool]) -> dict:
    tp = sum(truth[k] and predictions.get(k, False) for k in truth)
    fp = sum(not truth[k] and predictions.get(k, False) for k in truth)
    fn = sum(truth[k] and not predictions.get(k, False) for k in truth)
    tn = sum(not truth[k] and not predictions.get(k, False) for k in truth)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0.0
    return {"n": len(truth), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1, "f2": f2}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpg", type=Path, required=True)
    parser.add_argument("--llm", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")

    llm_reports = [json.loads(path.read_text()) for path in args.llm]
    reference_rows = llm_reports[0]["rows"]
    keys = {(row["project_slug"], row["file"]) for row in reference_rows}
    truth = {(row["project_slug"], row["file"]): bool(row["truth"])
             for row in reference_rows}
    expected = {(row["project_slug"], row["file"]): row["expected_cwe"]
                for row in reference_rows}

    engines = []
    cpg = json.loads(args.cpg.read_text())
    cpg_binary = {key: False for key in keys}
    cpg_exact = {key: False for key in keys}
    for run in cpg["runs"]:
        slug = run["project_slug"]
        for finding in run["raw_findings"]:
            key = (slug, finding.get("file", ""))
            if key in keys and not finding.get("sanitized"):
                cpg_binary[key] = True
                if norm_cwe(finding.get("cwe", "")) == expected[key]:
                    cpg_exact[key] = True
    engines.append({"engine": "ScanOps fixed Java CPG",
                    "binary": metrics(truth, cpg_binary),
                    "exact_cwe": metrics(truth, cpg_exact), "parse_failures": 0})

    for report in llm_reports:
        rows = report["rows"]
        row_keys = {(row["project_slug"], row["file"]) for row in rows}
        if row_keys != keys:
            raise SystemExit("LLM reports do not contain the exact same file set")
        binary_pred = {(row["project_slug"], row["file"]): row["label"] == "vuln"
                       for row in rows}
        exact_pred = {(row["project_slug"], row["file"]): row["label"] == "vuln"
                and norm_cwe(row.get("cwe", "")) == row["expected_cwe"]
                for row in rows}
        engines.append({"engine": report["summary"]["model"],
                        "binary": metrics(truth, binary_pred),
                        "exact_cwe": metrics(truth, exact_pred),
                        "parse_failures": report["summary"].get("parse_failures", 0)})

    lines = [
        "# G3 Java same-file development comparison",
        "",
        "This is a 15-file fail-fast development comparison, not the frozen held-out result.",
        "All engines use both binary and exact-CWE file-level scoring on the identical six",
        "positive and nine nominal-negative main-source files. Nominal negatives may contain",
        "unlabeled issues.",
        "",
    ]
    for title, field in (("Binary vulnerability", "binary"), ("Exact CWE", "exact_cwe")):
        lines.extend([
            f"## {title}", "",
            "| engine | TP | FP | FN | TN | precision | recall | F1 | F2 | parse failures |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for row in engines:
            score = row[field]
            lines.append(
                f"| {row['engine']} | {score['tp']} | {score['fp']} | {score['fn']} | "
                f"{score['tn']} | {score['precision']:.3f} | {score['recall']:.3f} | "
                f"{score['f1']:.3f} | {score['f2']:.3f} | {row['parse_failures']} |")
        lines.append("")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")
    args.out.with_suffix(".json").write_text(json.dumps(
        {"schema": "scanops.g3-same-file-comparison.v1", "engines": engines,
         "n_positive": sum(truth.values()), "n_negative": len(truth) - sum(truth.values())},
        ensure_ascii=False, indent=2))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
