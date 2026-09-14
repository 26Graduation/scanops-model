#!/usr/bin/env python3
"""Evaluate Qwen3.8-Max as a verifier of existing G3 Java CPG paths.

This is deliberately a path-level critic, not a whole-file classifier. It uses
the frozen fixed-CPG findings, sends only the finding evidence and local context,
and preserves every raw response. Only grounded high-confidence FALSE verdicts
are allowed to suppress a finding.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
for line in (ROOT / ".env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
os.environ["GRAPH_SPEC_LLM_MODEL"] = "qwen3.8-max"
os.environ["GRAPH_SPEC_CRITIC_ENABLED"] = "on"
sys.path.insert(0, str(ROOT))

from scanops.core import graph_spec_prod as graph  # noqa: E402
from run_g3_local import java_files, score_project, truth  # noqa: E402


def aggregate(runs: list[dict]) -> dict:
    tp = sum(run["score"]["tp"] for run in runs)
    fp = sum(run["score"]["fp"] for run in runs)
    target_fp = sum(run["score"]["target_cwe_fp"] for run in runs)
    fn = sum(run["score"]["fn"] for run in runs)

    def block(false_positives: int) -> dict:
        precision = tp / (tp + false_positives) if tp + false_positives else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        return {"tp": tp, "fp": false_positives, "fn": fn, "precision": precision,
                "recall": recall,
                "f1": 2 * precision * recall / (precision + recall)
                if precision + recall else 0.0}

    return {"method_metrics": block(fp), "target_cwe_method_metrics": block(target_fp),
            "project_recall": sum(run["score"]["project_detected"] for run in runs) / len(runs),
            "active_findings": sum(run["score"]["n_active_findings"] for run in runs),
            "critic_removed": sum(run["critic_audit"]["removed"] for run in runs)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--local-url",
                        help="Use a local llama-server instead of external DashScope.")
    parser.add_argument("--model-label", default="qwen3.8-max")
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    source = json.loads(args.input.read_text())
    if args.local_url:
        import requests
        graph.LLM_MAX_WORKERS = min(graph.LLM_MAX_WORKERS, 2)

        def call_local(system: str, user: str, n_predict: int) -> str:
            prompt = (f"<|im_start|>system\n{system}<|im_end|>\n"
                      f"<|im_start|>user\n{user}<|im_end|>\n"
                      "<|im_start|>assistant\n<think>\n\n</think>\n\n")
            response = requests.post(f"{args.local_url.rstrip('/')}/completion", json={
                "prompt": prompt, "n_predict": n_predict, "temperature": 0.0,
                "stop": ["<|im_end|>"],
            }, timeout=900)
            response.raise_for_status()
            return response.json().get("content", "")

        graph.call_rulegen = call_local
    project_cwes, fixes = truth()
    started = time.time()
    runs = []
    for source_run in source["runs"]:
        slug = source_run["project_slug"]
        files = java_files(HERE / "upstream" / "project-sources" / slug)
        content_by_path = {item["path"]: item["content"] for item in files}
        reviewed, audit = graph.review_findings(
            source_run["raw_findings"], content_by_path, "Java")
        scored = score_project(slug, project_cwes[slug], fixes[slug], reviewed)
        runs.append({"project_slug": slug, "score": scored,
                     "reviewed_findings": reviewed, "critic_audit": audit})
        print(json.dumps({"project_slug": slug, "input": audit["input"],
                          "removed": audit["removed"], "tp": scored["tp"],
                          "fp": scored["fp"], "fn": scored["fn"]}, ensure_ascii=False),
              flush=True)
    summary = {"schema": "scanops.cwe-bench-java.g3-path-critic.v1",
               "model": args.model_label, "input": str(args.input),
               "external_code_transfer": not bool(args.local_url),
               "false_suppression_policy": "high confidence + shown basis line + reason",
               "elapsed": round(time.time() - started, 3), **aggregate(runs)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "runs": runs},
                                   ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
