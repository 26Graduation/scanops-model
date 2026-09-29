#!/usr/bin/env python3
"""Generate per-repository Qwen3.8-Max rules and run the G3 Java CPG gate.

The runner consumes the already collected Joern candidates so candidate extraction is not repeated.
Every external prompt/response is appended before CPG scoring. It deliberately bypasses the product
cache to make the experiment self-contained and reproducible.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
for line in (ROOT / ".env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
os.environ["GRAPH_SPEC_LLM_MODEL"] = "qwen3.8-max"
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402
from scanops.core import graph_spec_prod as graph  # noqa: E402
from run_g3_local import java_files, score_project, truth  # noqa: E402


def metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall)
            if precision + recall else 0.0}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    run_dir = args.out.with_suffix("")
    raw_path = run_dir / "raw_rulegen.jsonl"
    if args.out.exists() or (run_dir.exists() and not args.resume):
        raise SystemExit("refusing to overwrite an existing run artifact")
    run_dir.mkdir(parents=True, exist_ok=args.resume)
    graph.RULEGEN_BATCH = args.batch_size
    graph.LLM_MAX_WORKERS = args.workers

    candidate_runs = json.loads(args.candidates.read_text())
    project_cwes, fixes = truth()
    original_call = graph.call_rulegen
    lock = threading.Lock()
    current = {"project_slug": ""}

    def recorded_call(system: str, user: str, n_predict: int) -> str:
        started = time.time()
        response, error = "", ""
        try:
            response = original_call(system, user, n_predict)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        record = {"project_slug": current["project_slug"], "model": graph.LLM_MODEL,
                  "n_predict": n_predict, "elapsed": round(time.time() - started, 3),
                  "system_prompt": system, "user_prompt": user, "response": response,
                  "error": error}
        with lock, raw_path.open("a") as fp:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")
        if error:
            raise RuntimeError(error)
        return response

    graph.call_rulegen = recorded_call
    started = time.time()
    runs = []
    for index, candidate_run in enumerate(candidate_runs, 1):
        slug = candidate_run["project_slug"]
        checkpoint = run_dir / f"{index:02d}_{slug}_run.json"
        if args.resume and checkpoint.exists():
            runs.append(json.loads(checkpoint.read_text()))
            print(json.dumps({"project_slug": slug, "resumed": True}, ensure_ascii=False),
                  flush=True)
            continue
        current["project_slug"] = slug
        files = java_files(HERE / "upstream" / "project-sources" / slug)
        items = graph.build_items(candidate_run["data"], "JAVASRC", files)
        labeled = graph.label_items(items, "Java")
        valid = graph.validate(labeled, graph.repo_path_tokens_from_files(files))
        dynamic_spec = graph.to_tsv(valid)
        spec_path = run_dir / f"{index:02d}_{slug}_dynamic.tsv"
        spec_path.write_text(dynamic_spec)
        spec = graph.base_spec_text("JAVASRC").rstrip() + "\n" + dynamic_spec
        result = run_repo_script(
            f"g3-dynamic-{index}", "taint", "Java", files, spec_text=spec,
            san_text=graph.sanitizer_spec_text("JAVASRC"),
            src_mode=graph.source_mode("JAVASRC"), arm="S2C", timeout=1200)
        data = result.get("data") or {}
        findings = data.get("findings") or []
        scored = score_project(slug, project_cwes[slug], fixes[slug], findings)
        run = {"project_slug": slug, "n_java_files": len(files),
               "candidate_count_before": candidate_run.get("n_items"),
               "candidate_count_after": len(items), "returned_labels": len(labeled),
               "valid_labels": len(valid), "dynamic_rule_rows": len(dynamic_spec.splitlines()),
               "runner": {"rc": result.get("rc"), "elapsed": result.get("elapsed"),
                          "timed_out": result.get("timed_out"), "error": data.get("error"),
                          "rule_errors": data.get("rule_errors")},
               "score": scored, "raw_findings": findings}
        checkpoint.write_text(json.dumps(run, ensure_ascii=False, indent=2))
        runs.append(run)
        print(json.dumps({k: run[k] for k in ("project_slug", "candidate_count_after",
                                               "returned_labels", "valid_labels",
                                               "dynamic_rule_rows")}, ensure_ascii=False), flush=True)

    tp = sum(run["score"]["tp"] for run in runs)
    fp = sum(run["score"]["fp"] for run in runs)
    target_fp = sum(run["score"]["target_cwe_fp"] for run in runs)
    fn = sum(run["score"]["fn"] for run in runs)
    summary = {"schema": "scanops.cwe-bench-java.g3-dynamic-qwen38.v1",
               "model": graph.LLM_MODEL, "batch_size": args.batch_size,
               "workers": args.workers, "external_code_transfer": True,
               "elapsed": round(time.time() - started, 3),
               "candidate_count_after_prefilter": sum(r["candidate_count_after"] for r in runs),
               "method_metrics": metrics(tp, fp, fn),
               "target_cwe_method_metrics": metrics(tp, target_fp, fn),
               "project_recall": sum(r["score"]["project_detected"] for r in runs) / len(runs),
               "active_findings": sum(r["score"]["n_active_findings"] for r in runs)}
    args.out.write_text(json.dumps({"summary": summary, "runs": runs},
                                   ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
