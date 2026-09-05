#!/usr/bin/env python3
"""Evaluate the deployed local Qwen classifier on frozen G3 Java repositories.

All main-source Java files are scanned.  Files listed by CWE-Bench-Java's vetted
fix_info are positives; other main-source files are negatives (and may contain
unlabelled unrelated issues, so both raw records and this limitation are retained).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
sys.path.insert(0, str(ROOT / "rebuild"))
from bench_common import parse  # noqa: E402
from repo_bench_scan import CHATML_TMPL, MAX_CODE, PROMPT_TMPL, chunks, prompt_hash  # noqa: E402


def norm_cwe(value: str) -> str:
    try:
        return f"CWE-{int(value.upper().replace('CWE-', ''))}"
    except (AttributeError, ValueError):
        return value.upper()


def inventory(slug: str) -> tuple[list[tuple[str, str]], set[str], str]:
    repo = UPSTREAM / "project-sources" / slug
    files = []
    for path in sorted(repo.rglob("*.java")):
        rel = path.relative_to(repo)
        if any(part in {".git", "target", "build", ".gradle", "test", "tests", "generated"}
               for part in rel.parts):
            continue
        files.append((str(rel), path.read_text(errors="replace")))
    positives = set()
    with (UPSTREAM / "data" / "fix_info.csv").open(newline="") as fp:
        for row in csv.DictReader(fp):
            if row["project_slug"] == slug and "/test/" not in row["file"]:
                positives.add(row["file"])
    expected = ""
    with (UPSTREAM / "data" / "project_info.csv").open(newline="") as fp:
        for row in csv.DictReader(fp):
            if row["project_slug"] == slug:
                expected = norm_cwe(row["cwe_id"])
                break
    return files, positives, expected


def metrics(rows: list[dict], exact: bool) -> dict:
    def pred(row: dict) -> bool:
        return row["label"] == "vuln" and (not exact or norm_cwe(row["cwe"]) == row["expected_cwe"])
    tp = sum(row["truth"] and pred(row) for row in rows)
    fp = sum(not row["truth"] and pred(row) for row in rows)
    fn = sum(row["truth"] and not pred(row) for row in rows)
    tn = sum(not row["truth"] and not pred(row) for row in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": 2 * precision * recall / (precision + recall)
            if precision + recall else 0.0}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--checkpoint", type=Path,
                        help="Append-only JSONL checkpoint (default: OUT with .jsonl suffix).")
    parser.add_argument("--summarize-only", action="store_true",
                        help="Score the existing checkpoint without issuing model requests.")
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    slugs = json.loads((HERE / "development_repos.json").read_text())["projects"]
    checkpoint = args.checkpoint or args.out.with_suffix(".jsonl")
    prior = []
    if checkpoint.exists():
        prior = [json.loads(line) for line in checkpoint.read_text().splitlines() if line.strip()]
    done = {(row["project_slug"], row["file"]) for row in prior}
    work = []
    for slug in slugs:
        files, positives, expected = inventory(slug)
        for rel, code in files:
            if (slug, rel) not in done:
                work.append((slug, rel, code, rel in positives, expected))
    # Development-gate fail-fast: establish recall on the scarce labelled positives
    # before spending hours on the much larger negative inventory.  Final metrics are
    # order-independent and the append-only checkpoint makes the run resumable.
    work.sort(key=lambda item: (not item[3], item[0], item[1]))
    expected_files = len(prior) + len(work)

    def classify(item: tuple) -> dict:
        slug, rel, code, truth, expected = item
        t0 = time.time()
        raws, labels = [], []
        for part in chunks(code):
            prompt = PROMPT_TMPL.format(language="Java", code=part[:MAX_CODE])
            response = requests.post(f"{args.url}/completion", json={
                "prompt": CHATML_TMPL.format(p=prompt), "n_predict": 200,
                "temperature": 0.0, "stop": ["<|im_end|>"],
            }, timeout=900)
            response.raise_for_status()
            raw = response.json().get("content", "")
            raws.append(raw)
            labels.append(parse(raw))
        vulnerable = [x for x in labels if x["label"] == "vuln"]
        label = "vuln" if vulnerable else ("parse_fail" if all(
            x["label"] == "parse_fail" for x in labels) else "safe")
        return {"project_slug": slug, "file": rel, "truth": truth,
                "expected_cwe": expected, "label": label,
                "cwe": vulnerable[0]["cwe"] if vulnerable else "",
                "chunks": len(labels), "raws": raws,
                "elapsed": round(time.time() - t0, 3)}

    rows = list(prior)
    started = time.time()
    if not args.summarize_only:
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        with checkpoint.open("a") as log, ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(classify, item) for item in work]
            for index, future in enumerate(as_completed(futures), 1):
                row = future.result()
                rows.append(row)
                log.write(json.dumps(row, ensure_ascii=False) + "\n")
                log.flush()
                if index % 10 == 0:
                    print(f"{index}/{len(work)} new files ({len(rows)} total), "
                          f"{time.time() - started:.1f}s", flush=True)
    summary = {
        "schema": "scanops.cwe-bench-java.g3-llm.v1",
        "model": "Qwen3.5-9B-Q4_K_M + adapter_v1_fix", "external_transfer": False,
        "prompt_sha256_16": prompt_hash(), "n_files": len(rows),
        "n_expected_files": expected_files, "complete": len(rows) == expected_files,
        "n_truth_files": sum(x["truth"] for x in rows),
        "binary": metrics(rows, exact=False), "exact_cwe": metrics(rows, exact=True),
        "parse_failures": sum(x["label"] == "parse_fail" for x in rows),
        "elapsed_this_run": round(time.time() - started, 3),
        "checkpoint": str(checkpoint),
        "label_caveat": "non-fix main files are treated as negative and may contain unrelated unlabeled flaws",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
