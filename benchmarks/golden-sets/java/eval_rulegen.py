#!/usr/bin/env python3
"""Run the audited 41-item Java API-role golden set against production Qwen3.8-Max.

This evaluator deliberately sends only API identity/signature. Evidence, notes, expected labels,
and corpus paths never enter the prompt. Raw model responses are retained before scoring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmarks" / "juliet-java"))

import pilot_llm  # noqa: E402
from scanops.core import graph_spec_prod as g  # noqa: E402

ROLES = ("source", "sink", "sanitizer", "none")


def load_v2() -> list[dict]:
    base = json.loads((HERE / "rule_golden_set_v1.json").read_text())
    overlay = json.loads((HERE / "rule_golden_set_v2_overrides.json").read_text())
    entries = [dict(x) for x in base["entries"]]
    by_api = {x["api"]: x for x in entries}
    for change in overlay["overrides"]:
        api = change["api"]
        if api not in by_api:
            raise ValueError(f"unknown v2 override api: {api}")
        by_api[api].update({k: v for k, v in change.items() if k != "api"})
    if len(entries) != overlay["_meta"]["resolved_entry_count"]:
        raise ValueError("resolved golden-set size changed")
    return entries


def prompt_item(idx: int, entry: dict) -> dict:
    # v1's human-readable signatures contain label-bearing editorial text for three local
    # helpers ("NOT a real library API"). Preserve the only fact production candidates expose:
    # the method resolves inside the current repository.
    signature = entry["full_signature"]
    if signature.startswith("<locally-defined"):
        signature = f"<local>.{entry['api']}(...)"
    signature = signature.replace(" [collections context]", "")
    return {
        "id": idx,
        "kind": "call",
        "name": entry["api"],
        "fulls": [signature],
        "n": 1,
        "snippets": entry.get("snippets", []),
    }


def f1_for_role(expected: list[str], predicted: list[str], role: str) -> dict:
    tp = sum(e == role and p == role for e, p in zip(expected, predicted))
    fp = sum(e != role and p == role for e, p in zip(expected, predicted))
    fn = sum(e == role and p != role for e, p in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def run(out_dir: Path, batch_size: int, workers: int) -> dict:
    entries = load_v2()
    items = [prompt_item(i, e) for i, e in enumerate(entries)]
    batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    jobs = []
    users = []
    for bi, batch in enumerate(batches):
        body = "\n\n".join(g.fmt_item(x) for x in batch)
        user = g.RULEGEN_USER_TMPL.format(
            lang="Java", bi=bi + 1, bn=len(batches), items=body)
        users.append(user)
        jobs.append((g.RULEGEN_SYSTEM, user, 200 * len(batch)))

    raw = pilot_llm.dashscope_chat_batch(
        jobs, max_workers=workers, is_valid=lambda text: g._extract_json_array(text) is not None)
    out_dir.mkdir(parents=True, exist_ok=False)
    raw_path = out_dir / "raw_responses.jsonl"
    with raw_path.open("w") as fp:
        for bi, (user, response) in enumerate(zip(users, raw), 1):
            fp.write(json.dumps({"batch": bi, "user_prompt": user, "response": response},
                                ensure_ascii=False) + "\n")

    returned = {}
    for text in raw:
        for obj in g._extract_json_array(text) or []:
            if isinstance(obj, dict) and isinstance(obj.get("id"), int):
                returned[obj["id"]] = obj

    rows = []
    expected_roles = []
    predicted_roles = []
    reversals = []
    for idx, (entry, item) in enumerate(zip(entries, items)):
        obj = returned.get(idx)
        pred_role = obj.get("role") if isinstance(obj, dict) else "missing"
        operational = False
        if pred_role == "none":
            operational = True
        elif pred_role in ROLES and obj:
            candidate = dict(obj)
            candidate["_candidate"] = {"kind": "call", "name": item["name"], "n": 1}
            operational = bool(g.validate([candidate], set()))
        if pred_role not in ROLES or not operational:
            scored_role = "invalid"
        else:
            scored_role = pred_role
        expected = entry["role"]
        expected_roles.append(expected)
        predicted_roles.append(scored_role)
        category_ok = expected != "sink" or (
            scored_role == "sink" and obj.get("cat") == entry.get("category"))
        cwe_ok = expected != "sink" or (
            scored_role == "sink" and str(obj.get("cwe", "")).upper() == entry.get("cwe"))
        applies_ok = expected != "sanitizer" or (
            scored_role == "sanitizer" and
            entry.get("category") in (obj.get("applies_to") or []))
        if (expected, scored_role) in (("source", "sink"), ("sink", "source")):
            reversals.append(entry["api"])
        rows.append({
            "id": idx, "api": entry["api"], "expected_role": expected,
            "predicted_role": scored_role, "operationally_valid": operational,
            "category_ok": category_ok, "cwe_ok": cwe_ok, "applies_to_ok": applies_ok,
            "prediction": obj,
        })

    per_role = {role: f1_for_role(expected_roles, predicted_roles, role) for role in ROLES}
    macro_f1 = sum(x["f1"] for x in per_role.values()) / len(ROLES)
    sink_total = sum(x == "sink" for x in expected_roles)
    sink_role_hits = sum(e == "sink" and p == "sink"
                         for e, p in zip(expected_roles, predicted_roles))
    sink_exact_hits = sum(r["expected_role"] == "sink" and r["category_ok"] and r["cwe_ok"]
                          for r in rows)
    result = {
        "run": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "model": "qwen3.8-max", "temperature": 0.0,
            "golden_view": "v1 + v2 overrides", "item_count": len(entries),
            "batch_size": batch_size, "workers": workers,
            "system_prompt_sha256": hashlib.sha256(g.RULEGEN_SYSTEM.encode()).hexdigest(),
            "base_sha256": hashlib.sha256((HERE / "rule_golden_set_v1.json").read_bytes()).hexdigest(),
            "overrides_sha256": hashlib.sha256(
                (HERE / "rule_golden_set_v2_overrides.json").read_bytes()).hexdigest(),
            "usage": pilot_llm.stats(),
        },
        "metrics": {
            "role_macro_f1": macro_f1,
            "sink_role_recall": sink_role_hits / sink_total if sink_total else 0.0,
            "sink_exact_recall": sink_exact_hits / sink_total if sink_total else 0.0,
            "missing_or_invalid": sum(x == "invalid" for x in predicted_roles),
            "high_impact_source_sink_reversals": reversals,
            "prediction_counts": Counter(predicted_roles),
            "per_role": per_role,
            "gate_pass": macro_f1 >= 0.85 and sink_role_hits / sink_total >= 0.90
                         and not reversals and len(returned) == len(entries),
        },
        "rows": rows,
    }
    (out_dir / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=6)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()
    result = run(args.out, args.batch_size, args.workers)
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2, default=dict))


if __name__ == "__main__":
    main()
