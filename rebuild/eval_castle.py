"""
ScanOps v4 — CASTLE 벤치마크 러너 (Claude / 로컬 모델 공용)
============================================================
CASTLE(arXiv:2503.09433, TASE 2025) 250개 C 파일에 대해 **논문의 공식 프롬프트를 그대로** 쓴다.
프롬프트를 우리 쪽에 유리하게 바꾸면 논문 표와 비교할 자격을 잃으므로 절대 수정하지 않는다.

채점은 논문 저장소 legacy_evaluate.py의 매칭 규칙을 그대로 옮겼다:
  - TP  : 보고한 finding 중 line이 정답 lines에 있거나 CWE가 정답 CWE(부모/자식 포함)와 일치
  - FP  : 그 외 finding (같은 줄 중복은 1건으로 셈 — 논문 주석과 동일)
  - TN  : non-vulnerable 파일에 아무것도 보고 안 함
  - FN  : vulnerable 파일에 아무것도 보고 안 함
CASTLE Score = TP당 +5, TN당 +2, FP당 -1 (논문 Eq.2의 MITRE Top-25 보너스는 미구현 →
  우리 점수는 논문 대비 **보수적**이며, 리포트에 이 사실을 명시한다)

실행:
  python eval_castle.py claude claude-sonnet-5           # Anthropic API
  python eval_castle.py local out/v3_s42_step750 v3s42   # 로컬 어댑터
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASTLE = Path("/tmp/CASTLE-Benchmark/datasets/CASTLE-C250.json")
POINTS = {"tp": 5, "tn": 2, "fp": -1, "fn": 0}


def load_castle() -> tuple[list[dict], str, dict]:
    d = json.loads(CASTLE.read_text())
    return d["tests"], d["prompt"], d["cwes"]


def accepted_cwes(cwe_meta: dict, correct: int) -> set[int]:
    """정답 CWE + 그 부모/자식 (논문 채점기와 동일하게 관대하게)"""
    e = cwe_meta.get(str(correct))
    if not e:
        return {correct}
    out = {correct}
    for key in ("children", "parents"):
        for p in e.get(key, []):
            out |= {int(k) for k in p}
    return out


def parse_findings(text: str) -> list[dict] | None:
    """```json ... ``` 블록에서 리스트 추출. 실패 시 None(파싱실패)."""
    m = re.search(r"```json\s*(.*?)```", text, re.S)
    raw = m.group(1) if m else None
    if raw is None:                       # 백틱 없이 뱉은 경우도 구제 시도
        m2 = re.search(r"(\[.*\])", text, re.S)
        raw = m2.group(1) if m2 else None
    if raw is None:
        return None
    try:
        v = json.loads(raw)
    except Exception:
        return None
    if not isinstance(v, list):
        return None
    out = []
    for f in v:
        if not isinstance(f, dict):
            continue
        try:
            out.append({"line": int(f.get("line", 0) or 0),
                        "cwe": int(f.get("cwe", 0) or 0),
                        "severity": str(f.get("severity", "")),
                        "message": str(f.get("message", ""))[:200]})
        except Exception:
            continue
    return out


def score_one(test: dict, findings: list[dict] | None, cwe_meta: dict) -> dict:
    """논문 채점기 규칙. findings=None(파싱실패)은 '보고 없음'으로 보수 처리."""
    fs = findings or []
    vuln = bool(test["vulnerable"])
    if not fs:
        return {"tp": 0, "fp": 0, "tn": 0 if vuln else 1, "fn": 1 if vuln else 0,
                "points": POINTS["fn"] if vuln else POINTS["tn"]}
    if not vuln:                          # 안전한 파일에 보고 → 전부 FP
        n = len({f["line"] for f in fs})
        return {"tp": 0, "fp": n, "tn": 0, "fn": 0, "points": POINTS["fp"] * n}
    ok = accepted_cwes(cwe_meta, int(test["cwe"]))
    lines = set(test.get("lines") or [])
    match = [f for f in fs if f["line"] in lines or f["cwe"] in ok]
    if match:
        fp = len({f["line"] for f in fs}) - len({f["line"] for f in match})
        return {"tp": 1, "fp": max(0, fp), "tn": 0, "fn": 0,
                "points": POINTS["tp"] + POINTS["fp"] * max(0, fp)}
    n = len({f["line"] for f in fs})
    return {"tp": 0, "fp": n, "tn": 0, "fn": 1, "points": POINTS["fp"] * n}


def aggregate(rows: list[dict]) -> dict:
    tp = sum(r["tp"] for r in rows); fp = sum(r["fp"] for r in rows)
    tn = sum(r["tn"] for r in rows); fn = sum(r["fn"] for r in rows)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    n_file_fp = sum(1 for r in rows if r["fp"] > 0)
    return {"n": len(rows), "TP": tp, "TN": tn, "FP": fp, "FN": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "accuracy": round((tp + tn) / len(rows), 4),
            "castle_score_no_bonus": sum(r["points"] for r in rows),
            "files_with_any_fp": n_file_fp,
            "fp_per_file": round(fp / len(rows), 3),
            "parse_fail": sum(1 for r in rows if r.get("parse_fail"))}


# ── 백엔드: Anthropic ────────────────────────────────────────────────────────
def run_claude(model: str, tests: list[dict], prompt: str) -> list[dict]:
    import anthropic
    key = [l.split("=", 1)[1].strip() for l in (ROOT.parent / ".env").read_text().splitlines()
           if l.startswith("ANTHROPIC_API_KEY=")][0]
    cl = anthropic.Anthropic(api_key=key)
    out = []
    t0 = time.time()
    for i, t in enumerate(tests, 1):
        try:
            r = cl.messages.create(model=model, max_tokens=1500,
                                   messages=[{"role": "user",
                                              "content": f"{prompt}\n\n```c\n{t['code']}\n```"}])
            txt = "".join(b.text for b in r.content if b.type == "text")
        except Exception as e:
            txt = ""
            print(f"  [{t['name']}] API 오류: {e}", flush=True)
        out.append({"name": t["name"], "raw": txt})
        if i % 25 == 0:
            print(f"  {i}/{len(tests)} ({time.time()-t0:.0f}s)", flush=True)
    return out


# ── 백엔드: 로컬 어댑터 ──────────────────────────────────────────────────────
def run_local(adapter: str, tests: list[dict], prompt: str) -> list[dict]:
    from unsloth import FastLanguageModel
    m, tok = FastLanguageModel.from_pretrained(adapter, max_seq_length=8192,
                                               load_in_4bit=True, dtype=None)
    FastLanguageModel.for_inference(m)
    out = []
    t0 = time.time()
    for i, t in enumerate(tests, 1):
        msgs = [{"role": "user", "content": f"{prompt}\n\n```c\n{t['code']}\n```"}]
        ids = tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=True,
                                      return_tensors="pt").to(m.device)
        g = m.generate(input_ids=ids, max_new_tokens=700, do_sample=False,
                       pad_token_id=tok.pad_token_id or tok.eos_token_id)
        out.append({"name": t["name"],
                    "raw": tok.decode(g[0][ids.shape[1]:], skip_special_tokens=True)})
        if i % 25 == 0:
            print(f"  {i}/{len(tests)} ({time.time()-t0:.0f}s)", flush=True)
    return out


def main() -> None:
    backend = sys.argv[1]
    tests, prompt, cwe_meta = load_castle()
    if backend == "claude":
        model = sys.argv[2]
        tag = model.replace(".", "").replace("-", "")
        raws = run_claude(model, tests, prompt)
    else:
        adapter, tag = sys.argv[2], sys.argv[3]
        raws = run_local(adapter, tests, prompt)

    rows, det = [], []
    for t, r in zip(tests, raws):
        f = parse_findings(r["raw"])
        s = score_one(t, f, cwe_meta)
        s["parse_fail"] = f is None
        rows.append(s)
        det.append({"name": t["name"], "vulnerable": t["vulnerable"], "cwe": t["cwe"],
                    "lines": t.get("lines"), "findings": f, "score": s, "raw": r["raw"][:1500]})
    res = aggregate(rows)
    res["backend"], res["tag"] = backend, tag
    (ROOT / "out" / f"castle_{tag}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2))
    (ROOT / "out" / f"castle_{tag}_detail.jsonl").write_text(
        "\n".join(json.dumps(d, ensure_ascii=False) for d in det))
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
