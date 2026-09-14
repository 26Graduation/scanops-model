"""GRAPH-SPEC §5-3 — LLM 스펙 → Joern Rule 스펙 변환 + arm 별 스펙 파일 생성.

만드는 것 (rebuild/out/ 아래):
  graph_spec_final_{repo}.json   파싱·검증·필터 결과 전부 (버린 것 포함)
  spec_S2A_{repo}.tsv            손 룰 (taint_v4.sc JSSRC 7개 + srcCalls) 를 스펙 형식으로 옮긴 것
  spec_S2B_{repo}.tsv            LLM 생성 스펙만
  spec_S2C_{repo}.tsv            §4-1 병합 규칙으로 합집합
  prop_S2B_{repo}.tsv / prop_S2C_{repo}.tsv   오염 전파 규칙 (CPGHunter)

반과적합 필터 (사양 §9): 패턴에 소스 파일 경로/`::program`/줄번호가 들어간 룰은 버린다.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

# GRAPH_RUN_SPEC.md §21 — 레포 간 공유 API 판단 캐시. (kind, name) 단위로 한 번 검증된
# 판단을 저장해 다음 레포부터 재사용한다. "처음 본 판단이 이긴다" — 사람이 캐시 파일을
# 직접 열어 틀린 항목을 고치는 게 유일한 수정 경로다(자동 덮어쓰기 안 함, §21-2).
API_CACHE_PATH = OUT / "graph_spec_api_cache.json"


def load_api_cache() -> dict:
    if API_CACHE_PATH.exists():
        return json.loads(API_CACHE_PATH.read_text())
    return {}


def cache_key(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def update_api_cache(good: list[dict], repo: str) -> dict:
    cache = load_api_cache()
    added = 0
    for r in good:
        cand = r.get("_candidate")
        if not cand:
            continue
        k = cache_key(cand["kind"], cand["name"])
        if k in cache:
            continue  # §21-2: 이미 있는 판단은 자동으로 안 덮어쓴다
        entry = {kk: r[kk] for kk in ("role", "cat", "cwe", "match", "pattern",
                                      "applies_to", "propagation", "confidence", "why")
                 if kk in r}
        entry["_first_seen_repo"] = repo
        entry["_reviewed_by_human"] = False
        cache[k] = entry
        added += 1
    if added:
        API_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True))
    return {"n_cache_entries_total": len(cache), "n_added_this_run": added}

CATS = {
    "sqli": "CWE-89", "cmdi": "CWE-78", "xss": "CWE-79", "pathtraver": "CWE-22",
    "ssrf": "CWE-918", "deser": "CWE-502", "codei": "CWE-94", "redirect": "CWE-601",
    "nosqli": "CWE-943", "logforge": "CWE-117", "sensitive": "CWE-200",
    "accesscontrol": "CWE-284", "weakcrypto": "CWE-327", "proto": "CWE-1321",
}

# ── S2-A: taint_v4.sc 의 JSSRC 손 룰을 그대로 옮긴다 (값 변경 없음) ────────────
HAND_JSSRC = [
    ("sqli",       "CWE-89",  "name", "(?i)(query|execute|raw|prepare)"),
    ("cmdi",       "CWE-78",  "name", "(?i)(exec|execSync|spawn|spawnSync|execFile|fork)"),
    ("xss",        "CWE-79",  "name", "(?i)(innerHTML|outerHTML|write|send|render|insertAdjacentHTML|dangerouslySetInnerHTML)"),
    ("pathtraver", "CWE-22",  "name", "(?i)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|sendFile)"),
    ("ssrf",       "CWE-918", "name", "(?i)(get|post|request|fetch|axios|got)"),
    ("deser",      "CWE-502", "name", "(?i)(parse|unserialize|deserialize)"),
    ("codei",      "CWE-94",  "name", "(?i)(eval|Function|runInNewContext|runInThisContext)"),
]
HAND_SRC = ("name", "(?i)(getParameter|getHeader|getQueryString|getInputStream|getCookies|"
                    "input|raw_input|request|argv|getenv|environ)")

BAD_PATH = re.compile(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs|py|java|scala|go|rb|php)\b")
BAD_PROG = re.compile(r"::program")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def repo_path_tokens(repo: str) -> set[str]:
    """스캔 대상 트리에서 나온 **레포 내부 모듈 경로 토큰**.

    npm 패키지 경로(`@angular/core`, `node:fs/promises`)는 살리고 레포 내부 모듈 경로
    (`lib/insecurity`, `routes/x`)만 걸러내기 위한 것이다. 벤치 이름을 손으로 적지 않고
    **분석 대상 레포에서 기계적으로 뽑는다** — 다른 레포에도 그대로 적용된다.
    """
    cand = json.loads((OUT / f"graph_spec_candidates_{repo}.json").read_text())
    src = Path(cand["staged_dir"])
    toks: set[str] = set()
    if not src.exists():
        return toks
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        parts = list(rel.parts)
        if p.is_file():
            parts[-1] = Path(parts[-1]).stem
        for i in range(len(parts)):
            seg = "/".join(parts[: i + 1])
            if "/" in seg:
                toks.add(seg)
    return toks


def parse_raw(repo: str) -> tuple[list[dict], list[dict]]:
    """배치 원본 응답 → 룰 객체 목록. (ok, parse_failures)"""
    items = json.loads((OUT / f"graph_spec_items_{repo}.json").read_text())["items"]
    by_id = {it["id"]: it for it in items}
    ok, fails = [], []
    for line in (OUT / f"graph_spec_raw_{repo}.jsonl").open():
        rec = json.loads(line)
        txt = re.sub(r"<think>.*?</think>", "", rec["raw"], flags=re.S).strip()
        if txt.startswith("```"):
            txt = re.sub(r"^```[a-z]*\n", "", txt)
            txt = re.sub(r"\n```$", "", txt)
        # 로컬 모델이 배열 앞뒤로 군말을 붙이는 경우가 있어 첫 '[' ~ 마지막 ']' 만 취한다.
        lb, rb = txt.find("["), txt.rfind("]")
        if lb != -1 and rb != -1 and rb > lb:
            txt = txt[lb:rb + 1]
        try:
            arr = json.loads(txt)
        except Exception as e:
            fails.append({"batch": rec["batch"], "error": str(e)[:200], "ids": rec["ids"]})
            continue
        for o in arr:
            if not isinstance(o, dict) or "id" not in o:
                continue
            src = by_id.get(o["id"])
            o["_candidate"] = {"name": src["name"], "kind": src["kind"], "n": src["n"]} if src else None
            o["_batch"] = rec["batch"]
            ok.append(o)
    return ok, fails


def validate(rules: list[dict], repo_toks: set[str]) -> tuple[list[dict], list[dict]]:
    """반과적합 + 형식 검증. (통과, 탈락+사유)"""
    good, bad = [], []
    for o in rules:
        role = o.get("role")
        pat = (o.get("pattern") or "").strip()
        why = None
        if role not in ("sink", "source", "sanitizer"):
            continue                                   # role=none 은 룰이 아니다
        if not pat:
            why = "empty_pattern"
        elif BAD_PATH.search(pat) or BAD_PROG.search(pat):
            why = "repo_path_in_pattern"               # 사양 §9 위반
        elif any(t in pat for t in repo_toks):
            why = "repo_module_path_in_pattern"        # 사양 §9 위반
        elif o.get("match") not in ("name", "full", "assign_field"):
            why = "bad_match_field"
        elif o.get("match") == "assign_field" and (o.get("_candidate") or {}).get("kind") != "assign":
            why = "assign_field_on_non_assign_candidate"   # PLAN.md 4단계 반과적합 방지
        elif role == "sink" and o.get("cat") not in CATS:
            why = "unknown_category"
        else:
            try:
                re.compile(pat)
            except re.error as e:
                why = f"regex_error:{e}"
        if why:
            bad.append({**{k: v for k, v in o.items() if not k.startswith("_")},
                        "reject_reason": why, "candidate": o.get("_candidate")})
        else:
            good.append(o)
    return good, bad


def dedupe_rules(rules: list[dict]) -> list[dict]:
    """(role, cat, pattern, field) 동일하면 하나로 — §4-1 규칙 2의 스펙 내부판."""
    seen: dict[tuple, dict] = {}
    for o in rules:
        k = (o["role"], o.get("cat", ""), o["pattern"], o["match"])
        if k not in seen:
            seen[k] = o
    return list(seen.values())


def san_tsv(rules: list[dict]) -> tuple[str, int]:
    """LLM sanitizer 룰 → sanFile 형식.

    sanFile 패턴은 **노드 코드 텍스트**에 부분일치시킨다(taint_v4.sc 와 동일 규약).
    LLM 이 낸 패턴은 호출 이름/풀네임 정규식이라 규약이 다르다 →
    패턴의 **마지막 식별자**를 뽑아 `\b<ident>\s*\(` 로 기계 변환한다.
    """
    lines = []
    for o in rules:
        if o["role"] != "sanitizer":
            continue
        ids = IDENT.findall(o["pattern"])
        if not ids:
            continue
        ident = ids[-1]
        ap = ",".join(o.get("applies_to") or ["*"])
        lines.append(f"llm\t{ap}\t\\b{re.escape(ident)}\\s*\\(")
    return ("\n".join(lines) + "\n" if lines else ""), len(lines)


def to_tsv(rules: list[dict]) -> str:
    lines = []
    for o in rules:
        if o["role"] == "sink":
            lines.append(f"sink\t{o['cat']}\t{CATS[o['cat']]}\t{o['match']}\t{o['pattern']}")
        elif o["role"] == "source":
            lines.append(f"source\t-\t-\t{o['match']}\t{o['pattern']}")
    return "\n".join(lines) + "\n"


def prop_tsv(rules: list[dict]) -> tuple[str, int]:
    lines = []
    for o in rules:
        props = o.get("propagation") or []
        if not props or o.get("match") != "full":
            continue
        maps = []
        for pr in props:
            a, b = pr.get("from"), pr.get("to")
            def norm(x):
                if x == "return":
                    return "return"
                return str(x) if isinstance(x, int) else None
            na, nb = norm(a), norm(b)
            if na is not None and nb is not None:
                maps.append(f"{na},{nb}")
        if maps:
            lines.append(f"{o['pattern']}\t{';'.join(maps)}")
    return ("\n".join(lines) + "\n" if lines else ""), len(lines)


def hand_rules() -> list[dict]:
    out = [{"role": "sink", "cat": c, "cwe": w, "match": f, "pattern": p,
            "confidence": "hand", "why": "taint_v4.sc JSSRC hand rule", "_src": "hand"}
           for c, w, f, p in HAND_JSSRC]
    out.append({"role": "source", "match": HAND_SRC[0], "pattern": HAND_SRC[1],
                "confidence": "hand", "why": "taint_v4.sc srcCalls", "_src": "hand"})
    # 2026-08-23: taint_v4.sc 에 없던 새 손 룰(§23). `obj[key] = val` 처럼 키 자체가 변수인
    # 대입 — 프로토타입 오염(CWE-1321)의 전형적 sink 모양. API 이름 판단이 아니라 구조
    # 패턴이라 LLM 라벨링이 필요 없다(assign_field 와 달리 pattern 규칙이 없다 — 구조만 본다).
    # 실측 근거: jonschlinkert/assign-deep:40, merge-deep:41,43,45 이 전부 이 모양이었다.
    out.append({"role": "sink", "cat": "proto", "cwe": "CWE-1321",
                "match": "dynamic_index", "pattern": "",
                "confidence": "hand", "why": "동적 키 프로퍼티 대입 — 프로토타입 오염 sink 패턴",
                "_src": "hand"})
    return out


def merge_s2c(hand: list[dict], llm: list[dict]) -> tuple[list[dict], list[dict]]:
    """§4-1: 합집합. (cat, sink 패턴, field) 세 값이 모두 같으면 병합. 역할 충돌은 둘 다 유지+기록."""
    merged: list[dict] = []
    key_seen: dict[tuple, dict] = {}
    for o in hand + llm:
        k = (o.get("cat", ""), o["pattern"], o["match"])
        if k in key_seen:
            key_seen[k].setdefault("_merged_from", []).append(o.get("_src", "llm"))
            continue
        key_seen[k] = o
        merged.append(o)
    # 역할 충돌: 같은 (pattern, match) 를 서로 다른 role 로 본 경우
    byp: dict[tuple, set] = {}
    for o in merged:
        byp.setdefault((o["pattern"], o["match"]), set()).add(o["role"])
    conflicts = [{"pattern": p, "match": m, "roles": sorted(rs)}
                 for (p, m), rs in byp.items() if len(rs) > 1]
    return merged, conflicts


def main(repo: str) -> None:
    raw, parse_fails = parse_raw(repo)
    repo_toks = repo_path_tokens(repo)
    good, bad = validate(raw, repo_toks)
    cache_stat = update_api_cache(good, repo)

    # §21-3: 캐시(사람이 고쳤을 수 있음)를 최종 근거로 삼는다. `raw`(role=none 포함, 검증 전
    # 원본 전체)를 훑어야 한다 — LLM이 "none"이라 답해서 validate()가 애초에 걸러버린 항목도
    # 사람이 캐시에서 sink/source로 교정했으면 살려내야 하기 때문이다. role=none 으로 고쳐진
    # 항목은 이번 실행의 LLM 판단과 무관하게 룰에서 뺀다.
    cache_now = load_api_cache()
    cached_keys = set()
    overridden = []
    for r in raw:
        cand = r.get("_candidate")
        if not cand:
            continue
        k = cache_key(cand["kind"], cand["name"])
        c = cache_now.get(k)
        if not c:
            continue
        cached_keys.add(k)
        if c.get("role") == "none":
            continue
        overridden.append({**r, **{kk: c[kk] for kk in
                           ("role", "cat", "cwe", "match", "pattern",
                            "applies_to", "propagation", "confidence", "why") if kk in c}})
    # 캐시에 없는 후보는 이번 실행의 검증된 판단(good)을 그대로 쓴다.
    good = [r for r in good if not (r.get("_candidate") and
            cache_key(r["_candidate"]["kind"], r["_candidate"]["name"]) in cached_keys)] + overridden
    good = overridden

    llm = dedupe_rules(good)
    for o in llm:
        o["_src"] = "llm"
    hand = hand_rules()
    s2c, conflicts = merge_s2c(hand, llm)

    (OUT / f"spec_S2A_{repo}.tsv").write_text(to_tsv(hand))
    (OUT / f"spec_S2B_{repo}.tsv").write_text(to_tsv(llm))
    (OUT / f"spec_S2C_{repo}.tsv").write_text(to_tsv(s2c))
    pb, nb = prop_tsv(llm)
    pc, nc = prop_tsv(s2c)
    (OUT / f"prop_S2B_{repo}.tsv").write_text(pb)
    (OUT / f"prop_S2C_{repo}.tsv").write_text(pc)
    sb_txt, n_sanb = san_tsv(llm)
    (OUT / f"san_S2B_{repo}.tsv").write_text(sb_txt)

    def count(rs, role):
        return sum(1 for r in rs if r["role"] == role)

    summary = {
        "repo": repo,
        "api_cache": cache_stat,
        "n_llm_labels_returned": len(raw),
        "n_role_not_none": len(good) + len(bad),
        "n_rules_valid": len(good),
        "n_rules_after_dedupe": len(llm),
        "n_rules_rejected": len(bad),
        "n_repo_path_tokens_used_for_filter": len(repo_toks),
        "reject_reasons": {r: sum(1 for b in bad if b["reject_reason"].split(":")[0] == r)
                           for r in sorted({b["reject_reason"].split(":")[0] for b in bad})},
        "batch_parse_failures": parse_fails,
        "S2A": {"sink": count(hand, "sink"), "source": count(hand, "source"),
                "sanitizer": count(hand, "sanitizer"), "prop": 0},
        "S2B": {"sink": count(llm, "sink"), "source": count(llm, "source"),
                "sanitizer": count(llm, "sanitizer"), "sanitizer_patterns": n_sanb, "prop": nb},
        "S2C": {"sink": count(s2c, "sink"), "source": count(s2c, "source"),
                "sanitizer": count(s2c, "sanitizer"), "prop": nc},
        "S2C_role_conflicts": conflicts,
        "confidence_dist": {c: sum(1 for r in llm if r.get("confidence") == c)
                            for c in sorted({r.get("confidence", "?") for r in llm})},
        "cat_dist_llm": {c: sum(1 for r in llm if r.get("cat") == c)
                         for c in sorted({r.get("cat", "") for r in llm if r["role"] == "sink"})},
        "rejected_rules": bad,
        "rules_S2B": llm,
        "rules_S2A": hand,
    }
    (OUT / f"graph_spec_final_{repo}.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in summary.items()
                      if k not in ("rejected_rules", "rules_S2B", "rules_S2A")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
