"""Targeted LLM Critic — Joern v3 가 vuln 이라 한 흐름만 골라 sanitizer 유무를 묻는다.

배경: Joern taint reachability 는 "파라미터가 sink 에 닿는가"만 본다. CleanVul 의
vuln/safe 쌍은 **양쪽 다 닿고** 차이는 그 사이의 검증·이스케이프에 있다
(JOERN_HYBRID_REPORT.md §4-6). 그래서 흐름 슬라이스만 잘라 LLM 에 묻는다.

주의: 이 Critic 도 결국 v1 어댑터 LLM 이다(외부 벤치 AUC 0.56). 그래서 report 에
적용하기 전에 tune 에서 T1~T3 사전등록 게이트를 통과해야 한다.
"""
from __future__ import annotations

import re
from typing import Any

from scanops.core.llm_client import chat as llm_chat

# 응답에서 판정을 뽑는 정규식.
# 정확 문자열 비교(==) 금지 — 줄표/콜론/공백/대소문자 차이에 의존하지 않는다.
_VERDICT_RE = re.compile(r"SANITIZED\s*[:\-–—]?\s*(YES|NO)", re.IGNORECASE)
_THINK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
_THINK_OPEN_RE = re.compile(r"<think>.*\Z", re.IGNORECASE | re.DOTALL)

MAX_PATH_LINES = 40


def strip_think(text: str) -> str:
    """<think>...</think> 제거. 닫히지 않은 블록도 잘라낸다."""
    t = _THINK_RE.sub(" ", text or "")
    return _THINK_OPEN_RE.sub(" ", t).strip()


def parse_verdict(raw: str) -> str:
    """'YES' | 'NO' | 'UNPARSED'.

    UNPARSED 를 NO 로 취급하지 않는다 — 취급하면 '모르겠음'이 '취약'으로 둔갑해
    정확도가 실제보다 좋아 보인다.
    """
    m = _VERDICT_RE.search(strip_think(raw))
    if not m:
        return "UNPARSED"
    return m.group(1).upper()


def build_prompt(category: str, language: str, path: list[dict]) -> str:
    """path = [{"line":int,"code":str,"role":"source|intermediate|sink"}, ...]"""
    steps = path[:MAX_PATH_LINES]
    lines = []
    for i, s in enumerate(steps, 1):
        role = s.get("role", "intermediate")
        ln = s.get("line", -1)
        code = (s.get("code") or "").strip()
        lines.append(f"{i}. [{role}] line {ln}: {code}")
    flow = "\n".join(lines)
    return (
        "You are an expert security code auditor.\n"
        "A static analyzer found a data flow from user-controlled input to a sensitive sink.\n"
        f"Category: {category}. Language: {language}.\n"
        "Flow (source → sink), each line is real code from the file:\n"
        f"{flow}\n"
        "Question: before reaching the sink, is the data properly sanitized, validated, "
        "parameterized, or encoded for this sink type?\n"
        'Answer exactly one line, starting with either "SANITIZED: YES" or "SANITIZED: NO", '
        "then a short reason."
    )


def critique(category: str, language: str, path: list[dict],
             timeout: int = 180, num_predict: int = 600) -> dict[str, Any]:
    """반환 {"verdict":"YES|NO|UNPARSED", "reason":str, "raw":str, "error":str|None}"""
    if not path:
        return {"verdict": "UNPARSED", "reason": "", "raw": "", "error": "empty_path"}
    prompt = build_prompt(category, language, path)

    # cold start 시 워커가 **빈 문자열**을 돌려주는 일이 실측됐다(첫 호출 27.3s, raw="").
    # 이건 형식 실패가 아니라 기동 지연이므로 1회만 재시도한다. 재시도해도 비면 UNPARSED.
    raw = ""
    err = None
    for attempt in (0, 1):
        try:
            raw = llm_chat("", [{"role": "user", "content": prompt}],
                           {"temperature": 0.0, "num_predict": num_predict}, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            err = str(e)[:200]
            raw = ""
        if strip_think(raw):
            err = None
            break
    if not strip_think(raw):
        return {"verdict": "UNPARSED", "reason": "", "raw": raw[:2000],
                "error": err or "empty_response"}
    verdict = parse_verdict(raw)
    cleaned = strip_think(raw)
    m = _VERDICT_RE.search(cleaned)
    reason = cleaned[m.end():].strip()[:300] if m else cleaned[:300]
    return {"verdict": verdict, "reason": reason, "raw": raw[:2000], "error": None}
