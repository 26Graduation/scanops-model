"""연속 점수 — score = logP(" CWE") − logP(" NONE")  (Phase 1-B)

rebuild/score_logprob.py 와 **같은 정의**를 서빙 경로에서 재현한다. 정의가 달라지면
rebuild 의 모든 AUC·τ 와 비교가 불가능해지므로, 토큰 ID가 다르면 자동 보정하지 않고
None 을 반환한다(§3 기재 후 SIGNAL 정책 보류).

프롬프트는 학습/채점과 동일하게 "VULNERABILITY:" 접두사까지 강제로 넣은 상태에서
바로 다음 토큰의 분포를 본다.
"""
from __future__ import annotations

import math

# rebuild/score_logprob.py 가 사용한 토큰 ID (unsloth/Qwen3.5-9B 토크나이저)
REF_NONE_ID = 41451
REF_CWE_ID = 49149

PREFIX = "VULNERABILITY:"
_NEG_INF = -30.0   # 후보 목록에 없을 때의 하한 (n_probs 밖 = 사실상 0 확률)


def _entry_logprob(e: dict) -> float | None:
    """llama.cpp 응답 형식 흡수: {"prob":p} 또는 {"logprob":lp}."""
    if "logprob" in e and e["logprob"] is not None:
        return float(e["logprob"])
    if "prob" in e and e["prob"] is not None:
        p = float(e["prob"])
        return math.log(p) if p > 0 else _NEG_INF
    return None


def _entry_text(e: dict) -> str:
    for k in ("tok_str", "token", "text"):
        if k in e and isinstance(e[k], str):
            return e[k]
    return ""


def score_from_probs(probs: list[dict]) -> float | None:
    """첫 토큰 후보 분포 → score. 두 후보가 모두 없으면 None."""
    if not probs:
        return None
    lp_cwe = lp_none = None
    for e in probs:
        t = _entry_text(e)
        if t == " CWE" and lp_cwe is None:
            lp_cwe = _entry_logprob(e)
        elif t == " NONE" and lp_none is None:
            lp_none = _entry_logprob(e)
    if lp_cwe is None and lp_none is None:
        return None
    return round((lp_cwe if lp_cwe is not None else _NEG_INF)
                 - (lp_none if lp_none is not None else _NEG_INF), 4)


def verify_token_ids(tokenize_fn) -> dict:
    """서빙 토크나이저의 ' CWE' / ' NONE' 첫 토큰 ID를 rebuild 기준값과 대조.

    반환 {"ok": bool, "cwe_id": int|None, "none_id": int|None, "note": str}
    ok=False 면 score 를 쓰면 안 된다 (점수 정의 불일치).
    """
    try:
        cwe = tokenize_fn(" CWE")
        none = tokenize_fn(" NONE")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "cwe_id": None, "none_id": None,
                "note": f"tokenize 호출 실패: {e}"}
    cid = cwe[0] if cwe else None
    nid = none[0] if none else None
    if cid is None or nid is None:
        return {"ok": False, "cwe_id": cid, "none_id": nid, "note": "빈 토큰 결과"}
    if cid == nid:
        return {"ok": False, "cwe_id": cid, "none_id": nid,
                "note": "두 후보의 첫 토큰이 동일 — 1위치 비교 불가"}
    ok = (cid == REF_CWE_ID and nid == REF_NONE_ID)
    return {"ok": ok, "cwe_id": cid, "none_id": nid,
            "note": "rebuild 기준값과 일치" if ok else
                    f"불일치 (기준 CWE={REF_CWE_ID}/NONE={REF_NONE_ID}) — 자동 보정하지 않음"}
