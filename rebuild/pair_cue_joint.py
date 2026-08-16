"""
쌍 단서 분석 2단계 — **동시 통제**와 **민감도** (§1-4b 의 한계 보강, 비용 $0)
==============================================================================
`pair_cue_analysis.py` 는 diff 크기와 방어 토큰을 **따로** 봤다. D-12 가 그 한계를 적었다.
여기서 두 가지를 더 한다:

  (A) **동시 통제** — (diff 구간 × 방어토큰 유무) 셀 안에서 코퍼스별 순위 정확도를 비교한다.
      코퍼스 항이 셀 안에서도 살아남으면 "표면 단서"만으로는 격차를 설명하지 못한다.
  (B) **민감도**   — 방어 토큰 목록을 넓은 것/좁은 것 두 벌로 돌린다.
      넓은 목록에는 `if/len/size/null` 같은 일반 토큰이 들어 있어, 효과가 그것들 때문일 수 있다.

출력: out/pair_cue_joint_{tag}.json
실행: python3 rebuild/pair_cue_joint.py [tag]
"""

import json
import re
import sys
import difflib
from collections import defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parent
TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"


CODE=re.compile(r"```[^\n]*\n(.*?)\n```",re.S)
WIDE=re.compile(r"\b(if|assert|check|valid|verify|sanitiz|escape|encode|quote|bound|limit|clamp|strn?cpy_s|snprintf|strlcpy|len|size|length|count|null|NULL|nullptr|None|overflow|range|index|offset)\b",re.I)
NARROW=re.compile(r"\b(assert|sanitiz|escape|encode|htmlspecialchars|strlcpy|snprintf|clamp|bounds?_check|is_valid|validate)\b",re.I)
def key(m): return m.get("pair_id") or m.get("cve_id")
def code(p):
    m=CODE.search(p); return m.group(1) if m else p
def build(split):
    sc=[json.loads(l) for l in open(str(ROOT/'out'/f'{TAG}_logprob_{split}.jsonl'))]
    da=[json.loads(l) for l in open(str(ROOT/'data'/f'{split}.jsonl'))]
    g=defaultdict(lambda: defaultdict(list))
    for s,d in zip(sc,da):
        k=key(s['meta'])
        if k: g[k][s['meta']['label']].append((s['score'],code(d['prompt'])))
    rows=[]
    for k,v in g.items():
        if len(v.get('vuln',[]))!=1 or len(v.get('safe',[]))!=1: continue
        (sv,cv),(ss,cs)=v['vuln'][0],v['safe'][0]
        dl=sum(1 for l in difflib.unified_diff(cv.splitlines(),cs.splitlines(),n=0)
               if l[:1] in '+-' and not l.startswith(('+++','---')))
        rows.append(dict(dl=dl,
            gw=bool({x.group(0).lower() for x in WIDE.finditer(cs)}-{x.group(0).lower() for x in WIDE.finditer(cv)}),
            gn=bool({x.group(0).lower() for x in NARROW.finditer(cs)}-{x.group(0).lower() for x in NARROW.finditer(cv)}),
            ok=sv>ss))
    return rows
SP=[('test','내부test'),('cleanvul_v2_report','CleanVul'),('primevul_report','PrimeVul')]
R={n:build(s) for s,n in SP}
def acc(rs): return (round(sum(r['ok'] for r in rs)/len(rs),4), len(rs)) if rs else (None,0)
print("=== diff 구간 × 방어토큰(넓은 목록) 동시 통제 ===")
print(f"{'셀':>22} | " + " | ".join(f"{n:>16}" for _,n in SP))
for lo,hi in [(0,5),(6,20),(21,10**9)]:
    for g in (False,True):
        cell=f"diff {lo}-{hi if hi<10**9 else '∞'} guard={'Y' if g else 'N'}"
        out=[]
        for _,n in SP:
            a,k=acc([r for r in R[n] if lo<=r['dl']<=hi and r['gw']==g]); out.append(f"{a} (n={k})")
        print(f"{cell:>22} | " + " | ".join(f"{o:>16}" for o in out))
print()
print("=== 방어토큰 목록 민감도 (넓은 vs 좁은) ===")
for _,n in SP:
    for tag,f in (('wide','gw'),('narrow','gn')):
        y,ny=acc([r for r in R[n] if r[f]]); x,nx=acc([r for r in R[n] if not r[f]])
        print(f"{n:>10} {tag:>7}: 추가 {y} (n={ny})  미추가 {x} (n={nx})")

OUT = {"tag": TAG,
       "WARNING": "사후 참고. 예측 대조이며 인과가 아니다.",
       "joint_cells": {}, "token_list_sensitivity": {}}
for lo, hi in [(0, 5), (6, 20), (21, 10**9)]:
    for g in (False, True):
        cell = f"diff{lo}-{hi if hi < 10**9 else 'inf'}_guard{'Y' if g else 'N'}"
        OUT["joint_cells"][cell] = {}
        for _, n in SP:
            a, k = acc([r for r in R[n] if lo <= r["dl"] <= hi and r["gw"] == g])
            OUT["joint_cells"][cell][n] = {"rank_acc": a, "n": k}
for _, n in SP:
    OUT["token_list_sensitivity"][n] = {}
    for tag, f in (("wide", "gw"), ("narrow", "gn")):
        y, ny = acc([r for r in R[n] if r[f]])
        x, nx = acc([r for r in R[n] if not r[f]])
        OUT["token_list_sensitivity"][n][tag] = {
            "guard_added": {"rank_acc": y, "n": ny},
            "no_guard": {"rank_acc": x, "n": nx}}
p = ROOT / "out" / f"pair_cue_joint_{TAG}.json"
p.write_text(json.dumps(OUT, ensure_ascii=False, indent=2))
print(f"\u2192 {p}")
