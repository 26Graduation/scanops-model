"""MID-GATE 전용 세트 — CleanVul_v2 **tune** 의 유사도 0.95+ 쌍을 P2 형식·위치 상쇄로 만든다.

report 를 게이트에 쓰면 최종 판정이 오염된다(어제와 같은 규율).
그래서 게이트는 tune 에서만 뽑는다.
출력: data/gate_cbX_P2.jsonl, data/gate_cbY_P2.jsonl
"""
import difflib, json
from collections import defaultdict
from pathlib import Path
from build_diff_prompts import changed_line_idx, code_of, comment_of, mark, p2, pair_key
ROOT = Path(__file__).resolve().parent
rows = [json.loads(l) for l in (ROOT/'data'/'cleanvul_v2_tune.jsonl').open()]
g = defaultdict(dict)
for r in rows:
    k = pair_key(r['meta'])
    if k: g[k][r['meta']['label']] = r
out = defaultdict(list)
n = 0
for k, v in g.items():
    if 'vuln' not in v or 'safe' not in v: continue
    cv, cs = code_of(v['vuln']['prompt']), code_of(v['safe']['prompt'])
    if difflib.SequenceMatcher(None, cv, cs).ratio() < 0.95: continue
    n += 1
    lang = v['vuln']['meta'].get('lang_group') or 'code'
    c = comment_of(lang)
    for assign, (a, b) in (('X', (cv, cs)), ('Y', (cs, cv))):
        for ver, code, other in (('A', a, b), ('B', b, a)):
            is_v = (ver == 'A') == (assign == 'X')
            meta = {'source':'gate','pair_id':f'tune|{k}','language':lang,'lang_group':lang,
                    'bench':'CleanVul_tune','assign':assign,'judged_version':ver,
                    'label':'vuln' if is_v else 'safe'}
            out[f'cb{assign}_P2'].append(
                {'prompt': p2(lang, code, ver, mark(code, changed_line_idx(code, other), c)),
                 'meta': meta})
for name, rs in out.items():
    p = ROOT/'data'/f'gate_{name}.jsonl'
    with p.open('w') as f:
        for r in rs: f.write(json.dumps(r, ensure_ascii=False)+'\n')
    print(f'  {p.name}: {len(rs)}건')
print(f'[게이트 세트] CleanVul_v2 tune 의 0.95+ 쌍 {n}개')
