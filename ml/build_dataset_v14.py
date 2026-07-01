"""ScanOps V14 학습데이터 — V13(CVEfixes) + 합성 주입 패턴 추가 (OWASP 약점 보강)
================================================================
V13 진단(3벤치): 실제 CVE(CVEfixes)·깨끗한 코드(CyberNative)엔 강하나 **OWASP 서블릿
합성 주입 패턴엔 과소탐지**(재현율 23.6%). 원인 = 학습이 "미묘한 실제 CVE"에 편식되어
"명백한 주입" 스타일을 거의 못 봄 + OWASP를 학습서 제외(zero-shot 유지).

V14 처방(레버 A): **다른 출처의 합성 주입 데이터**를 학습에 추가해 명백한 주입 패턴을
가르친다. OWASP 테스트셋은 계속 제외(zero-shot 유지).

데이터 = V13(3,483) + CyberNative 학습split(다언어 secure/insecure).
누수 차단: CyberNative **평가용 154케이스(cybernative_benchmark.jsonl) 코드해시 제외** +
OWASP 흔적 제외 + V13과 dedup.

실행: python -m ml.build_dataset_v14 --add 2500 --out data/lora_train_v14.jsonl
산출: <out>(train) + <out>_val.jsonl
"""
from __future__ import annotations
import argparse, hashlib, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_qwen_rag import build_ft_user_prompt

SEED = 41
NONE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0"
MIN_LEN, MAX_LEN = 40, 1600
# CyberNative 학습은 전 언어 사용(많을수록 좋음). 평가는 그래프커버 7언어만이었음.
LANG_MAP = {
    "python":"Python","java":"Java","javascript":"Node.js / Express","php":"PHP",
    "ruby":"Ruby","go":"Go","c#":"C#","c++":"C++","swift":"Swift","kotlin":"Kotlin",
}
_OWASP = ("HttpServletRequest","HttpServletResponse","BenchmarkTest","org.owasp")

def _norm(c): return re.sub(r"\s+"," ",c or "").strip().lower()
def _h(c): return hashlib.sha1(_norm(c).encode()).hexdigest()
def _is_owasp(c): return any(k in c for k in _OWASP)
def _extract(md):
    m=re.search(r"```[a-zA-Z+#0-9./]*\n(.*?)```", md or "", re.S)
    return (m.group(1) if m else (md or "")).strip()

def _excluded_hashes():
    """V13 학습 + CyberNative 벤치 + OWASP 홀드아웃 → 학습 제외."""
    ex=set()
    for name in ("lora_train_v13.jsonl","lora_train_v13_val.jsonl"):
        p=ROOT/"data"/name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    m=re.search(r"```[a-zA-Z+#./]*\n(.*?)```", json.loads(line)["prompt"], re.S)
                    if m: ex.add(_h(m.group(1)))
    b=ROOT/"data"/"cybernative_benchmark.jsonl"
    if b.exists():
        for line in b.read_text().splitlines():
            if line.strip(): ex.add(_h(json.loads(line)["code"]))
    try:
        from scripts.owasp_benchmark_cases import build_cases, JAVA_DIR, _extract_code
        for c in build_cases():
            jf=JAVA_DIR/f"{c['id']}.java"
            if jf.exists(): ex.add(_h(_extract_code(jf)))
    except Exception as e:
        print(f"  (OWASP 해시 스킵: {e})")
    return ex

def _vuln_comp(vuln_desc: str) -> str:
    name=(vuln_desc or "Security Vulnerability").strip().split(".")[0][:70]
    low=name.lower()
    sev,cvss=("CRITICAL","9.8") if any(k in low for k in ("inject","rce","command","deserial","eval","overflow")) else ("HIGH","8.1")
    return f"VULNERABILITY: {name}\nSEVERITY: {sev}\nCVSS: {cvss}"

def build(add_n: int, out: Path):
    from datasets import load_dataset
    rng=random.Random(SEED)
    excl=_excluded_hashes()
    print(f"제외 해시 {len(excl)}개 (V13+CyberNative벤치+OWASP)")

    # 1) V13 데이터 로드(베이스)
    def load(p): return [json.loads(l) for l in open(p) if l.strip()]
    v13=load(ROOT/"data"/"lora_train_v13.jsonl")+load(ROOT/"data"/"lora_train_v13_val.jsonl")
    seen=set();
    for r in v13:
        m=re.search(r"```[a-zA-Z+#./]*\n(.*?)```", r["prompt"], re.S)
        if m: seen.add(_h(m.group(1)))

    # 2) CyberNative 학습 추가분 수집(평가셋과 dedup)
    ds=load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train", streaming=True)
    cand=defaultdict(list); scanned=0
    for r in ds:
        scanned+=1
        if scanned>20000: break
        lang=LANG_MAP.get(str(r.get("lang","")).strip().lower())
        if not lang: continue
        for md,label in ((r.get("rejected"),"vuln"),(r.get("chosen"),"safe")):
            code=_extract(md)
            if not (MIN_LEN<=len(code)<=MAX_LEN): continue
            if _is_owasp(code): continue
            hh=_h(code)
            if hh in excl or hh in seen: continue
            seen.add(hh)
            comp=_vuln_comp(r.get("vulnerability","")) if label=="vuln" else NONE_COMPLETION
            cand[(lang,label)].append({"prompt":build_ft_user_prompt(lang,code),"completion":comp,"label":label,"src":"cyber"})

    langs=sorted({l for (l,_) in cand})
    per=max(2, add_n//(2*max(1,len(langs))))
    add=[]
    for lang in langs:
        for label in ("vuln","safe"):
            items=cand.get((lang,label),[]); rng.shuffle(items); add.extend(items[:per])
    rng.shuffle(add); add=add[:add_n]

    # 3) 병합 + train/val 재분할(90:10)
    base=[{**r,"src":"v13"} for r in v13]
    allrows=base+add
    rng.shuffle(allrows)
    k=max(1,int(len(allrows)*0.10))
    val=allrows[:k]; train=allrows[k:]
    def strip(r): return {"prompt":r["prompt"],"completion":r["completion"]}
    out.write_text("\n".join(json.dumps(strip(r),ensure_ascii=False) for r in train)+"\n",encoding="utf-8")
    vp=out.with_name(out.stem+"_val.jsonl")
    vp.write_text("\n".join(json.dumps(strip(r),ensure_ascii=False) for r in val)+"\n",encoding="utf-8")

    nv=sum(1 for r in allrows if "NONE" not in r["completion"])
    print("─"*60)
    print(f"V13 {len(base)} + CyberNative 추가 {len(add)} = 총 {len(allrows)} (취약 {nv}/안전 {len(allrows)-nv})")
    print("CyberNative 언어:", dict(Counter(r['prompt'].split('this ')[1].split(' code')[0] for r in add)))
    print(f"train {len(train)} | val {len(val)}")
    print(f"저장: {out}\n검증: {vp}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--add", type=int, default=2500, help="CyberNative 추가 샘플 수")
    ap.add_argument("--out", type=Path, default=ROOT/"data"/"lora_train_v14.jsonl")
    a=ap.parse_args()
    build(a.add, a.out)
