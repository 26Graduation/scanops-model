# feat/hyeeun vs feat/sehan 브랜치 비교 분석

> 분석 기준일: 2026-05-13  
> hyeeun (cf3a83b) · sehan (a11864c)

---

## 1. 파일 구조 차이

```
git diff --name-only feat/hyeeun...feat/sehan
```

```
feat/hyeeun (전혜은)              feat/sehan (김세한)
──────────────────────────        ──────────────────────────────────────
scanops-model/                    scanops-model/
├── src/                          ├── src/
│   ├── preprocess_nvd_2026.py    │   ├── filter_nvd.py          ← 신규
│   └── embed_cve.py              │   ├── preprocess_nvd.py      ← 다름
│                                 │   └── vectorize_cve.py       ← 다름
├── data/                         ├── data/
│   └── cve_index.faiss ★        │   └── (json만, faiss 없음)
│                                 ├── chroma_db/                 ← 신규
│                                 │   └── chroma.sqlite3
│                                 ├── scripts/                   ← 신규 (20+개)
│                                 │   ├── lora_finetune.py
│                                 │   ├── rag_pipeline.py
│                                 │   ├── benchmark_core.py
│                                 │   ├── grok_client.py
│                                 │   ├── generate_train_data.py
│                                 │   └── adapters/
│                                 │       ├── grok_adapter.py
│                                 │       ├── ollama_adapter.py
│                                 │       └── rag_adapter.py
│                                 ├── models/
│                                 │   └── tinyllama-security-lora/
│                                 │       ├── adapter_config.json
│                                 │       └── checkpoint-{13,26,39}/
│                                 └── reports/
│                                     ├── *.html
│                                     └── *.json
```

**커밋 수:**
- feat/hyeeun: **3개** (init → init → 4단계 임베딩 완료)
- feat/sehan: **5개** (init → NVD 전처리/벡터화/LoRA → Grok 연결 → 벤치마크 문서 → 파서 수정)

> ⚠️ **중요 발견**: 사용자 설명에는 "feat/hyeeun: Qdrant (Docker 기반)"이라고 명시했지만,  
> **실제 코드는 FAISS** (`faiss.IndexFlatIP`)를 사용하고 있음. Qdrant 연동은 미완성 상태.

---

## 2. 데이터 전처리 스크립트 비교

### 2-1. 필터링 기준 차이

| 항목 | feat/hyeeun (`preprocess_nvd_2026.py`) | feat/sehan (`filter_nvd.py`) |
|------|---------------------------------------|------------------------------|
| 전략 | **제외 목록** 방식 | **허용 목록** 방식 |
| 조건 | `EXCLUDE_STATUS = {'Rejected', 'Deferred'}` | `VALID_STATUSES = {"Analyzed", "Modified"}` |
| 포함 상태 | Analyzed, Modified, **Awaiting Analysis, Undergoing Analysis** 등 전부 | Analyzed, Modified **만** |
| 결과 데이터 수 | **~12,251개** (대부분 포함) | **792개** (완전 분석된 것만) |

```python
# feat/hyeeun — 제외 방식 (더 많이 포함)
EXCLUDE_STATUS = {'Rejected', 'Deferred'}
valid = [i for i in items if i['cve']['vulnStatus'] not in EXCLUDE_STATUS]

# feat/sehan — 허용 방식 (신뢰도 우선)
VALID_STATUSES = {"Analyzed", "Modified"}
filtered = [v for v in data["vulnerabilities"]
            if v["cve"].get("vulnStatus") in VALID_STATUSES]
```

**평가:**
- hyeeun: 양(量) 우선 → RAG 검색 커버리지 넓음, but 분석 미완료 CVE 포함
- sehan: 질(質) 우선 → CVSS 점수·CWE 모두 채워진 CVE만, but 792개로 샘플 편중 위험

### 2-2. 최종 데이터 수 차이

```
feat/hyeeun: 12,251개   ████████████████████████████████████████ (100%)
feat/sehan:     792개   ██▌                                       (6.5%)
```

sehan의 792개는 **2026년 최근 CVE만** 대상으로 했기 때문 (nvdcve-2.0-recent.json 사용).  
hyeeun은 전체 2026년 NVD 데이터셋 기준.

### 2-3. 선정 필드 차이

| 필드 | feat/hyeeun | feat/sehan |
|------|:-----------:|:----------:|
| cve_id / id | ✅ | ✅ |
| published | ✅ | ✅ |
| lastModified | ❌ | ✅ |
| vuln_status | ✅ (원본) | ❌ (필터 후 제거) |
| base_score | ✅ | ✅ |
| severity | ✅ | ✅ |
| attack_vector | ✅ | ❌ |
| cwe_id (단일) | ✅ (문자열) | ✅ cwe_primary |
| cwe (배열) | ❌ | ✅ |
| affected_products | ✅ (CPE 파싱) | ❌ |
| cvss_vector | ✅ | ✅ vector_string |
| description | ✅ | ✅ |
| age_days | ❌ | ✅ (파생) |
| days_since_modified | ❌ | ✅ (파생) |
| reference_count | ❌ | ✅ (파생) |
| references | ❌ | ✅ |
| **총 필드 수** | **10개** | **15개 (파생 포함)** |

**hyeeun 강점:** `attack_vector`, `affected_products` (CPE 파싱) — RAG 검색 품질에 직접 기여  
**sehan 강점:** `age_days`, `days_since_modified` — 최신성 필터링 가능, `cwe[]` 배열로 다중 CWE 처리

---

## 3. 벡터 DB 비교

### 3-1. 실제 구현 현황

| 항목 | feat/hyeeun | feat/sehan |
|------|-------------|------------|
| **실제 구현** | **FAISS** (IndexFlatIP) | **ChromaDB** (PersistentClient) |
| 계획 (설명서 기준) | Qdrant (Docker) | ChromaDB |
| 저장 방식 | `data/cve_index.faiss` + `cve_id_map.json` | `chroma_db/chroma.sqlite3` |
| 검색 방식 | `index.search(q_vec, top_k)` | `collection.query(query_embeddings=[...])` |
| 메타데이터 | 별도 JSON 파일 필요 | 컬렉션 내 `metadatas` 필드 |
| 유사도 방식 | Inner Product (정규화 벡터 → cosine 동일) | L2 distance → `1 - dist` |
| Docker 필요 | ❌ | ❌ |
| HTTP 서버 | ❌ (파일 기반) | ❌ (로컬 sqlite) |

### 3-2. 백엔드 HTTP API 연동 관점 평가

```
백엔드(Spring Boot) → 벡터 DB 호출 시나리오:

방식 A: 백엔드 → Python 중간 서버(FastAPI) → 벡터 DB
방식 B: 벡터 DB에 HTTP API가 있어서 백엔드 직접 호출
```

| 평가 기준 | FAISS (hyeeun 현재) | ChromaDB (sehan) | Qdrant (계획) |
|----------|-------------------|-----------------|--------------|
| HTTP API 기본 제공 | ❌ | ❌ (로컬 모드) | ✅ REST API 내장 |
| Spring Boot 직접 연동 | ❌ | ❌ | ✅ |
| Docker 배포 | ❌ | △ (서버 모드 가능) | ✅ |
| Python FastAPI 경유 | ✅ | ✅ | ✅ |
| 현재 구현 복잡도 | 낮음 | 낮음 | 높음 |
| 확장성 | 낮음 | 중간 | 높음 |

**결론:**  
현 단계(로컬 개발)에서는 **ChromaDB** (sehan)가 적합. Python FastAPI로 `/search` 엔드포인트를 감싸면 Spring Boot 연동 가능. Qdrant는 프로덕션 전환 시 고려.

---

## 4. 임베딩 입력 텍스트 구성 비교

### 4-1. 실제 코드

```python
# feat/hyeeun (embed_cve.py) — 구조화 템플릿 (7개 필드)
def serialize_cve(record: dict) -> str:
    return (
        f"CVE ID: {record['cve_id']}. "
        f"Severity: {record.get('severity', 'N/A')} (score: {score_str}). "
        f"Attack Vector: {record.get('attack_vector', 'N/A')}. "
        f"CWE: {cwe}. "
        f"Status: {record.get('vuln_status', 'N/A')}. "
        f"Affected Products: {products}. "
        f"Description: {record.get('description', '')}"
    )
# 예시 출력:
# "CVE ID: CVE-2026-40520. Severity: HIGH (score: 7.2). Attack Vector: NETWORK.
#  CWE: CWE-78. Status: Analyzed. Affected Products: freepbx:api.
#  Description: FreePBX api module...shell_exec() without sanitization..."
```

```python
# feat/sehan (vectorize_cve.py) — description 중심 압축 (3개 필드)
def build_embed_text(cve: dict) -> str:
    parts = [cve.get("description", "")]
    if severity or score is not None:
        parts.append(f"Severity: {severity} CVSS: {score}")
    if cwes:
        parts.append("CWE: " + " ".join(cwes))
    return " ".join(filter(None, parts))
# 예시 출력:
# "FreePBX api module...shell_exec() without sanitization... Severity: HIGH CVSS: 8.6 CWE: CWE-78"
```

### 4-2. RAG 검색 목적 관점 평가

| 쿼리 유형 | hyeeun (7필드) | sehan (3필드) |
|----------|--------------|--------------|
| `"SQL injection python"` | ✅ (description + CWE) | ✅ |
| `"network attack critical"` | ✅ Attack Vector: NETWORK 매칭 | △ description에 있으면 가능 |
| `"apache tomcat vulnerability"` | ✅ Affected Products: apache:tomcat | ❌ 필드 없음 |
| `"CWE-78 command injection"` | ✅ CWE 필드 명시 | ✅ CWE 필드 있음 |
| 문장 의미 검색 | △ 필드 레이블이 노이즈 될 수 있음 | ✅ description이 자연어 중심 |

**결론:**  
- **hyeeun 강점:** `Attack Vector`, `Affected Products` → 제품명/벡터 기반 검색에 유리  
- **sehan 강점:** description 자연어 중심 → bge-small 모델의 의미 검색에 최적화  
- **통합 추천:** description을 앞에, 구조화 필드를 뒤에 붙이는 하이브리드 방식

```python
# 추천 통합 임베딩 텍스트
def serialize_cve_merged(record: dict) -> str:
    desc = record.get("description", "")
    severity = record.get("severity", "")
    score = record.get("base_score") or record.get("score", "")
    cwe = record.get("cwe_id") or " ".join(record.get("cwe", []))
    av = record.get("attack_vector", "")
    products = ", ".join(record.get("affected_products", []))
    
    structured = " | ".join(filter(None, [
        f"Severity: {severity}",
        f"CVSS: {score}",
        f"CWE: {cwe}",
        f"Vector: {av}" if av else "",
        f"Products: {products}" if products else "",
    ]))
    return f"{desc} [{structured}]"
```

---

## 5. LLM 파이프라인 비교

### 5-1. 현재 구현 상태

| 항목 | feat/hyeeun | feat/sehan |
|------|-------------|------------|
| LLM 파이프라인 | **없음** (임베딩까지만) | **완성** |
| LLM 모델 | - | Gemma-2 2B IT (HuggingFace) |
| 서빙 방식 | - | HF 직접 로드 + LoRA 어댑터 |
| Ollama | 미연결 | gemma:2b (베이스라인용) |
| RAG 연동 | FAISS 인덱스 있음, 검색 API 없음 | ChromaDB + rag_local.py |
| 탐지율 | **측정 불가** (LLM 없음) | **85%** (17/20) |

### 5-2. 탐지율 차이 원인 코드 레벨 분석

```
hyeeun: 임베딩 파이프라인만 완성 → LLM 미연결 → 탐지율 측정 불가
sehan:  전처리 → 벡터 DB → LoRA 파인튜닝 → 벤치마크 전 파이프라인 완성
```

**sehan 85% 달성 핵심 요인:**

① **모델 업그레이드**: Gemma 2B (35%) → Gemma-2 2B IT + LoRA (85%)
```python
# lora_finetune.py
MODEL_ID = "google/gemma-2-2b-it"   # Gemma 2세대, IT(instruction-tuned)
LORA_R   = 16                        # rank 16 (기존 8 → 2배)
target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"]  # 전체 어텐션
EPOCHS   = 5                         # 충분한 학습
```

② **학습 데이터 4배 확장**: 50개 → 203개 (NVD 792개 CVE 활용)
```python
# generate_train_augment.py
# NVD CWE 태그 → 코드 템플릿 자동 생성
# 결과: 19개 CWE, 203개 예제
```

③ **Gemma-2 IT 전용 프롬프트 형식**:
```
<start_of_turn>user
Analyze this Python code...<end_of_turn>
<start_of_turn>model
CWE-78 OS Command Injection...<end_of_turn>
```

④ **실제 학습 loss 수렴**: 2.909 → 0.692 (76% 감소, 5 epochs)

---

## 6. 통합 제안

### 6-1. main 머지 시 충돌 가능 파일 목록

| 파일 | 충돌 가능성 | 이유 |
|------|:---------:|------|
| `src/preprocess_nvd.py` vs `src/preprocess_nvd_2026.py` | 🔴 높음 | 같은 역할, 다른 파일명·로직 |
| `src/vectorize_cve.py` vs `src/embed_cve.py` | 🔴 높음 | 같은 역할 (FAISS 공통), 구조 다름 |
| `data/cve_index.faiss` | 🟡 중간 | hyeeun만 존재, sehan은 chroma_db 사용 |
| `.gitignore` | 🟡 중간 | sehan에 `*.safetensors`, `chroma_db/` 추가됨 |
| `README.md` | 🟢 낮음 | 내용 없음 (양쪽 모두) |
| `src/filter_nvd.py` | 🟢 없음 | sehan 전용, hyeeun에 없음 |
| `scripts/` 전체 | 🟢 없음 | sehan 전용, hyeeun에 없음 |

**머지 전략:**
```bash
# sehan을 기준으로 머지 (파이프라인 더 완성)
git checkout feat/sehan
git merge feat/hyeeun

# 충돌 해결 방침
# src/preprocess_nvd.py → sehan 유지 (filter → preprocess 2단계 분리가 더 명확)
# src/embed_cve.py → hyeeun의 affected_products 필드 추출 로직 sehan으로 이식
# data/ → sehan의 chroma_db 유지, hyeeun의 faiss는 마이그레이션
```

### 6-2. ChromaDB로 벡터 DB 통일 시 sehan 수정 사항

hyeeun의 FAISS → ChromaDB 마이그레이션:

```python
# scripts/migrate_faiss_to_chroma.py (sehan에 이미 존재!)
# → hyeeun의 cve_index.faiss + nvd_2026_preprocessed.json 을
#    ChromaDB cve_collection에 추가 삽입하면 됨

import chromadb
import faiss, json, numpy as np
from sentence_transformers import SentenceTransformer

# hyeeun 데이터 로드
with open("data/nvd_2026_preprocessed.json") as f:
    raw = json.load(f)
records = raw["data"]   # 12,251개

# 기존 chroma_db에 추가 삽입
client = chromadb.PersistentClient(path="chroma_db")
col = client.get_collection("cve_collection")

model = SentenceTransformer("BAAI/bge-small-en-v1.5")
# → serialize + encode + col.add() 로 기존 792개에 12,251개 추가
# → 총 ~13,000개 CVE 벡터 DB 완성
```

**sehan 쪽 코드 수정 필요 항목:**
- `rag_local.py`의 `_search_cves()` → 메타데이터 스키마 맞추기 (hyeeun은 `vuln_status`, `attack_vector` 필드 추가됨)
- `scripts/vectorize_cve.py` → hyeeun의 `affected_products` 필드 추출 로직 추가

### 6-3. RAG(hyeeun) + LoRA(sehan) 통합 파이프라인 구조 제안

```
                    ┌──────────────────────────────────────┐
                    │       통합 파이프라인 (main)           │
                    └──────────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
         ① 전처리 파이프라인                  ② 분석 파이프라인
    (hyeeun src/ + sehan src/ 통합)       (sehan scripts/ 활용)
                    │                                 │
    ┌───────────────┼───────────────┐                 │
    ▼               ▼               ▼                 │
filter_nvd.py  preprocess.py  embed_cve.py            │
(sehan)        (hyeeun+sehan) (통합 버전)              │
12,251개 CVE   15개 필드       ChromaDB 저장          │
                                                      │
                              ┌───────────────────────┘
                              ▼
               ┌──────────────────────────────┐
               │     scanops_pipeline.py       │
               │  (신규 통합 파이프라인 파일)    │
               │                              │
               │  입력: language + code        │
               │                              │
               │  1단계: LoRA 모델 탐지         │
               │    gemma-2-2b-it + LoRA →    │
               │    VULNERABILITY / CWE / FIX │
               │                              │
               │  2단계: CVE 근거 검색          │
               │    CWE → ChromaDB 검색 →     │
               │    유사 CVE top-3 반환         │
               │                              │
               │  출력: {                      │
               │    vulnerability, severity,  │
               │    attack, fix,              │
               │    cve_references: [...]     │
               │  }                           │
               └──────────────────────────────┘
```

**코드 스케치:**

```python
# scripts/scanops_pipeline.py — 통합 파이프라인
"""
RAG(hyeeun) + LoRA(sehan) 통합
- 탐지: Gemma-2 2B LoRA (85% 정확도)
- 근거: ChromaDB 12,251개 CVE (hyeeun 데이터 머지 후)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import chromadb
from sentence_transformers import SentenceTransformer

BASE    = Path(__file__).resolve().parent.parent
LORA    = BASE / "models" / "gemma2-security-lora"
CHROMA  = BASE / "chroma_db"

_model     = None
_tokenizer = None
_chroma    = None
_embedder  = None

PROMPT = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [name with CWE ID]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
ATTACK: [one sentence]
FIX: [fixed code only]"""


def _load_lora():
    global _model, _tokenizer
    if _model: return _model, _tokenizer
    dtype = torch.float16 if torch.backends.mps.is_available() else torch.float32
    base = AutoModelForCausalLM.from_pretrained(
        "google/gemma-2-2b-it", torch_dtype=dtype, low_cpu_mem_usage=True
    )
    _model = PeftModel.from_pretrained(base, str(LORA))
    _model.eval()
    _tokenizer = AutoTokenizer.from_pretrained(LORA)
    return _model, _tokenizer


def _load_rag():
    global _chroma, _embedder
    if _chroma: return _chroma, _embedder
    client  = chromadb.PersistentClient(path=str(CHROMA))
    _chroma = client.get_collection("cve_collection")
    _embedder = SentenceTransformer("BAAI/bge-small-en-v1.5")
    return _chroma, _embedder


def analyze(language: str, code: str) -> dict:
    # ── Step 1: LoRA 탐지 ──────────────────────────────────
    model, tok = _load_lora()
    device = next(model.parameters()).device
    text   = (f"<start_of_turn>user\n"
               f"{PROMPT.format(language=language, code=code)}"
               f"<end_of_turn>\n<start_of_turn>model\n")
    inputs = tok(text, return_tensors="pt").to(device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=256,
                             do_sample=False,
                             pad_token_id=tok.eos_token_id)
    response = tok.decode(out[0][inputs["input_ids"].shape[1]:],
                          skip_special_tokens=True)
    parsed = _parse(response)

    # ── Step 2: CVE 근거 검색 ─────────────────────────────
    cve_refs = []
    vuln = parsed.get("VULNERABILITY", "")
    if vuln and vuln != "—":
        try:
            col, emb = _load_rag()
            import re
            cwe = re.search(r"CWE-\d+", vuln)
            query = f"{cwe.group(0)} {vuln} {language}" if cwe else f"{vuln} {language}"
            vec   = emb.encode(
                "Represent this sentence for searching relevant passages: " + query
            ).tolist()
            res   = col.query(query_embeddings=[vec], n_results=3,
                              include=["documents", "metadatas", "distances"])
            for doc, meta, dist in zip(res["documents"][0],
                                        res["metadatas"][0],
                                        res["distances"][0]):
                sim = round(1 - dist, 3)
                if sim >= 0.5:
                    cve_refs.append({
                        "cve_id":      meta.get("cve_id", "?"),
                        "cwe":         meta.get("cwe", "?"),
                        "severity":    meta.get("severity", "?"),
                        "similarity":  sim,
                        "description": doc[:200],
                    })
        except Exception:
            pass

    return {
        "vulnerability":  parsed.get("VULNERABILITY", "—"),
        "severity":       parsed.get("SEVERITY", "—"),
        "attack":         parsed.get("ATTACK", "—"),
        "fix":            parsed.get("FIX", "—"),
        "cve_references": cve_refs,
    }


def _parse(text: str) -> dict:
    import re
    fields = {}
    for key in ("VULNERABILITY", "SEVERITY", "ATTACK", "FIX"):
        m = re.search(rf"^{key}:[ \t]*(.+)", text, re.MULTILINE | re.IGNORECASE)
        fields[key] = m.group(1).strip() if m else "—"
    return fields
```

---

## 7. 최종 요약 및 권장 사항

| 항목 | 추천 |
|------|------|
| 전처리 방식 | **sehan** (filter → preprocess 2단계 분리, 명확) |
| 필터링 기준 | **hyeeun** 방식 (Rejected+Deferred만 제외) → 더 많은 데이터 확보 |
| 임베딩 텍스트 | **통합** (sehan description 중심 + hyeeun의 attack_vector, products 추가) |
| 벡터 DB | **ChromaDB** (sehan) — 단기. 프로덕션 시 Qdrant 전환 |
| LLM 파이프라인 | **sehan** (완성, 85%) |
| 데이터 크기 | **hyeeun** 방식으로 12,251개 확보 → ChromaDB 마이그레이션 |
| 최우선 작업 | hyeeun의 12,251개 CVE → sehan ChromaDB 에 추가 삽입 |
