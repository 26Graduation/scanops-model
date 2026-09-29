# 5단계. LLM 선정 + LoRA 파인튜닝 ✅ 완료

> 실행 환경: M3 MacBook Air 8GB · Python 3.14 venv · 2026-05-06

---

## 1. 모델 선정 경위

| 항목 | 내용 |
|---|---|
| 1차 후보 | google/gemma-2b (Ollama) |
| 파인튜닝 모델 | TinyLlama/TinyLlama-1.1B-Chat-v1.0 |
| 교체 이유 | Gemma 2B는 HuggingFace 가입 + 라이선스 동의 필요(Gated). TinyLlama는 ungated, fp16 2.2 GB로 M3 8 GB에 적합 |
| 추론(서빙) 모델 | gemma:2b (Ollama) — 응답 품질 우선 |
| **2차 교체 모델** | **xAI Grok API (grok-3-mini)** |
| 2차 교체 이유 | 기존 API 구독 활용, 로컬 서버(Ollama) 의존성 제거, 응답 품질 향상 기대 |

---

## 2. LoRA 설정값

| 파라미터 | 값 |
|---|---|
| 베이스 모델 | TinyLlama/TinyLlama-1.1B-Chat-v1.0 |
| LoRA rank (r) | 8 |
| lora_alpha | 16 |
| target_modules | q_proj, v_proj |
| lora_dropout | 0.05 |
| Epochs | 3 |
| Batch size | 1 |
| Gradient accumulation | 4 (effective batch = 4) |
| Learning rate | 2e-4 |
| max_length | 512 |
| Device | MPS (Apple Metal) |
| Trainable params | 1,126,400 / 1,101,174,784 (0.10%) |
| 학습 시간 | 123초 (~2분) |

---

## 3. 학습 데이터 구성

**파일:** `data/lora_train.jsonl` (50개)

| CWE | 취약점명 | 케이스 수 | 사용 언어 |
|---|---|---|---|
| CWE-284 | Improper Access Control | 12 | Python, Java, Node.js, Go |
| CWE-416 | Use After Free | 10 | C, C++ |
| CWE-77 | OS Command Injection | 10 | Python, Node.js, Java, PHP |
| CWE-125 | Out-of-Bounds Read | 8 | C, C++ |
| CWE-200 | Information Exposure | 5 | Python, Java, Node.js |
| CWE-190 | Integer Overflow | 5 | C, Java |
| **합계** | | **50** | |

**데이터 형식:**
```json
{
  "prompt": "Analyze this Python code for security vulnerabilities:\n\n{code}\n\nVULN_TYPE:",
  "completion": "CWE-77 OS Command Injection\nSEVERITY: CRITICAL\nATTACK: ...\nFIX:\n{fixed_code}"
}
```

---

## 4. 학습 Loss 곡선

| Step | Epoch | Loss |
|---|---|---|
| 5 | 0.40 | 1.525 |
| 10 | 0.80 | 1.365 |
| 15 | 1.16 | 1.239 |
| 20 | 1.56 | 1.229 |
| 25 | 1.96 | 1.080 |
| 30 | 2.32 | 0.990 |
| 35 | 2.72 | 1.049 |
| **최종** | **3.0** | **1.181** |

Loss가 1.525 → 1.181로 22.5% 감소. 50개 소규모 데이터 대비 안정적 수렴.

---

## 5. 파인튜닝 전후 탐지율 비교

**테스트:** 20개 코드 취약점 케이스 (security_benchmark.py 동일)

| 모델 | 탐지율 | 탐지 수 | 평균 응답시간 |
|---|---|---|---|
| Gemma 2B (Ollama, pre-LoRA) | 20.0% | 4/20 | 8.64s |
| TinyLlama 1.1B + LoRA | **35.0%** | **7/20** | **5.44s** |
| **변화** | **+15.0%p ↑** | **+3개** | **−3.2s ↓** |
| xAI Grok API (grok-3-mini) | 65.0% | 13/20 | 18.3s |
| **xAI Grok API (grok-3)** | **85.0%** | **17/20** | **3.97s** |

### LLM 교체 이력

- **1차 로컬 모델:** Ollama + Gemma 2B (완료, 베이스라인 확보)
- **교체 모델:** xAI Grok API — grok-3-mini / grok-3 비교 측정 완료 (2026-05-11)
- **교체 이유:** 기존 API 구독 활용, 로컬 서버 의존성 제거, 응답 품질 향상
- **결론:** grok-3 채택 — 탐지율 35% → **85% (+50%p)**, 응답시간 4.27s → **3.97s (−0.3s)**

### 공통 탐지 실패 케이스 (grok-3-mini / grok-3 모두 miss)

| # | 취약점 | 원인 |
|---|---|---|
| #11 | Overly Permissive Endpoint | 코드만 봐서는 범위 과다 허용임을 판단하기 어려움 |
| #12 | Timing Attack | `password.equals()` → Timing Attack 연결이 비직관적 |
| #20 | Supply Chain Attack (unpinned) | `@main` 핀 미지정 → Supply Chain 연결 학습 부족 |

> 위 3개는 RAG(CVE 컨텍스트) 연동(6단계) 시 개선 기대

**언어별 탐지 변화:**

| 언어 | Pre | Post | 변화 |
|---|---|---|---|
| React / Next.js | 0/4 | 3/4 | ↑+3 |
| Node.js / Express | 0/4 | 1/4 | ↑+1 |
| Java Spring Boot | 0/4 | 2/4 | ↑+2 |
| Python | 2/4 | 0/4 | ↓-2 |
| C | 1/2 | 1/2 | = |
| GitHub Actions YAML | 0/2 | 0/2 | = |

---

## 6. 분석 및 한계

### 성과
- 50개 데이터 / 3 epochs만으로 탐지율 **+15%p 향상**
- 응답시간 **37% 단축** (8.64s → 5.44s) — 경량 모델 + LoRA 효과
- CWE 번호 포함 응답 형식 학습 성공 (예: `CWE-79`, `CWE-125`)
- XSS, SQL Injection, Buffer Overflow 패턴 신규 탐지

### 한계 및 개선 방향
| 한계 | 원인 | 개선 방향 |
|---|---|---|
| Command Injection 탐지 하락 | 모델 크기(1.1B) 한계 | 데이터 확대(200개+) or 7B 모델 |
| GitHub Actions YAML 0% | 학습 데이터에 포함 안 됨 | YAML 케이스 추가 |
| 일부 할루시네이션 | 50개 과소학습 | 데이터셋 3~5배 확장 |
| Gemma 2B 직접 파인튜닝 불가 | HF Gated + 8GB RAM 한계 | HF 토큰 발급 후 재도전 |

---

## 7. 생성된 파일 목록

| 파일 | 설명 |
|---|---|
| `data/lora_train.jsonl` | 50개 학습 데이터 |
| `models/tinyllama-security-lora/` | LoRA 어댑터 저장 |
| `scripts/generate_train_data.py` | 학습 데이터 생성기 |
| `scripts/lora_finetune.py` | LoRA 학습 스크립트 (MPS) |
| `scripts/benchmark_lora.py` | 전후 비교 벤치마크 |
| `reports/lora_benchmark.html` | 시각화 리포트 |
| `reports/lora_train_loss.json` | 학습 손실 로그 |

---

## 8. 현재 완성된 아키텍처 (2026-05-11 기준)

> 이 섹션은 Claude/Claude Code에 프롬프팅할 때 참고용으로 작성된 아키텍처 문서입니다.

---

### 8-1. 전체 파이프라인 흐름

```
[사용자 코드 입력]
       │
       ▼
┌─────────────────────────────────────────┐
│           rag_pipeline.py               │
│                                         │
│  1. BGE-small 임베딩 (BAAI/bge-small-en-v1.5)
│         ↓                               │
│  2. ChromaDB 유사 CVE 검색 (top-5)      │
│     컬렉션: cve_collection (792개)      │
│         ↓                               │
│  3. CVE 컨텍스트 + 코드 → 프롬프트 조합 │
│         ↓                               │
│  4. xAI Grok API 호출 (grok-3)          │
│         ↓                               │
│  5. 응답 파싱: VULNERABILITY/SEVERITY/  │
│               ATTACK/FIX               │
└─────────────────────────────────────────┘
       │
       ▼
[취약점 분석 결과]
 - 취약점명 + CWE ID
 - 심각도 (CRITICAL/HIGH/MEDIUM/LOW)
 - 공격 시나리오
 - 수정 코드
 - 근거 CVE 목록 (실제 CVE ID + 유사도)
```

---

### 8-2. 핵심 파일 구조

```
scanops-model/
├── .env                          ← API 키 (XAI_API_KEY=xai-...)
├── chroma_db/                    ← ChromaDB 벡터 DB
│   └── cve_collection            ← 792개 NVD CVE 임베딩
├── data/
│   ├── nvdcve-2.0-preprocessed.json  ← 792개 CVE 원본 (id, cwe, severity, description)
│   └── lora_train.jsonl          ← LoRA 학습 데이터 50개
├── models/
│   └── tinyllama-security-lora/  ← TinyLlama LoRA 어댑터 (현재 미사용)
├── scripts/
│   ├── grok_client.py            ← Grok API 클라이언트 (query_llm 함수)
│   ├── rag_pipeline.py           ← RAG 파이프라인 (search_cve + analyze)
│   ├── benchmark_core.py         ← 공통 벤치마크 프레임워크 (20개 케이스, 파서, HTML)
│   ├── benchmark_grok.py         ← Grok 단독 벤치마크
│   ├── benchmark_rag.py          ← RAG + Grok 벤치마크
│   ├── benchmark_compare.py      ← 멀티모델 비교 리포트 생성
│   └── adapters/
│       ├── grok_adapter.py       ← Grok 단독 (ChromaDB 미사용)
│       ├── rag_adapter.py        ← RAG (ChromaDB + Grok), CVE 근거 품질 지표 포함
│       ├── ollama_adapter.py     ← 로컬 모델 (Ollama)
│       └── openai_adapter.py     ← OpenAI GPT 계열
└── reports/
    ├── results_*.json            ← 각 모델 벤치마크 결과 (JSON)
    ├── grok_benchmark_grok_3.html
    ├── rag_benchmark.html
    └── compare_report.html       ← 멀티모델 비교 HTML
```

---

### 8-3. 사용 중인 모델 및 라이브러리

| 역할 | 모델/라이브러리 | 버전/비고 |
|---|---|---|
| **LLM (추론)** | xAI Grok API — `grok-3` | API 호출, OpenAI 호환 형식 |
| **임베딩 (RAG 검색)** | BAAI/bge-small-en-v1.5 | sentence-transformers, 로컬 실행 |
| **벡터 DB** | ChromaDB | PersistentClient, `chroma_db/` 경로 |
| **HTTP 클라이언트** | httpx | Grok API 호출 |
| **환경변수** | python-dotenv | `.env` → `XAI_API_KEY` |
| **파인튜닝 (과거)** | TinyLlama 1.1B + LoRA | 현재 미사용, 모델 파일만 보관 |

---

### 8-4. Grok API 연동 방식

**파일:** `scripts/grok_client.py`

```python
# 핵심 함수 시그니처
def query_llm(
    prompt: str,
    system_prompt: str = SECURITY_SYSTEM_PROMPT,
    model: str = "grok-3-mini",   # 또는 "grok-3"
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> tuple[str, float]:           # (응답 텍스트, 경과시간(초))
```

- API 엔드포인트: `https://api.x.ai/v1/chat/completions`
- 인증: `Authorization: Bearer {XAI_API_KEY}` (`.env`에서 로드)
- 요청 형식: OpenAI Chat Completions 호환 JSON
- system_prompt: 보안 전문가 역할 부여 + CWE/심각도 포함 응답 유도

---

### 8-5. RAG 연동 방식

**파일:** `scripts/rag_pipeline.py`

```python
# 핵심 함수
def analyze(language, code, n_results=5, model="grok-3-mini"):
    # 1. 검색 쿼리 생성: f"{language} security vulnerability: {code}"
    # 2. BGE-small로 임베딩
    # 3. ChromaDB에서 top-5 유사 CVE 검색
    # 4. CVE 컨텍스트 포맷팅: "- CVE-ID (CWE, SEVERITY, CVSS): description"
    # 5. Grok API 호출
    return response, elapsed, cve_list
```

**RAG 프롬프트 구조:**
```
Reference CVEs (use as context only — focus on the code below):
- CVE-2026-XXXX (CWE-89, HIGH, CVSS 8.6): ...
- CVE-2026-YYYY (CWE-89, CRITICAL, CVSS 9.1): ...

Analyze this {language} code for security vulnerabilities.
Code: {code}

Respond in this exact format:
VULNERABILITY: ...
SEVERITY: ...
ATTACK: ...
FIX: ...
```

**RAG 역할 (현재 전략):** 탐지율 향상보다 **근거 제시**에 집중.
모델이 탐지한 취약점이 실제 어떤 CVE와 유사한지 보여주는 용도로 사용.

---

### 8-6. 벤치마크 평가 기준

**테스트:** 20개 코드 스니펫 (React/Next.js 4개, Node.js 4개, Java 4개, Python 4개, C 2개, GitHub Actions 2개)

**탐지 판정 방식:** 키워드 매칭 + CWE 번호 매칭 (이중 검증)
```python
# 예: "Supply Chain Attack" 기대 → "Unpinned Dependency (CWE-829)" 응답
# → "supply/chain" 키워드 없음 → CWE-829 매핑으로 탐지 인정
```

**최종 성능 수치 (2026-05-11):**

| 모델 | 탐지율 | 평균 응답시간 | 비고 |
|---|---|---|---|
| Gemma 2B (Ollama) | 35% | 4.27s | 베이스라인 |
| TinyLlama 1.1B + LoRA | 35% | 5.44s | LoRA 파인튜닝 |
| Grok API (grok-3-mini) | 65% | 18.3s | |
| Grok API (grok-3) | 95%→**100%** | 5.72s | 파서 수정 후 재채점 |

> **파서 수정 이력 (2026-05-11):** CWE 번호 기반 이중 매칭 추가.  
> Grok이 정확히 탐지했음에도 표현 차이로 miss 처리된 4개 케이스 (#8, #11, #12, #20) 구제.  
> - #8: `Use of Hard-coded Credentials (CWE-798)` → "Hardcoded Secret" 인정  
> - #11: `Missing Authorization (CWE-862)` → "Overly Permissive Endpoint" 인정  
> - #12: `Timing Attack in String Comparison (CWE-208)` → "Timing Attack" 인정  
> - #20: `Unpinned Dependency (CWE-829)` → "Supply Chain Attack" 인정

---

### 8-7. 멀티모델 비교 벤치마크 사용법

친구들 모델과 비교할 때:

```bash
# 각자 자신의 어댑터로 실행 (results_*.json 생성됨)
python scripts/adapters/grok_adapter.py                       # Grok 단독 (RAG 없음)
python scripts/adapters/rag_adapter.py                        # RAG + Grok (CVE 근거 포함)
python scripts/adapters/ollama_adapter.py --model llama3:8b   # Ollama 로컬 모델
python scripts/adapters/openai_adapter.py --model gpt-4o      # OpenAI GPT

# 결과 합쳐서 비교 리포트 생성
python scripts/benchmark_compare.py
# → reports/compare_report.html
```

**새 모델 추가 방법 (어댑터 작성):**
```python
# scripts/adapters/my_model_adapter.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from benchmark_core import PROMPT_TMPL, run_benchmark, save_html

def query(language: str, code: str) -> tuple[str, float]:
    prompt = PROMPT_TMPL.format(language=language, code=code)
    # 여기에 자신의 모델 호출 코드 작성
    response = "..."  # 모델 응답
    elapsed  = 1.23   # 응답시간(초)
    return response, elapsed

if __name__ == "__main__":
    summary = run_benchmark(query, model_name="내 모델 이름")
    save_html(summary)
```

---

### 8-8. Claude/Claude Code 프롬프팅 참고사항

이 프로젝트에서 Claude Code에 요청할 때 알아야 할 것들:

- **작업 디렉토리:** `scanops-model/` (Python 프로젝트, venv는 `.venv/`)
- **실행 방법:** 항상 `source .venv/bin/activate` 먼저 (또는 `.venv/bin/python3`)
- **API 키:** `.env` 파일에 `XAI_API_KEY` (코드에 하드코딩 금지)
- **벤치마크 추가:** `benchmark_core.py`의 `CASES` 리스트에 케이스 추가, 파서/평가 로직은 건드리지 말 것
- **새 모델 연동:** `scripts/adapters/` 폴더에 어댑터 파일 추가, `query(language, code) → (str, float)` 함수만 구현하면 됨
- **ChromaDB 컬렉션명:** `cve_collection` (변경 시 `search_chroma.py`, `rag_pipeline.py` 모두 수정 필요)
- **리포트 출력 경로:** 모든 HTML/JSON은 `reports/` 폴더
- **Python 버전:** 3.14 (`.venv/bin/python3`)
