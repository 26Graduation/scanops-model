# ScanOps 모델 아키텍처 정리 (노션용)

작성일: 2026-06-23 · 대상 레포: `scanops-model`

> Claude에게 구현을 맡기고 "무엇을 했는지"만 알고 "어떻게/무엇으로 했는지"는
> 흩어져 있던 내용을 한 곳에 모은 문서. 코드 경로를 함께 적어 필요하면 바로
> 찾아볼 수 있게 했다.

---

## 0. 전체 그림

```
[NVD CVE 원본 JSON]
      │ 전처리 (scanops/data/prepare.py)
      ▼
[BGE 임베딩 384차원] ──▶ [Qdrant 벡터DB: cve_vulnerabilities 컬렉션, 792개]
                                      │ search_cves() 유사도 검색
                                      ▼
[코드 입력] ──▶ [QLoRA 파인튜닝 모델: Stage 1 탐지] ──▶ [RAG: CVE 컨텍스트 보강]
                       │ 실패 시 폴백                         │
                       ▼                                      ▼
              [base 모델 + RAG: Stage 2]            [Stage1/2 응답 + CVE 근거]
                                                              │
                                                              ▼
                                              [코드 그래프(Neo4j) 근거 보정]
                                          (정적 import 오탐 억제 / 사용자입력 추적)
                                                              │
                                                              ▼
                                            [최종 응답: graph_evidence, kg_risk_score,
                                             suppressed_by_graph 포함]
```

엔드포인트: `scripts/api_server.py` (FastAPI) — `/analyze`, `/analyze/batch`, `/analyze/pr`, `/health`

---

## 1. NVD 데이터 수집·전처리

**파일:** `scanops/data/prepare.py` (전처리+적재), `scripts/fetch_nvd_live.py` (최신 CVE 라이브 수집)

- 원본: NVD REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
- `fetch_nvd_live.py`는 최근 40일 구간을 `pubStartDate`~`pubEndDate`로 잘라 페이지네이션
  수집한다 (rate limit: API 키 없을 때 5요청/30초 → 6초 슬립).
- **제외 기준** (`EXCLUDE_STATUS = {"Rejected", "Deferred"}`): NVD 데이터의 절반 이상을
  차지하는 무효/보류 상태 CVE는 RAG 학습 대상에서 제외.
- **추출 필드** (`preprocess_nvd_raw`):

| 필드 | 추출 방식 |
|---|---|
| `cve_id` | `cve.id` |
| `published` | `cve.published[:10]` (날짜만) |
| `vuln_status` | `cve.vulnStatus` (필터링용, 저장은 함) |
| `base_score`, `severity`, `attack_vector`, `cvss_vector` | `metrics.cvssMetricV31` → 없으면 `V30` → `Primary` 타입 우선, 없으면 첫 항목 |
| `cwe_id` | `weaknesses[].description[lang=en]` 중 `NVD-CWE-*`(범용 placeholder) 제외, `Primary` 타입 우선 |
| `affected_products` | `configurations[].nodes[].cpeMatch[]`에서 vendor:product 파싱, 최대 5개 |
| `description` | 영어 설명 원문 |

- 1단계 초기 정의서에는 `age_days`, `days_since_modified`, `score_version`, `cwe_primary`,
  `reference_count` 같은 파생 필드도 있었으나(`nvdcve-2.0-preprocessed.json` 산출 당시),
  현재 `prepare.py`의 운영 버전은 위 표의 필드로 단순화되어 있다.
- 산출물 예: `data/nvdcve-2.0-preprocessed.json`(초기 792개 세트), `data/nvdcve-2.0-live.json`(최신 수집분)

---

## 2. 임베딩

**파일:** `scanops/core/embedder.py`

| 항목 | 값 |
|---|---|
| 모델 | `BAAI/bge-small-en-v1.5` (로컬, 무료) |
| 차원 | 384 |
| 프리픽스 | `"Represent this sentence for searching relevant passages: "` (BGE 권장 검색 프리픽스, 쿼리·문서 양쪽 모두 동일 적용) |
| 정규화 | `normalize_embeddings=True` → L2 정규화, 따라서 **내적 = 코사인 유사도** |
| 싱글톤 | 프로세스당 1회 로드 (`threading.Lock` + 모듈 전역 캐시) |

임베딩 입력 텍스트는 CVE의 `description`(영문 원문)이며, 적재 시
`store_in_qdrant()`에서 배치(128개 단위)로 `embed_documents()` 호출.

> 참고: 1단계 설계서에는 `description + Severity + CVSS + CWE`를 합친 텍스트를
> 임베딩한다고 되어 있었지만, 현재 운영 코드(`prepare.py`)는 `description` 원문만
> 임베딩하고 나머지(severity/score/cwe 등)는 **페이로드 메타데이터**로만 저장한다 —
> 메타데이터 필터링(`severity_filter`)으로 별도 조합 가능하기 때문.

---

## 3. 벡터 DB

**현재: Qdrant** (PersistentClient가 아니라 Docker 서버 모드가 기본)

| 항목 | 값 |
|---|---|
| 접속 | `QDRANT_URL` (기본 `http://localhost:6333`), 또는 `QDRANT_PATH` 설정 시 embedded 로컬 모드 |
| 컬렉션 | `cve_vulnerabilities` (`QDRANT_COLLECTION` 환경변수) |
| 거리 함수 | Cosine |
| 벡터 차원 | 384 |
| 현재 적재량 | **792개** (기본 세트) |
| 페이로드 | `cve_id, published, vuln_status, base_score, severity, attack_vector, cwe_id, affected_products, cvss_vector, description` |
| 확장 | `python -m scanops.data.prepare --input <raw.json> --raw --recreate` 로 더 큰 NVD 피드 적재 가능 |

**히스토리:** 1~2단계 설계서 시점에는 FAISS(792개, 로컬 인덱스 파일)로 먼저
구축했다가, 메타데이터 필터링·영속성·백엔드 HTTP 연동 편의성 때문에 ChromaDB →
최종적으로 **Qdrant**로 마이그레이션했다 (`feat/hyeeun` 브랜치 방식을 채택,
`feat/sehan`의 2-stage RAG는 CVE 오염 문제로 폐기).

---

## 4. RAG 파이프라인

**파일:** `scanops/core/rag.py`, 추론 시점엔 `scripts/benchmark_qwen_rag.py`의
`search_cves` / `build_ft_rag_user_prompt` 가 실제 호출됨 (API 서버도 이 모듈 사용)

흐름 (1-stage: retrieve → generate):

1. `search_cves(query, top_k)` — 질문/코드 텍스트를 BGE로 임베딩 → Qdrant
   `query_points()`로 코사인 유사도 top-k 검색. `severity_filter`로 페이로드
   메타데이터 필터링 가능.
2. `build_prompt(query, cves)` — 검색된 CVE들을 `[CVE #n] ID/Severity/CVSS/
   Attack Vector/CWE/Products/Description` 블록으로 직렬화해 시스템 프롬프트
   + 컨텍스트 + 질문으로 합침.
3. `call_llm()` / `stream_llm()` — Ollama HTTP API(`/api/generate`)로 추론.
   - 파인튜닝 모델(`qwen2.5-coder-security*`, `gemma2-security*`)은 별도
     stop 토큰(`[EMPTY_*]`, `Human resources`, `\n\n\n` 등)과 낮은 temperature(0.1),
     `repeat_penalty=1.3`을 사용 — 소형 모델이 학습 데이터 패턴을 반복 토해내는
     문제를 줄이기 위함.
   - base 모델은 temperature 0.2, `num_predict=1024`(파인튜닝 모델은 300으로 더 짧게).

**중요 결정사항:**
- Modelfile에서 `SYSTEM` 프롬프트를 제거하고 `/api/chat`이 아닌 직접 프롬프트
  조립 방식을 사용 — Modelfile SYSTEM + 요청 SYSTEM이 중복 적용되는 문제 방지.
- 코드를 항상 마크다운 코드블록으로 감싸서 전달 — JSX의 `{}`, `<>` 등 특수문자가
  모델 프롬프트 파서에서 오인식되는 것을 방지.
- 프롬프트 순서는 **"코드 먼저 → CVE 컨텍스트 나중"** — 작은 모델이 CVE 설명
  문구에 앵커링되어 코드 내용과 무관한 취약점을 베껴 쓰는 현상을 줄이기 위함.
- Qdrant에 올라간 CVE 레코드 중 `cve_id`가 `N/A`로 비어있는 경우가 있어, 이를
  보완하기 위해 아래 5절의 **2-Stage 어댑티브 시스템**을 도입함.

---

## 5. QLoRA 파인튜닝

**파일:** `scanops/models/train_qlora.py`

| 항목 | 값 |
|---|---|
| 베이스 모델 | `Qwen/Qwen2.5-Coder-1.5B-Instruct` (기본) / `google/gemma-2-2b-it` (`--model gemma`) |
| 학습 데이터 | `data/lora_train_v4.jsonl` — **291개** `{prompt, completion}` 쌍 (v2는 203개, 19 CWE) |
| 4bit 양자화 | CUDA에서만 `bitsandbytes`(nf4, double quant) 사용. **MPS(M3)에서는 bitsandbytes 미지원**이라 float16 로 폴백 (`USE_BNB = torch.cuda.is_available()`) |
| LoRA target modules | `q_proj, k_proj, v_proj, o_proj` |
| LoRA rank (r) | **32** (v4 실제 학습값, `adapter_config.json` 확인) |
| LoRA alpha | **64** (= 2×rank, CLI 기본 `--lora-alpha 0` → 자동 계산) |
| LoRA dropout | 0.05 |
| Epochs | 3 (v4 실제 — `train_log_v4.json`: 375 step에서 종료, `epoch=3.0`) |
| Batch size | 1, gradient accumulation 8 → 실효 배치 8 |
| Learning rate | 1e-4 (cosine decay, 로그상 최종 step LR ≈ 2.17e-6) |
| 최종 train_loss | 0.29 (v4, step 375) |
| 디바이스 | MPS(M3 Mac) 자동 감지, CUDA/CPU 폴백 지원 |
| 체크포인트 | `models/qwen-security-qlora-v4/{checkpoint-250, checkpoint-375, final}` |

**채팅 포맷:** Qwen은 `<|im_start|>system/user/assistant<|im_end|>` ChatML 포맷,
Gemma-2는 `<start_of_turn>user/model<end_of_turn>` 포맷으로 각각 별도 포맷터
(`format_qwen`, `format_gemma2`) 적용 후 토크나이즈(`max_length=768`).

**데이터 형식 예시** (`data/lora_train_v4.jsonl`):
```json
{"prompt": "Analyze this Node.js / Express code for security vulnerabilities:\n\n res.send('<div>' + attackers + '</div>');",
 "completion": "VULNERABILITY: CWE-79 Cross-Site Scripting\nSEVERITY: HIGH\nATTACK: ...\nFIX:\n..."}
```
→ 학습 후 `VULNERABILITY/SEVERITY/CVSS/ATTACK/FIX` 5개 필드 고정 포맷으로
응답하도록 모델이 학습됨 (`parse_response()`가 이 포맷을 정규식으로 파싱).

**파인튜닝 데이터 선택 근거:** `feat/sehan` 브랜치의 `lora_train_v2`(203개)를
베이스로 시작해 v4까지 점진적으로 확장(291개). `feat/hyeeun` 브랜치는 RAG용
CVE 데이터(12,251개)만 있고 파인튜닝 데이터는 없어 채택하지 않음.

**Railway 배포 vs 로컬 비교 모델 선정 근거:**
- Qwen2.5-Coder-1.5B: Q4 양자화 시 ≈1GB RAM → Railway 기본 플랜에서 구동 가능 → **최종 배포 모델**
- Gemma-2 2B: Q4 양자화 시 ≈1.5GB RAM → Railway 한계치 → 로컬 비교 실험용으로만 사용

---

## 6. 어댑티브 추론 (Stage 1 → Stage 2 폴백)

**파일:** `scripts/api_server.py :: run_adaptive()` (구버전: `scripts/benchmark_qwen_rag.py :: run_scanops_adaptive()`)

```
Stage 1: QLoRA 파인튜닝 모델 (RAG 없음, MODEL_FT)
  └ VULNERABILITY가 유효한 이름 + SEVERITY 존재 → 성공 → RAG로 CVE 보강만 추가
  └ 실패(파싱 실패/빈 응답/헛것) → Stage 2로 폴백
Stage 2: base 모델(MODEL_BASE=qwen2.5-coder:1.5b) + Qdrant RAG 컨텍스트
  └ Stage1이 식별한 취약점명을 CVE 검색 쿼리 힌트로 재사용
```

- **헛것(hallucination) 필터:** `_is_valid_vuln_name()` — CWE-ID 패턴이거나
  `_VALID_VULN_TERMS`(xss, sql injection, ssrf, idor 등 40여개 키워드) 중 하나라도
  포함해야 진짜 취약점명으로 인정. "AI Assistant", "On the first line" 같은 LLM
  잡설을 걸러냄.
- **PR 스캔(`/analyze/pr`) 전용 보강:** Stage1+Stage2 raw 응답을 모두 합쳐
  `_parse_all_blocks()`로 여러 취약점 블록을 한 번에 파싱(중복 제거). 추가로
  `_SINK_RULES`(정규식 기반 eval/XSS/SSRF 결정적 탐지)로 LLM이 놓친 고신호
  위험 패턴을 무조건 탐지하는 안전망을 둠.

---

## 7. 코드 그래프 (Neo4j) — 그래프 기반 오탐 억제/사용자입력 추적

**파일:** `scanops/core/code_graph.py` (`feat/kyungyun` 브랜치에서 merge, 2026-06-23)

LLM이 1차로 "XSS다/SSRF다"라고 판단한 결과를, **실제 데이터 흐름 그래프**로
재검증하는 단계. 정규식 기반 경량 정적 분석으로 아래 그래프를 추출한다:

```
File ─DECLARES─▶ Variable ─RESOLVES_TO─▶ StaticImport   (정적 asset import)
                     │
                     ├─FLOWS_TO──◀ UserInput            (URLSearchParams/req.query 등)
                     │
                     └─PASSED_AS_PROP─▶ Variable(다른 파일의 prop) ─FLOWS_TO─▶ DangerousSink
File ─DECLARES_COMPONENT─▶ Component ─DECLARES_PROP─▶ Prop
```

- `NEO4J_URI` 환경변수가 설정되어 있으면 `evidence_from_neo4j()`가 Cypher
  쿼리로 동일한 판정을 수행(데모 시 Neo4j Browser로 그래프 시각화 가능,
  `sync_to_neo4j()`가 분석마다 그래프를 적재). 미설정 시 인메모리 `CodeGraph`로
  자동 폴백 — Neo4j 없이도 API가 동작함.
- **판정 로직** (`evidence()` / `should_suppress_finding()` / `kg_risk_score()`):
  - 소스가 정적 asset import(`.png/.svg/.css` 등) → `verdict="safe"` → XSS 오탐
    억제(`suppressed_by_graph=true`, `severity=INFO`, `kg_risk_score=0.0`)
  - 소스가 `UserInput`(URLSearchParams/req.query/location 등)이고 prop을 거쳐
    위험 sink(`img src`, `innerHTML`, `dangerouslySetInnerHTML`, `fetch`,
    `axios.*`)에 도달 → `verdict="tainted"` → 탐지 유지 + `kg_risk_score` +0.9
  - 둘 다 증명 못하면 `verdict="unknown"` → 점수만 소폭 하향(-0.2), 탐지 유지

**검증된 3가지 시나리오** (`tests/test_code_graph.py`,
`scripts/benchmark_graph_vs_grok.py`):

| 케이스 | 코드 흐름 | 정답 | ScanOps 그래프 근거 |
|---|---|---|---|
| ① | `HanLogo`(정적 import) → prop → `<img src={HanLogo}>` | SAFE | `suppressed_by_graph=true` |
| ② | `URLSearchParams.get('img')` → prop → `<img src={logo}>` | XSS 위험 유지 | `verdict=tainted` |
| ③ | `URLSearchParams.get('api')` → `fetch(apiUrl)` | SSRF 위험 유지 | `verdict=tainted` |

---

## 8. 벤치마크 방법론

### 8-1. 탐지율·오탐률 벤치마크 (NVD 2026 100케이스)
**파일:** `scripts/benchmark_v5_cases.py`(케이스 정의) + `scripts/benchmark_v5.py`(실행)
→ `reports/results_v5_false_positive_benchmark.json`

- 양성 50개: **2026년 5~6월 NVD 신규 공개 CVE**(예: CVE-2026-11585, CVE-2026-8977 등)
  를 코드 패턴으로 재구성. Grok/GPT 등 프런티어 모델의 학습 컷오프 이후
  공개된 CVE라 "암기"가 불가능 → RAG 강점 검증용.
- 음성 50개: parameterized query, 출력 escaping, allow-list, authz 체크,
  SecureRandom 등 **실제 mitigation이 적용된 안전 코드** + 순수 비즈니스 로직.
- 같은 adjudication 프롬프트(`ADJ_PROMPT`)로 ScanOps(FT+게이트)와
  Grok-3-mini를 **LLM만 교체해 공정 비교**. 정적 mitigation 패턴 매칭
  (`mitigation_safe()`)을 1차 필터로 두고 LLM 판정을 보정하는 하이브리드 방식.
- 측정 지표: TP/FN/FP/TN, recall, FPR, precision, accuracy, F1, 평균 응답시간.

### 8-2. 코드 그래프 비교 벤치마크 (신규, 2026-06-23)
**파일:** `scripts/benchmark_graph_vs_grok.py` → `reports/results_graph_vs_grok.json`

- 7절의 3가지 그래프 시나리오를 ScanOps(FT 모델 1차 탐지 + 그래프 보정)와
  Grok-3-mini(동일 멀티파일 코드, 그래프 없이 텍스트만)에 동일하게 입력해
  VULNERABLE/SAFE 이진 판정 정확도를 비교.
- 목적: "모델 크기"가 아니라 "그래프 기반 데이터 흐름 추적"이라는
  **아키텍처 차이**가 멀티파일 오탐/누락에 미치는 영향을 분리해서 측정.

### 8-3. 최종 결과 요약

| 벤치마크 | ScanOps | Grok-3-mini |
|---|---|---|
| NVD 2026 100케이스 — 탐지율 | 92.0% | 86.0% |
| NVD 2026 100케이스 — 오탐률 | 6.0% | 0.0% |
| NVD 2026 100케이스 — 정확도 | 93.0% | 93.0% |
| NVD 2026 100케이스 — 평균응답 | 0.2s | 2.14s |
| 코드 그래프 3케이스 — 정확도 | 100% (3/3) | 33.3% (1/3) |

전체 정확도는 비슷하지만(93%) ScanOps가 최신 CVE를 더 많이 잡고(+6%p
recall), 10배 이상 빠르며, 멀티파일 데이터 흐름이 필요한 케이스에서는
Grok이 구조적으로 약하다는 것을 확인했다. 상세 해석은
`reports/ScanOps_vs_Grok_그래프벤치마크_v6.md` 참고.

---

## 9. 재현 명령어 모음

```bash
cd scanops-model
source .venv/bin/activate

# Qdrant 적재 (기본 792개, 더 큰 피드는 --raw --input)
python -m scanops.data.prepare

# 최신 NVD CVE 라이브 수집 (최근 40일)
python scripts/fetch_nvd_live.py

# QLoRA 파인튜닝
python -m scanops.models.train_qlora --model qwen --epochs 3 --lora-r 32

# 벤치마크
python scripts/benchmark_v5.py                 # NVD 100케이스 vs Grok
python scripts/benchmark_graph_vs_grok.py       # 코드 그래프 3케이스 vs Grok

# API 서버 (백엔드 연동용)
uvicorn scripts.api_server:app --host 0.0.0.0 --port 8100 --reload

# CLI
scanops scan/chat/benchmark/db-prepare
```
