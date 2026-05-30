# ScanOps AI 모델 — 기술 스택 전체 정리

> 작성일: 2026-05-27  
> 프로젝트: 26Graduation / scanops-model  
> 목표: 코드 취약점 자동 탐지 AI — 외부 API 없이 완전 로컬/자체 서버 운용

---

## 1. 시스템 전체 아키텍처

```
[사용자 코드 입력]
       │
       ▼
┌──────────────────────────────────────────────────┐
│           ScanOps Adaptive 분석 파이프라인           │
│                                                  │
│  Stage 1 ── QLoRA 파인튜닝 모델 (no RAG)           │
│    모델: qwen2.5-coder-security-v2 (Ollama)        │
│    → 빠른 응답, 16/20 케이스 처리                   │
│                                                  │
│  Stage 2 ── Base 모델 + Qdrant RAG (폴백)          │
│    모델: qwen2.5-coder:1.5b (Ollama)               │
│    CVE 검색: Qdrant (BAAI/bge-small-en-v1.5)      │
│    → Stage 1 미탐지 케이스 추가 처리                 │
└──────────────────────────────────────────────────┘
       │
       ▼
 FastAPI (api_server.py) → Spring Boot 백엔드 연동
```

---

## 2. LLM (추론 모델)

### 2-1. 배포 모델 (Railway Ollama)

| 역할 | 모델 | 크기 | 용도 |
|------|------|------|------|
| **Stage 1 — Fine-tuned** | `qwen2.5-coder-security-v2:latest` | ~987 MB | QLoRA 파인튜닝 완료, 취약점 직접 분석 |
| **Stage 2 — Base** | `qwen2.5-coder:1.5b` | ~986 MB | RAG 컨텍스트와 결합해 폴백 분석 |

- **베이스 모델**: `Qwen/Qwen2.5-Coder-1.5B-Instruct` (HuggingFace)
- **GGUF 변환**: Q4_K_M 양자화 → 1GB 미만 (Railway 기본 플랜 RAM 내 운용)
- **HuggingFace 공개 저장소**: `SehanKim/qwen2.5-coder-security-v2-gguf`
- **Ollama 서비스 URL**: `https://ollama-production-ac66.up.railway.app`

### 2-2. 모델 선정 경위

| 단계 | 모델 | 탐지율 | 제거 이유 |
|------|------|--------|----------|
| 1차 | TinyLlama-1.1B-Chat | ~35% | 코드 이해 능력 부족 |
| 2차 | Gemma-2 2B IT + LoRA | 85% | Railway RAM 초과 (Q4 ≈1.5GB) |
| 2차 (비교) | Grok-3 API | 95% | 유료 외부 API, 코드 외부 전송 |
| **최종** | **Qwen2.5-Coder-1.5B + QLoRA** | **95%** | **Q4 ≈1GB, Railway 운용 가능, 자체 개발** |

> Qwen2.5-Coder는 코딩 특화 사전학습으로 동일 파라미터 대비 보안 코드 이해도가 높음

---

## 3. 파인튜닝 (QLoRA)

### 3-1. 파인튜닝 방식

| 항목 | 값 |
|------|-----|
| **방법** | QLoRA (PEFT — Parameter-Efficient Fine-Tuning) |
| **프레임워크** | HuggingFace `transformers` + `peft` + `accelerate` |
| **디바이스** | Apple MPS (M3 MacBook Air 8GB) |
| **양자화** | CUDA 환경: bitsandbytes 4-bit / MPS 환경: float16 fallback |

### 3-2. LoRA 하이퍼파라미터 (v4 최종)

| 파라미터 | 값 | 설명 |
|---------|-----|------|
| `lora_r` | **32** | LoRA rank — 학습 파라미터 수 결정 |
| `lora_alpha` | **64** | r의 2배 (표준 스케일링) |
| `target_modules` | `q_proj, k_proj, v_proj, o_proj` | 전체 어텐션 헤드 대상 |
| `lora_dropout` | 0.05 | 과적합 방지 |
| 학습 가능 파라미터 | ~25M / 1.5B (약 1.7%) | |

### 3-3. 학습 설정 (v4)

| 파라미터 | 값 |
|---------|-----|
| `num_train_epochs` | **8** |
| `per_device_train_batch_size` | 1 |
| `gradient_accumulation_steps` | 8 → **effective batch = 8** |
| `learning_rate` | 1e-4 |
| `max_seq_length` | 512 |
| `eval_strategy` | epoch |
| `load_best_model_at_end` | True |
| 학습 시간 | **23.9분** (M3 MPS) |

### 3-4. 학습 Loss 곡선 (v4)

| Checkpoint | Epoch | Train Loss | Eval Loss |
|-----------|-------|------------|-----------|
| 33 | 1 | 2.580 | 0.9764 |
| 66 | 2 | — | 0.6892 |
| 99 | 3 | — | 0.6186 |
| 132 | 4 | — | 0.5936 |
| **165** | **5** | — | **0.5933** ← 최적 |
| 198 | 6 | — | 0.6051 |
| 231 | 7 | — | 0.6199 |
| 264 | 8 | 0.384 | 0.6295 |

- 최적 체크포인트: **checkpoint-165** (eval_loss=0.5933)
- `load_best_model_at_end=True` 로 자동 선택됨

### 3-5. 채팅 포맷 (Qwen 2.5 Instruct)

```
<|im_start|>system
You are a security code analyzer.<|im_end|>
<|im_start|>user
Analyze this Python code for security vulnerabilities:

```python
{취약한 코드}
```

Respond starting with VULNERABILITY: on the first line.<|im_end|>
<|im_start|>assistant
VULNERABILITY: CWE-78 OS Command Injection
SEVERITY: CRITICAL
ATTACK: user_input이 shell=True로 전달돼 임의 OS 명령 실행 가능
FIX:
subprocess.run(['safe_cmd', user_input], shell=False)<|im_end|>
```

---

## 4. 학습 데이터

### 4-1. 데이터 버전 이력

| 버전 | 파일 | 샘플 수 | 비고 |
|------|------|---------|------|
| v1 | `lora_train.jsonl` | 50개 | 수동 작성 |
| v2 | `lora_train_v2.jsonl` | 203개 | NVD CVE 기반 자동 증강 |
| v3 | `lora_train_v3.jsonl` | 241개 | 다국어·언어 균형 보완 |
| **v4** | **`lora_train_v4.jsonl`** | **291개** | **19 CWE → 40 CWE 확장** |
| 추가 | `lora_train_v4_additional.jsonl` | **68개** | 부족 CWE 보충 (2026-05-27) |

### 4-2. v4 기준 CWE 분포 (상위 10개)

| CWE | 취약점 | 샘플 수 |
|-----|--------|---------|
| CWE-79 | Cross-Site Scripting (XSS) | 46 |
| CWE-89 | SQL Injection | 33 |
| CWE-78 | OS Command Injection | 32 |
| CWE-284 | Improper Access Control | 28 |
| CWE-22 | Path Traversal | 25 |
| CWE-77 | Command Injection | 14 |
| CWE-416 | Use After Free | 12 |
| CWE-798 | Hardcoded Credentials | 11 |
| CWE-502 | Insecure Deserialization | 10 |
| CWE-200 | Sensitive Data Exposure | 9 |
| 기타 30개 | SSRF, CSRF, XXE, ReDoS 등 | 91 |

### 4-3. 학습 데이터 형식

```json
{
  "prompt": "Analyze this Python code for security vulnerabilities:\n\nimport subprocess\nsubprocess.call(user_input, shell=True)",
  "completion": "VULNERABILITY: CWE-78 OS Command Injection\nSEVERITY: CRITICAL\nATTACK: user_input이 shell=True로 subprocess에 전달돼 임의 OS 명령 실행 가능\nFIX:\nsubprocess.run(['safe_cmd', user_input], shell=False)"
}
```

---

## 5. RAG (Retrieval-Augmented Generation)

### 5-1. 벡터 DB

| 항목 | 값 |
|------|-----|
| **벡터 DB** | **Qdrant** |
| 데이터 소스 | NVD (National Vulnerability Database) CVE |
| CVE 항목 수 | **12,251개** (Railway 서비스) / 792개 (로컬 embedded) |
| 컬렉션 이름 | `cve_vulnerabilities` |
| 유사도 메트릭 | Cosine similarity |
| Qdrant 서비스 URL | `https://qdrant-production-3ef0.up.railway.app` |

### 5-2. 임베딩 모델

| 항목 | 값 |
|------|-----|
| **임베딩 모델** | **BAAI/bge-small-en-v1.5** |
| 프레임워크 | `sentence-transformers` |
| 벡터 차원 | **384차원** |
| 정규화 | L2 normalize (cosine 계산용) |
| 쿼리 prefix | `"Represent this sentence for searching relevant passages: "` |
| 실행 환경 | 로컬 CPU (Railway api_server 컨테이너 내 실행) |

### 5-3. RAG 파이프라인 (1-stage)

```
[코드 입력]
    → 쿼리 생성: "{언어} {취약점명} {코드 앞 120자}"
    → BAAI/bge-small-en-v1.5 임베딩 (384d)
    → Qdrant cosine search (top_k=5)
    → CVE 컨텍스트 프롬프트에 삽입
    → Qwen2.5-Coder:1.5b 응답 생성
```

> 2-stage RAG (sehan 브랜치)는 CVE 오염 문제로 채택하지 않음

---

## 6. Adaptive 시스템 (최종 배포 구조)

```python
# Stage 1: 파인튜닝 모델로 빠르게 시도
resp = call_model(prompt, "qwen2.5-coder-security-v2:latest", is_finetuned=True)
if detected(resp):                # 취약점 탐지 성공
    return stage=1, result

# Stage 2: base + RAG 폴백 (Stage 1 미탐지 케이스)
cves = qdrant.search(code_query, top_k=5)
resp = call_model(rag_prompt, "qwen2.5-coder:1.5b", is_finetuned=False)
return stage=2, result
```

- Stage 1 처리: **16/20 케이스** (응답 2.71s 평균)
- Stage 2 폴백: **4케이스 중 3케이스 추가 탐지**
- 최종 탐지율: **95% (19/20)**

---

## 7. 벤치마크 결과

> 테스트 셋: 20개 케이스 (Python, Java, Node.js, C, React, GitHub Actions YAML)

| 모델 | 탐지율 | 평균 응답시간 | 비용 | 비고 |
|------|--------|------------|------|------|
| Gemma:2b (base, Ollama) | 90.0% | 4.29s | 무료 | 베이스라인 |
| Qwen2.5-Coder-1.5B (base) | 85.0% | 1.43s | 무료 | |
| Qwen2.5-Coder + Qdrant RAG | 85.0% | 1.43s | 무료 | |
| Qwen QLoRA v2 (no RAG) | 80.0% | 2.05s | 무료 | 파인튜닝 단독 |
| Qwen QLoRA v2 + Qdrant RAG | 85.0% | 4.35s | 무료 | |
| **ScanOps v2 Adaptive** | **95.0%** | **2.71s** | **무료** | **최종 배포 버전** |
| Grok-3 API (비교) | 95.0% | 17.66s | 유료 | 외부 API |
| ScanOps RAG v2 (Qdrant+Grok-3) | 100.0% | 5.45s | 유료 | Grok-3 기반 |

**핵심 성과**: 유료 Grok-3 API와 동일한 95% 탐지율을 비용 $0, 응답속도 6.5배 빠르게 달성

---

## 8. 배포 인프라

### 8-1. Railway 서비스 구성

| 서비스 | 역할 | URL |
|--------|------|-----|
| **scanops-model** | FastAPI API 서버 | `https://scanops-model-production.up.railway.app` |
| **ollama** | LLM 추론 서버 | `https://ollama-production-ac66.up.railway.app` |
| **qdrant** | 벡터 DB | `https://qdrant-production-3ef0.up.railway.app` |

### 8-2. API 서버 (FastAPI)

| 항목 | 값 |
|------|-----|
| 프레임워크 | FastAPI + uvicorn |
| 주요 엔드포인트 | `POST /analyze`, `POST /analyze/batch`, `GET /health` |
| 파일 | `scripts/api_server.py` |
| Docker | `Dockerfile` (python:3.11-slim) |

### 8-3. Ollama 모델 등록 현황

```
qwen2.5-coder-security-v2:latest    987 MB   ← Stage 1 (파인튜닝)
hf.co/SehanKim/qwen2.5-coder-security-v2-gguf:Q4_K_M  987 MB  ← 원본
qwen2.5-coder:1.5b                  986 MB   ← Stage 2 (base)
```

### 8-4. 환경변수

```env
QDRANT_URL=https://qdrant-production-3ef0.up.railway.app
QDRANT_COLLECTION=cve_vulnerabilities
OLLAMA_URL=https://ollama-production-ac66.up.railway.app
OLLAMA_MODEL=qwen2.5-coder:1.5b
PORT=8100
```

---

## 9. 백엔드 연동

Spring Boot `scanops-backend`의 `ScanopsModelClient.java`가 Railway API 서버를 호출:

```java
// application.yml 또는 환경변수
scanops.model.url=https://scanops-model-production.up.railway.app

// POST /analyze 요청
{
  "language": "Python",
  "code": "...",
  "use_rag": true
}

// 응답
{
  "detected": true,
  "stage": 1,
  "vulnerability": "CWE-78 OS Command Injection",
  "severity": "CRITICAL",
  "attack": "user_input이 shell=True로 전달돼 임의 OS 명령 실행 가능",
  "fix": "subprocess.run(['cmd'], shell=False)",
  "cve_references": [...]
}
```

---

## 10. 핵심 파일 구조

```
scanops-model/
├── data/
│   ├── lora_train_v4.jsonl              ← 파인튜닝 데이터 291개 (v4)
│   ├── lora_train_v4_additional.jsonl   ← 추가 데이터 68개 (2026-05-27)
│   └── nvdcve-2.0-preprocessed.json     ← NVD CVE 원본
├── models/
│   ├── qwen-security-qlora/             ← QLoRA 어댑터 (checkpoint-165 최적)
│   │   ├── adapter_config.json
│   │   ├── adapter_model.safetensors
│   │   └── checkpoint-165/             ← eval_loss=0.5933 최적
│   └── qwen-security-v2.Q4_K_M.gguf   ← Ollama용 GGUF (Q4, ~987MB)
├── scanops/
│   ├── core/
│   │   ├── embedder.py                 ← BAAI/bge-small-en-v1.5 싱글톤
│   │   ├── rag.py                      ← Qdrant 검색 + Ollama 스트리밍
│   │   └── scanner.py                  ← scan_code/scan_file/scan_directory
│   └── models/
│       └── train_qlora.py              ← QLoRA 학습 (Qwen/Gemma-2 선택)
├── scripts/
│   ├── api_server.py                   ← FastAPI 서버 (Adaptive 로직)
│   ├── benchmark_core.py               ← parse_response, detected()
│   ├── benchmark_qwen_rag.py           ← Adaptive 벤치마크 실행
│   └── convert_to_gguf_v2.py           ← PEFT → GGUF 변환
├── Dockerfile
└── railway.toml
```

---

## 11. 재현 방법

```bash
# 1. 설치
pip install -e .

# 2. QLoRA 파인튜닝 (로컬, ~24분)
python -m scanops.models.train_qlora --model qwen --epochs 8

# 3. GGUF 변환 → Ollama 등록
python scripts/convert_to_gguf_v2.py
ollama create qwen2.5-coder-security-v2 -f models/Modelfile_v2

# 4. CVE 벡터 DB 구축
scanops db-prepare --raw data/nvdcve-2.0-preprocessed.json

# 5. Adaptive 벤치마크 실행
python scripts/benchmark_qwen_rag.py

# 6. API 서버 로컬 실행
uvicorn scripts.api_server:app --host 0.0.0.0 --port 8100 --reload
```

---

## 12. 결론

| 항목 | 내용 |
|------|------|
| 최종 모델 | Qwen2.5-Coder-1.5B + QLoRA (checkpoint-165) |
| 임베딩 | BAAI/bge-small-en-v1.5 (384d) |
| 벡터 DB | Qdrant (12,251 CVE) |
| 추론 서빙 | Ollama (Q4_K_M GGUF) |
| 아키텍처 | Adaptive 2-stage (Fine-tuned → Base+RAG fallback) |
| 탐지율 | **95%** (Grok-3 동급, 비용 $0, 응답 6.5배 빠름) |
| 배포 | Railway (FastAPI + Ollama + Qdrant) |
