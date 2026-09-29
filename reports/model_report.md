# ScanOps — 보안 특화 LLM 개발 보고서

> 실행 환경: M3 MacBook Air 8GB · Python 3.14 venv · 2026-05-13  
> 핵심 목표: **외부 API 없이 완전 로컬에서 동작하는 보안 취약점 탐지 AI**

---

## 1. 모델 선정 및 교체 이력

| 단계 | 모델 | 탐지율 | 비고 |
|------|------|--------|------|
| 1차 | Gemma 2B (Ollama, 로컬) | 35% | 베이스라인 — 무료 |
| 2차 (실험) | xAI Grok API (grok-3) | 100% | 유료 API, 외부 의존성 |
| **3차 (최종)** | **Gemma-2 2B IT + LoRA 파인튜닝** | **85%** | **완전 무료, 완전 로컬** |

### 최종 모델 선택 이유

Grok API는 성능이 높지만 졸업과제의 핵심 목표인 **"자체 개발 보안 AI"** 와 맞지 않음.

- 유료 API에 완전히 의존 → 기술적 기여 없음
- 외부 서버 전송 → 보안 취약 코드를 외부로 보내는 아이러니
- 로컬 모델 + LoRA 파인튜닝으로 Grok 수준(85%)에 도달 가능 → API 불필요

---

## 2. 학습 데이터 구성

### 2-1. 데이터 확장 과정

| 버전 | 파일 | 데이터 수 | 방법 |
|------|------|----------|------|
| v1 | `lora_train.jsonl` | 50개 | 수동 작성 |
| **v2** | **`lora_train_v2.jsonl`** | **203개** | **수동 + NVD 자동 생성** |

### 2-2. 데이터 생성 방식 (`generate_train_augment.py`)

**외부 API 없이** 두 가지 방법으로 데이터를 4배 확장:

1. **수동 작성 패턴 확장** — 기존 50개 + 신규 취약점 유형 직접 작성
2. **NVD CVE 템플릿 자동 생성** — `nvdcve-2.0-preprocessed.json` (792개 CVE) 에서 CWE 태그를 추출해 코드 템플릿에 적용

```
nvdcve-2.0-preprocessed.json (792개 CVE description + CWE 태그)
        ↓  CWE별 코드 템플릿 적용 (rag_local이 아닌 로컬 생성)
lora_train_v2.jsonl (203개 코드 + 취약점 분석)
```

### 2-3. CWE 분포 (최종 203개)

| CWE | 취약점명 | 케이스 수 | 주요 언어 |
|-----|---------|----------|----------|
| CWE-79 | Cross-Site Scripting (XSS) | 39 | React, Python, Node.js, Java |
| CWE-284 | Improper Access Control | 26 | Python, Java, Node.js |
| CWE-89 | SQL Injection | 22 | Python, Java, Node.js, PHP |
| CWE-22 | Path Traversal | 20 | Python, Java, Node.js, PHP |
| CWE-78 | OS Command Injection | 20 | Python, Node.js, Java, PHP |
| CWE-77 | Command Injection (CI/CD) | 13 | GitHub Actions YAML |
| CWE-416 | Use After Free | 12 | C, C++ |
| CWE-200 | Sensitive Data Exposure | 9 | Python, Java, Node.js |
| CWE-125 | Out-of-Bounds Read | 8 | C, C++ |
| CWE-190 | Integer Overflow | 7 | C, Java, Python |
| CWE-798 | Hardcoded Credentials | 5 | Python, Java, Node.js |
| CWE-502 | Insecure Deserialization | 4 | Python, Java, Node.js |
| 기타 7개 | SSRF, CSRF, XXE, DoS 등 | 18 | 다양 |
| **합계** | | **203** | |

### 2-4. 학습 데이터 형식

```json
{
  "prompt": "Analyze this Python code for security vulnerabilities:\n\nimport subprocess\nsubprocess.call(user_input, shell=True)\n\nVULN_TYPE:",
  "completion": "CWE-78 OS Command Injection\nSEVERITY: CRITICAL\nATTACK: Attacker injects '; cat /etc/passwd' via user_input to read system files.\nFIX:\nsubprocess.call(['safe_cmd', user_input], shell=False)"
}
```

---

## 3. LoRA 파인튜닝 설정

### 3-1. 모델 업그레이드 이유

| 항목 | 기존 | 변경 |
|------|------|------|
| 베이스 모델 | TinyLlama-1.1B-Chat | **google/gemma-2-2b-it** |
| 파라미터 수 | 1.1B | **2.0B** |
| 아키텍처 | LLaMA 1세대 | **Gemma 2 (Google, 2024)** |
| 코드 이해 능력 | 낮음 | **중상 (보안 추론 가능)** |
| 메모리 사용 | ~2GB | ~5GB (LoRA 학습 시) |
| M3 8GB 학습 | 가능 | **가능 (MPS 백엔드)** |

### 3-2. LoRA 하이퍼파라미터

| 파라미터 | 값 | 변경 이유 |
|---------|-----|----------|
| 베이스 모델 | google/gemma-2-2b-it | Gemma 2, instruction-tuned |
| LoRA rank (r) | **16** | 기존 8 → 16 (더 많은 파라미터 학습) |
| lora_alpha | **32** | r의 2배 (표준 설정) |
| target_modules | **q_proj, k_proj, v_proj, o_proj** | Gemma-2 전체 어텐션 헤드 |
| lora_dropout | 0.05 | 동일 |
| Epochs | **5** | 기존 3 → 5 (203개 데이터 충분히 학습) |
| Batch size | 1 | M3 메모리 한계 |
| Gradient accumulation | **8** | Effective batch = 8 |
| Learning rate | **1e-4** | 기존 2e-4 → 1e-4 (안정적 수렴) |
| max_length | **768** | 기존 512 → 768 (긴 코드 처리) |
| Device | MPS (Apple Metal) | M3 GPU 활용 |
| Trainable params | ~13M / 2B (0.65%) | |

### 3-3. Gemma-2 IT 학습 형식

Gemma-2 Instruction Tuned 모델의 채팅 형식에 맞게 래핑:

```
<start_of_turn>user
Analyze this Python code for security vulnerabilities:

{code}

VULN_TYPE:<end_of_turn>
<start_of_turn>model
CWE-78 OS Command Injection
SEVERITY: CRITICAL
ATTACK: ...
FIX: ...<end_of_turn>
```

---

## 4. 학습 Loss 곡선

| Step | Epoch | Loss | 비고 |
|------|-------|------|------|
| 10 | 0.39 | 2.909 | 초기 |
| 20 | 0.79 | 1.649 | |
| 30 | 1.16 | 1.320 | |
| 40 | 1.55 | 1.108 | |
| 50 | 1.95 | 1.021 | |
| 60 | 2.32 | 0.914 | |
| 70 | 2.71 | 0.844 | |
| 80 | 3.08 | 0.797 | |
| 90 | 3.47 | 0.808 | |
| 100 | 3.87 | 0.710 | |
| 110 | 4.24 | 0.698 | |
| 120 | 4.63 | 0.711 | |
| **130** | **5.0** | **0.692** | **최종** |

- Loss 2.909 → 0.692, **76.2% 감소**
- 학습 시간: **2,855초 (약 48분)**, M3 MPS 백엔드
- 안정적 수렴 확인 (epoch 4 이후 0.69~0.71 수렴)

---

## 5. 최종 탐지율 비교

### 5-1. 전체 모델 비교

**테스트:** 20개 코드 취약점 케이스 (React, Node.js, Java, Python, C, GitHub Actions)

| 모델 | 탐지율 | 탐지 수 | 평균 응답시간 | 비용 | 인터넷 필요 |
|------|--------|---------|------------|------|-----------|
| Gemma 2B Ollama (베이스라인) | 35% | 7/20 | 4.27s | 무료 | ❌ |
| RAG + Gemma 2B | 35% | 7/20 | 3.47s | 무료 | ❌ |
| **Gemma-2 2B LoRA (최종)** | **85%** | **17/20** | **5.09s** | **무료** | **❌** |
| xAI Grok API (grok-3-mini) | 65% | 13/20 | 18.3s | 유료 | ✅ |
| xAI Grok API (grok-3) | 100% | 20/20 | 5.72s | 유료 | ✅ |

> **핵심:** 로컬 LoRA 모델(85%)이 유료 Grok-3-mini(65%)를 **+20%p 초과**. 비용 0원.

### 5-2. 언어별 탐지율

| 언어 | 베이스라인 (Gemma 2B) | LoRA 파인튜닝 | 변화 |
|------|---------------------|-------------|------|
| React / Next.js | 2/4 (50%) | 3/4 (75%) | ↑+1 |
| Node.js / Express | 1/4 (25%) | 4/4 (100%) | ↑+3 |
| Java Spring Boot | 2/4 (50%) | 3/4 (75%) | ↑+1 |
| Python | 1/4 (25%) | 4/4 (100%) | ↑+3 |
| C | 1/2 (50%) | 2/2 (100%) | ↑+1 |
| GitHub Actions YAML | 0/2 (0%) | 1/2 (50%) | ↑+1 |

### 5-3. 탐지 실패 케이스 (3개)

| # | 취약점 | 실패 이유 |
|---|--------|----------|
| #7 | Insecure CORS | `Access-Control-Allow-Origin: *` — 설정값만 있어 의미 추론 필요 |
| #11 | Overly Permissive Endpoint | `/**` 와일드카드가 과도함을 추론해야 함 |
| #12 | Timing Attack | `password.equals()` → Timing Attack 연결이 비직관적 |

> RAG CVE 컨텍스트 추가 시 개선 가능성 있음 (현재 RAG는 더 강한 베이스 모델 필요)

---

## 6. 시스템 아키텍처 (최종, Grok-free)

### 6-1. 전체 파이프라인

```
[사용자 코드 입력]
       │
       ▼
┌─────────────────────────────────────────┐
│         로컬 보안 분석 파이프라인          │
│                                         │
│  옵션 A: LoRA 직접 추론                  │
│    HuggingFace gemma-2-2b-it            │
│    + LoRA 어댑터 (models/gemma2-lora/)  │
│    → MPS(M3 GPU) 로컬 실행              │
│                                         │
│  옵션 B: RAG + Ollama                   │
│    1. 코드 → Ollama(gemma:2b) 탐지      │
│    2. CWE → ChromaDB 유사 CVE 검색      │
│       (BAAI/bge-small-en-v1.5 임베딩)   │
│    3. CVE 근거 포함 재탐지               │
└─────────────────────────────────────────┘
       │
       ▼
[취약점 분석 결과]
 - VULNERABILITY: 취약점명 + CWE ID
 - SEVERITY: CRITICAL/HIGH/MEDIUM/LOW
 - ATTACK: 공격 시나리오
 - FIX: 수정 코드
 - CVE References: 실제 유사 CVE 목록
```

### 6-2. 핵심 파일 구조

```
scanops-model/
├── data/
│   ├── nvdcve-2.0-preprocessed.json   ← 792개 NVD CVE (RAG + 데이터 생성 원본)
│   ├── lora_train.jsonl               ← v1 학습 데이터 50개
│   └── lora_train_v2.jsonl            ← v2 학습 데이터 203개 ★
├── models/
│   └── gemma2-security-lora/          ← Gemma-2 LoRA 어댑터 ★
├── chroma_db/
│   └── cve_collection                 ← 792개 CVE 임베딩 (ChromaDB)
├── scripts/
│   ├── generate_train_augment.py      ← 데이터 증강 (NVD → 코드 예제) ★
│   ├── lora_finetune.py               ← LoRA 학습 (gemma-2-2b-it, MPS) ★
│   ├── rag_local.py                   ← RAG 파이프라인 (Ollama, Grok-free) ★
│   ├── benchmark_local.py             ← 로컬 벤치마크 (baseline/lora/rag/all) ★
│   ├── vectorize_cve.py               ← NVD → ChromaDB 임베딩
│   └── (기존 Grok 관련 파일 유지)
└── reports/
    ├── benchmark_local_*.html         ← 최신 비교 보고서 ★
    └── lora_train_loss.json           ← 학습 loss 로그
```

### 6-3. 사용 중인 모델 및 라이브러리

| 역할 | 모델/라이브러리 | 비고 |
|------|--------------|------|
| **LLM (파인튜닝)** | google/gemma-2-2b-it + LoRA | HuggingFace, 로컬 실행 |
| **LLM (추론 서빙)** | gemma:2b (Ollama) | 로컬, RAG 파이프라인용 |
| **임베딩 (RAG)** | BAAI/bge-small-en-v1.5 | sentence-transformers, 로컬 |
| **벡터 DB** | ChromaDB | PersistentClient |
| **파인튜닝 프레임워크** | HuggingFace PEFT + Transformers | LoRA 어댑터 |
| **학습 백엔드** | PyTorch MPS (Apple Metal) | M3 GPU 활용 |

---

## 7. 재현 방법

```bash
cd scanops-model

# 1. 학습 데이터 생성 (50 → 203개)
.venv/bin/python3 scripts/generate_train_augment.py

# 2. LoRA 파인튜닝 (HF 토큰 필요, ~48분)
export HF_TOKEN=hf_xxxx
.venv/bin/python3 scripts/lora_finetune.py

# 3. 전체 벤치마크 (baseline vs RAG vs LoRA)
.venv/bin/python3 scripts/benchmark_local.py --mode all

# 4. LoRA만 빠르게 테스트
.venv/bin/python3 scripts/benchmark_local.py --mode lora
```

---

## 8. 성과 요약

| 항목 | 기존 (Grok 의존) | 최종 (완전 로컬) |
|------|----------------|----------------|
| 탐지율 | 100% (Grok-3) | **85% (LoRA)** |
| 비용 | 유료 API | **$0** |
| 인터넷 의존 | 필수 | **없음** |
| 기술 기여 | API 호출만 | **데이터 구축 + 파인튜닝** |
| 학습 데이터 | 없음 | **203개 보안 특화 데이터셋** |
| 모델 소유 | xAI 소유 | **자체 어댑터 보유** |

**결론:** Grok-3 대비 탐지율 -15%p이지만, 완전 무료·완전 로컬·자체 개발 모델로 졸업과제의 기술적 기여를 직접 증명할 수 있음.
유료 API를 쓰는 것은 "사용"이고, LoRA 파인튜닝은 "개발"임.
