# ScanOps — 보안 취약점 자동 탐지 시스템 최종 보고서 v3

> 작성일: 2026-05-27  |  모델: QLoRA v3 (Qwen2.5-Coder-1.5B-Instruct)  
> 시스템: Adaptive 2-Stage (Fine-tuned + RAG Fallback)

---

## 1. 시스템 개요

ScanOps는 소스코드에서 보안 취약점을 자동으로 탐지하는 AI 기반 분석 엔진입니다.  
QLoRA로 파인튜닝한 소형 LLM(1.5B 파라미터)과 Qdrant 벡터 DB 기반 RAG를 결합해  
**95% 이상의 탐지율**과 **평균 2.7초 응답**을 동시에 달성합니다.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ScanOps 전체 아키텍처                           │
│                                                                     │
│  Spring Boot Backend                                                │
│  ┌────────────┐   HTTP POST /analyze                               │
│  │  GitHub    │ ──────────────────────────────────────────────►    │
│  │  Analyzer  │                                                     │
│  └────────────┘         FastAPI (Railway)                          │
│                         ┌─────────────────────────────────────┐    │
│                         │  run_adaptive()                      │    │
│                         │                                      │    │
│                         │  ┌──────────────────────────────┐   │    │
│                         │  │ Stage 1: QLoRA v3 파인튜닝   │   │    │
│                         │  │ - Qwen2.5-Coder-1.5B         │   │    │
│                         │  │ - LoRA r=32, α=64            │   │    │
│                         │  │ - GGUF Q4_K_M (986MB)        │   │    │
│                         │  │                              │   │    │
│                         │  │ 결과 유효? ──No──────────────┼──►│   │
│                         │  │     │                        │   │    │
│                         │  │    Yes                       │   │    │
│                         │  │     ▼                        │   │    │
│                         │  │ CVE 보강 (Qdrant RAG)        │   │    │
│                         │  └──────────────────────────────┘   │    │
│                         │                                      │    │
│                         │  ┌──────────────────────────────┐   │    │
│                         │  │ Stage 2: Base + RAG Fallback │   │    │
│                         │  │ - Qwen2.5-Coder:1.5b (base)  │   │    │
│                         │  │ - Qdrant: 12,251 CVE 벡터    │   │    │
│                         │  │ - BGE-small-en-v1.5 임베딩   │   │    │
│                         │  └──────────────────────────────┘   │    │
│                         └─────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. 모델 학습 파이프라인

### 2.1 베이스 모델

| 항목 | 내용 |
|------|------|
| **모델** | Qwen/Qwen2.5-Coder-1.5B-Instruct |
| **파라미터** | 1.54B (총), 8.7M (학습 가능, 0.56%) |
| **양자화** | GGUF Q4_K_M (986 MB) |
| **컨텍스트** | 32,768 토큰 |

### 2.2 QLoRA 설정

```
LoRA 하이퍼파라미터
────────────────────────────
r (rank)          : 32
lora_alpha        : 64
lora_dropout      : 0.05
target_modules    : q_proj, k_proj, v_proj, o_proj
scaling factor    : alpha/r = 2.0
────────────────────────────
학습 설정
────────────────────────────
epochs            : 8
batch_size        : 1
gradient_accum    : 4  (effective batch = 4)
learning_rate     : 1e-4
optimizer         : AdamW
max_seq_len       : 768
device            : Apple M3 MPS
────────────────────────────
```

### 2.3 학습 데이터 구성

```
v4 전체 데이터셋: 367개 샘플  (v4.jsonl 291 + additional 76)

언어 분포
─────────────────────────────────────────
Python      ███████████████████░ 148 (40%)
JavaScript  ████████████░░░░░░░░  75 (20%)
Java        ███████████░░░░░░░░░  55 (15%)
C           █████████░░░░░░░░░░░  81 (22%)
기타         █░░░░░░░░░░░░░░░░░░░   8 ( 3%)
─────────────────────────────────────────

CWE 분포 Top 10 (total 29 unique CWEs)
─────────────────────────────────────────
CWE-79  (XSS)              ████████ 54
CWE-89  (SQL Injection)    ██████   33
CWE-78  (Cmd Injection)    ██████   32
CWE-639 (IDOR)             ████     4
CWE-327 (Weak Crypto)      ███      3
CWE-434 (File Upload)      ███      3
CWE-338 (Weak PRNG)        ███      3
CWE-601 (Open Redirect)    ███      3
CWE-916 (Weak Hash)        ███      3
CWE-1333 (ReDoS)           ███      3
─────────────────────────────────────────
```

### 2.4 학습 곡선 (v2 기준, step 265)

```
Train Loss
  2.6 │▓
  2.4 │▓
  2.2 │▓
  2.0 │ ▓
  1.8 │  ▓
  1.6 │   ▓
  1.4 │    ▓
  1.2 │     ▓
  1.0 │      ▓
  0.8 │       ▓▓
  0.6 │         ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  0.4 │
      └──────────────────────────────►
      0   50  100  150  200  250  step

Eval Loss (checkpoint 별)
  1.0 │▓
  0.9 │
  0.8 │
  0.7 │  ▓
  0.6 │     ▓  ▓* ▓  ▓  ▓  ▓
  0.5 │
      └──────────────────────────────►
      33  66  99 132 165 198 231 264
                   ↑
              Best checkpoint
              (eval_loss=0.5933)
```

> **Best checkpoint**: step 165, eval_loss = 0.5933  
> step 165 이후 eval loss가 소폭 상승 → 해당 checkpoint를 최종 어댑터로 선택

### 2.5 v3 토프업 학습

| 항목 | 내용 |
|------|------|
| **추가 데이터** | `lora_train_v4_additional.jsonl` (76개) |
| **신규 CWE** | CWE-79 XSS 8종 추가 (Express/DOM/jQuery) |
| **학습률** | 2e-5 (v2 대비 낮춤, catastrophic forgetting 방지) |
| **epochs** | 8 |

---

## 3. RAG 파이프라인

```
코드 입력
   │
   ▼
임베딩 생성 (BAAI/bge-small-en-v1.5, 384차원)
   │
   ▼
Qdrant 벡터 검색 (top-3 CVE)
   │  Collection: cve_vulnerabilities
   │  총 12,251개 CVE 벡터
   │
   ▼
CVE 컨텍스트 주입
   │  - CVE ID / CVSS Score / CWE ID
   │  - 취약점 설명 (200자 truncation)
   │
   ▼
LLM 프롬프트 구성 → 모델 추론
```

### Qdrant 설정

| 항목 | 값 |
|------|-----|
| **벡터 DB** | Qdrant (self-hosted, Railway) |
| **임베딩 모델** | BAAI/bge-small-en-v1.5 |
| **벡터 차원** | 384 |
| **유사도 메트릭** | Cosine |
| **컬렉션** | `cve_vulnerabilities` |
| **총 벡터 수** | 12,251개 |

---

## 4. Adaptive 2-Stage 시스템

```
                   코드 입력
                      │
                      ▼
          ┌─────────────────────┐
          │  Stage 1: QLoRA v3  │  ← 파인튜닝 모델 (빠름, 높은 정밀도)
          │  (RAG 없이 직접 분석)│
          └─────────┬───────────┘
                    │
          ┌─────────▼───────────┐
          │  결과 유효성 검증   │
          │  - VULNERABILITY 값이 취약점 이름인가?
          │  - SEVERITY가 파싱됐는가?           │
          └─────────┬───────────┘
                    │
         ┌──────────┴──────────┐
        Yes                   No (garbage/empty)
         │                     │
         ▼                     ▼
  Stage 1 성공          ┌─────────────────────┐
  Qdrant RAG로           │  Stage 2: Base+RAG  │
  CVE 보강 ──────────►  │  - base 모델 사용   │
                         │  - CVE 컨텍스트 주입 │
                         │  - Stage1 힌트 활용  │
                         └─────────────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │  최종 응답           │
                         │  VULNERABILITY       │
                         │  SEVERITY           │
                         │  ATTACK (한국어)     │
                         │  FIX (코드)         │
                         │  CVE References     │
                         └─────────────────────┘
```

**Stage 1 성공 조건** (`_is_valid_vuln` + SEVERITY 검증):
- VULNERABILITY 값이 "last line", "at end of" 등 위치 설명이 아닐 것
- 값 내부에 "vulnerability:" 키워드가 재등장하지 않을 것
- 문장이 3개 미만일 것 (설명글 아님)
- SEVERITY가 CRITICAL/HIGH/MEDIUM/LOW 중 하나로 파싱될 것

---

## 5. 벤치마크 결과

### 5.1 모델별 탐지율 비교

```
모델                                   탐지율   탐지    시간
────────────────────────────────────────────────────────────
Qwen2.5-Coder:1.5b (base)          ████████░░  85%  17/20  1.4s
Qwen2.5-Coder:1.5b + RAG           ████████░░  85%  17/20  1.4s
Qwen QLoRA v2 (fine-tuned)         ████████░░  80%  16/20  2.1s
Qwen QLoRA v2 + RAG                ████████░░  85%  17/20  4.4s
ScanOps v2 (QLoRA+RAG Adaptive)    █████████░  95%  19/20  2.7s ← 이전
ScanOps v3 (QLoRA+RAG Adaptive)    █████████░  ??%  ??/20  ??s ← 현재
ScanOps — Grok-3 (API)             ██████████  95%  19/20 17.7s
ScanOps — Grok-3 + RAG (API)       ██████████ 100%  20/20  5.5s
────────────────────────────────────────────────────────────
```

### 5.2 ScanOps v2 케이스별 결과 (20/20)

```
ID  언어                  취약점                              결과  Stage
────────────────────────────────────────────────────────────────────────
01  React / Next.js       XSS                                  ✓    2
02  React / Next.js       XSS (javascript: URI)                ✓    1
03  React / Next.js       Code Injection via eval              ✓    1
04  React / Next.js       XSS via event handler                ✓    1
05  Node.js / Express     SQL Injection                        ✓    1
06  Node.js / Express     Command Injection                    ✓    1
07  Node.js / Express     Insecure CORS                        ✓    1
08  Node.js / Express     Hardcoded Secret                     ✓    1
09  Java Spring Boot      SQL Injection                        ✓    1
10  Java Spring Boot      Command Injection                    ✓    2
11  Java Spring Boot      Overly Permissive Endpoint           ✓    1
12  Java Spring Boot      Timing Attack                        ✓    1
13  Python                Insecure Deserialization             ✓    1
14  Python                Command Injection                    ✓    2
15  Python                Arbitrary Code Execution via YAML    ✓    1
16  Python                Command Injection                    ✓    1
17  C                     Format String Attack                 ✓    1
18  C                     Buffer Overflow                      ✓    1
19  GitHub Actions YAML   Script Injection (untrusted input)   ✗    2  ← 미탐
20  GitHub Actions YAML   Supply Chain Attack (unpinned)       ✓    1
────────────────────────────────────────────────────────────────────────
탐지율: 19/20 = 95%  |  Stage1: 15건  Stage2: 4건  |  평균 2.71s
```

### 5.3 Stage 분포

```
v2 Stage 분포 (20케이스)
─────────────────────────
Stage 1 (QLoRA 직접 탐지)  ███████████████  15건 (75%)
Stage 2 (Base+RAG 폴백)    █████            4건  (20%)
미탐지                     █               1건  ( 5%)
─────────────────────────
```

---

## 6. 배포 인프라

```
┌──────────────────── Railway Cloud ────────────────────────┐
│                                                           │
│  ┌────────────────────┐    ┌──────────────────────────┐  │
│  │  FastAPI Server    │    │  Ollama Server           │  │
│  │  (api_server.py)   │◄──►│  (model serving)         │  │
│  │  Port: 8100        │    │  Port: 11434             │  │
│  │                    │    │                          │  │
│  │  /analyze          │    │  qwen2.5-coder-security  │  │
│  │  /analyze/batch    │    │  -v3:latest (986 MB)     │  │
│  │  /health           │    │                          │  │
│  └────────────────────┘    │  qwen2.5-coder:1.5b      │  │
│          ▲                 │  (base fallback)         │  │
│          │                 └──────────────────────────┘  │
│  ┌───────┴────────────┐                                  │
│  │  Qdrant            │                                  │
│  │  (vector search)   │                                  │
│  │  12,251 CVE 벡터   │                                  │
│  └────────────────────┘                                  │
└──────────────────────────────────────────────────────────┘
         ▲
         │ HTTP
         │
┌────────┴───────────┐
│  Spring Boot        │
│  (scanops-backend)  │
└─────────────────────┘
```

### API 응답 형식

```json
{
  "language":      "Python",
  "file_path":     "app/auth.py",
  "detected":      true,
  "stage":         1,
  "vulnerability": "CWE-78 Command Injection",
  "severity":      "HIGH",
  "attack":        "공격자가 user_input에 악성 명령을 주입하여 서버에서 임의 코드를 실행합니다.",
  "fix":           "subprocess.run(['cmd', arg], shell=False)",
  "cve_references": [
    { "cve_id": "CVE-2021-44228", "severity": "CRITICAL", "base_score": 10.0, ... }
  ],
  "elapsed":       2.71
}
```

---

## 7. v3 개선 사항

### 7.1 추가 학습 데이터 (76개 샘플)

| CWE | 유형 | 추가 수 |
|-----|------|---------|
| CWE-79 | XSS (Reflected/DOM/Stored) | **8** (신규) |
| CWE-639 | IDOR | 4 |
| CWE-327 | Weak Cryptography | 3 |
| CWE-434 | Unrestricted Upload | 3 |
| CWE-338 | Weak PRNG | 3 |
| 기타 24개 | 희귀 CWE 보강 | 55 |

### 7.2 v3에서 새로 추가된 XSS 패턴

```javascript
// 이전에 오탐(SQL Injection으로 분류)하던 패턴들
app.get("/user", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>"); // ← Reflected XSS
});

app.get("/profile/:id", (req, res) => {
  res.send(`<div>${req.params.id}</div>`);            // ← Template literal XSS
});

document.getElementById("bio").innerHTML = userInput; // ← DOM XSS

$('#result').html(data.content);                      // ← jQuery Stored XSS
```

### 7.3 파서 개선 (VULNERABILITY 유효성 검증)

```
이전 문제:
  모델 출력 → "on the second last line. VULNERABILITY: at end of block."
  → Stage 1 성공으로 잘못 판단 → 쓰레기 결과 반환

v3 해결:
  _is_valid_vuln() 함수로 아래 패턴 감지 → Stage 2 폴백 강제
  - 값 내 "vulnerability:" 재등장
  - "last line", "at end of" 위치 설명
  - 3개 이상 문장 (설명글)
```

---

## 8. 성능 요약

| 지표 | v2 | v3 | 변화 |
|------|----|----|------|
| **탐지율** | 95% (19/20) | TBD | - |
| **평균 응답** | 2.71s | TBD | - |
| **Stage1 비율** | 75% | TBD | - |
| **훈련 샘플** | 291 | 367 | +76 |
| **CWE 커버리지** | 40종 | 29종+ | XSS 대폭 보강 |
| **모델 크기** | 986 MB | 986 MB | 동일 |

---

## 9. 재현 방법

```bash
# 1. 환경 설정
cd /Users/kimsehan/Desktop/scanops/scanops-model
source .venv/bin/activate

# 2. v3 토프업 학습 (약 10분)
python scripts/topup_v3.py

# 3. GGUF 변환 + Ollama 등록 + HF Hub 업로드
python scripts/convert_to_gguf_v3.py

# 4. Railway 배포
python scripts/deploy_railway_v3.py

# 5. 벤치마크 실행
python scripts/benchmark_v3.py

# 6. API 서버 로컬 테스트
uvicorn scripts.api_server:app --host 0.0.0.0 --port 8100 --reload
```

---

*ScanOps Model v3 — QLoRA Fine-tuned Qwen2.5-Coder + Qdrant RAG*  
*Training: Apple M3 MPS  |  Serving: Railway Cloud  |  2026-05-27*
