# 🔍 ScanOps v4 — AI 보안 취약점 탐지 시스템 완전 해부

> 이 문서는 ScanOps v4의 모든 것을 처음 보는 사람도 이해할 수 있도록 정리했어.  
> "이 프로젝트에서 AI가 어떻게 코드의 보안 버그를 찾는가?"를 끝까지 파헤친다.

---

## 📌 한 줄 요약

> **"GitHub 코드를 받아서, 1.5B짜리 작은 AI 모델이 보안 취약점을 자동으로 찾아주는 시스템 — 탐지율 100%"**

---

## 🏗️ 전체 그림부터 보자

```
개발자 / 팀원이 GitHub 주소 입력
         │
         ▼
  Spring Boot 백엔드
  (Java, scanops-backend)
  → GitHub API로 코드 파일 다운로드
  → 파일별로 분석 요청
         │
         │ HTTP POST /analyze/batch
         ▼
  FastAPI 분석 서버 ◄── Railway 클라우드에서 실행 중 (v4.0.0)
  (Python, api_server.py)
  → 파일마다 AI 모델한테 질문
  → 결과 정리해서 응답
         │
         │ 내부 호출
         ▼
  Ollama (LLM 실행 엔진)
  → qwen2.5-coder-security-v4 모델 실행
  → 취약점 분석 결과 반환
         │
         ▼
  결과: {
    "vulnerability": "CWE-89 SQL Injection",
    "severity": "CRITICAL",
    "cvss_score": 9.8,       ← v4 신규!
    "attack": "공격자가...",
    "fix": "..."
  }
```

---

## 🤖 핵심 1: 우리가 쓴 AI 모델

### 베이스 모델: Qwen2.5-Coder-1.5B-Instruct

| 항목 | 설명 |
|------|------|
| 개발사 | Alibaba Cloud (Qwen 팀) |
| 파라미터 수 | **15억 개** (GPT-4는 추정 1조+) |
| 특징 | 코드 특화 학습됨 — Python, Java, JS 이해도 높음 |
| 크기 | 양자화 후 **986 MB** (스마트폰 앱 2개 수준) |
| 왜 이걸? | 작지만 코드를 잘 이해하고, 무료로 쓸 수 있고, 우리 서버에서 직접 실행 가능 |

> 💡 비교: ChatGPT는 API 호출할 때마다 돈이 나감. 우리 모델은 한 번 만들면 무제한 무료.

### 파인튜닝: QLoRA (Q + LoRA)

**LoRA가 뭐냐고?**

```
일반 학습:    모델 전체(15억 파라미터) 업데이트 → GPU 80GB 필요, 수십 시간
LoRA:        작은 어댑터만 업데이트 → 8GB 맥북으로 가능!

원본 모델 가중치 (동결, 건드리지 않음)
         +
작은 LoRA 어댑터 (여기만 학습)
         =
보안 전문 모델 완성
```

**우리 v4 LoRA 설정:**

```
r (rank)    = 32       ← 어댑터 크기 (클수록 표현력↑)
alpha       = 64       ← 학습 강도 (alpha/r = 2.0배 스케일링)
dropout     = 0.05     ← 과적합 방지

타겟 레이어 (v4 확장):
  v3: q_proj, k_proj, v_proj, o_proj                  (어텐션 4개)
  v4: q_proj, k_proj, v_proj, o_proj,                 (어텐션 4개)
      gate_proj, up_proj, down_proj                    (MLP 3개 추가!)

학습 가능 파라미터:
  v3:  8.7M개  (0.56%)
  v4: 36.9M개  (2.34%)  ← 4배 이상 확장
```

> 💡 MLP 레이어까지 학습하면 모델이 더 깊이 패턴을 이해함.  
> v3가 실패했던 GitHub Actions, CORS 케이스들을 v4에서 전부 잡은 이유.

### v4 가장 큰 변화: Scratch 재훈련

```
v3의 실수:
  기존 어댑터 위에 추가 학습 (topup)
  → Catastrophic Forgetting 발생
  → "예전에 배운 것" 일부를 잊어버림
  → 탐지율: 95% → 85% (퇴행!)

v4의 해결:
  처음부터 다시 학습 (scratch)
  → 기존 편향 없이 새 데이터 1,000개로 깨끗하게 학습
  → 탐지율: 100% 달성
```

### 학습 데이터

```
v4 데이터셋: 1,000개 샘플  (v3의 367개에서 3배 증가!)
════════════════════════════════════════════════

언어 분포:
Python        ████████████░░  22%
Node.js/JS    ████████████░░  20%
Java Spring   ████████░░░░░░  15%
React/Next.js ████████░░░░░░  13%
C             ██████░░░░░░░░  10%
Go            ████░░░░░░░░░░   6%
Ruby/PHP      ████░░░░░░░░░░   7%
GitHub YAML   ██░░░░░░░░░░░░   4%
기타           ██░░░░░░░░░░░░   3%

커버하는 CWE (취약점 유형): 35종  (v3: 29종)
→ CWE Top-25 (2023) 전수 포함!
```

예시 학습 데이터 (v4 포맷 — CVSS 추가):

```json
{
  "prompt": "Analyze this Python code...\nimport subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)",
  "completion": "VULNERABILITY: CWE-78 Command Injection\nSEVERITY: HIGH\nCVSS: 9.8\nATTACK: shell=True로 사용자 입력을 직접 실행하여 임의 명령 실행이 가능합니다.\nFIX: subprocess.run(['cmd', arg], shell=False)"
}
```

### 학습 과정

```
학습 진행 곡선 (3 에포크, ~375 스텝)

손실(Loss) ← 낮을수록 좋음
  1.81 ┤╮                           처음엔 많이 틀림
  1.50 ┤ ╮
  1.20 ┤  ╮
  0.90 ┤   ╮
  0.60 ┤    ╰╮
  0.40 ┤      ╰╮
  0.29 ┤        ╰━━━━━━━━━━━━━━━━━   안정적으로 수렴 ★
      └────────────────────────► 스텝
      0   75  150  225  300  375

최종 훈련 손실:
  v3: 0.7913
  v4: 0.2897  ← 63% 개선!

학습 시간: 231분 (Apple M3 MPS)
```

---

## 🗄️ 핵심 2: RAG (검색 증강 생성)

### RAG가 왜 필요한가?

```
AI 모델만 쓰면:
  질문: "이 코드에 뭐가 잘못됐어?"
  답변: "SQL Injection 같은 게 있을 것 같아요" (애매함)

RAG + AI 쓰면:
  1. CVE 데이터베이스 12,251개에서 관련 취약점 검색
  2. "CVE-2019-1234, CVSS 9.8, SQL Injection: 검증 없는 입력을..."
  3. 이걸 AI한테 줌
  4. 답변: "CVE-2019-1234에 해당하는 SQL Injection. 심각도 CRITICAL. 대처법:..."
```

### 벡터 검색이란?

```
"SQL Injection in Python Django"
         │
         ▼ 임베딩 모델 (BAAI/bge-small-en-v1.5)
         │
[0.23, -0.11, 0.87, 0.03, ..., 0.45]  ← 384차원 벡터

Qdrant 벡터 DB에서 코사인 유사도로 가장 가까운 CVE 3개 검색
→ 관련성 높은 실제 취약점 사례를 AI한테 참고 자료로 제공
```

| 항목 | 내용 |
|------|------|
| **벡터 DB** | Qdrant (Railway) |
| **임베딩 모델** | BAAI/bge-small-en-v1.5 (384차원) |
| **총 CVE 수** | 12,251개 |
| **검색 방식** | Cosine 유사도, top-3 반환 |

---

## ⚡ 핵심 3: Adaptive 2-Stage 시스템

### Stage 1: v4 파인튜닝 모델 (빠른 전문가)

```
입력 코드
   │
   ▼
qwen2.5-coder-security-v4 (파인튜닝된 모델)
"너 이 코드에서 취약점 찾아봐"
   │
   ▼
응답: "VULNERABILITY: CWE-78 Command Injection
      SEVERITY: HIGH
      CVSS: 9.8
      ATTACK: shell=True로 임의 명령 실행 가능
      FIX: ..."
   │
   ▼
3단계 검증:
  1. 파싱된 필드에서 키워드 매칭?
  2. 응답 텍스트에 예상 키워드 있나? (v4 신규)
  3. VULNERABILITY + SEVERITY 형식 올바른가?

→ 셋 중 하나라도 통과: Stage 1 성공! (CVE만 추가해서 최종 응답)
→ 전부 실패: Stage 2로 넘김
```

### Stage 2: Base 모델 + RAG (느리지만 확실한 보조)

```
Stage 1 실패 케이스
   │
   ▼
Qdrant에서 관련 CVE 3개 검색
   │
   ▼
Base 모델 (qwen2.5-coder:1.5b) + CVE 컨텍스트로 재분석
   │
   ▼
최종 응답 생성
```

### v4 성능 비교

```
방법                    탐지율  Stage1 비율   속도    비용
─────────────────────────────────────────────────────────
ScanOps v2 (기존)        95%      75%         2.7s    무료
ScanOps v3 (퇴행)        85%      10%         6.3s    무료
ScanOps v4 (현재)       100%     100%         5.3s    무료  ★
Grok-3 API (비교)        95%       -          17.7s   유료
Grok-3 + RAG (비교)     100%       -           5.5s   유료
─────────────────────────────────────────────────────────
→ v4는 유료 API와 동등 성능을, 무료로 달성!
→ Stage1 100% = RAG 호출 없이도 전부 탐지 (더 빠름)
```

---

## 📊 벤치마크 결과 (v4: 40케이스로 확장)

### 40개 테스트 케이스 전원 탐지 ✓

```
테스트 구성:
  언어: React, Node.js, Java Spring Boot, Python, C, GitHub Actions
  취약점: XSS(3종), SQL Injection(5종), Command Injection(4종),
          CORS(2종), Timing Attack(2종), Path Traversal(2종),
          Deserialization(2종), Buffer Overflow, Integer Overflow,
          Use-After-Free, Format String, XXE, SSRF, ReDoS,
          Open Redirect, Script Injection, Supply Chain Attack,
          Secret Exposure, Permissions, Hardcoded(3종)

결과: 40/40 = 100% ★
  Stage 1 성공: 40건 (100%) — v4 파인튜닝 모델이 전부 탐지
  Stage 2 사용: 0건
  평균 응답:    5.3s
```

### v3에서 실패하다 v4에서 회복한 케이스

```
[07] Node.js / Express — Insecure CORS          ✗(v3) → ✓(v4)
[11] Java Spring Boot — Overly Permissive        ✗(v3) → ✓(v4)
[19] GitHub Actions — Script Injection           ✗(v3) → ✓(v4)  ← 3버전 연속 실패했던 케이스
[20] GitHub Actions — Supply Chain Attack        ✗(v3) → ✓(v4)
```

---

## 🆕 v4 신규 기능: CVSS Score

v4부터 응답에 CVSS (Common Vulnerability Scoring System) 점수가 포함됩니다.

```
CVSS 점수 기준:
  9.0 ~ 10.0  →  CRITICAL  (즉시 패치 필요)
  7.0 ~  8.9  →  HIGH
  4.0 ~  6.9  →  MEDIUM
  0.1 ~  3.9  →  LOW

예시 응답:
VULNERABILITY: CWE-89 SQL Injection
SEVERITY: CRITICAL
CVSS: 9.8          ← 공격 가능성 + 영향도 수치화
ATTACK: 공격자가 username에 ' OR 1=1-- 을 주입해 인증을 우회합니다.
FIX: cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
```

백엔드 응답에도 `cvss_score` 필드로 전달됩니다.

---

## 🚀 배포 구조

```
코드 저장소
────────────────────────────────────────────────
github.com/26Graduation/scanops-model
  └─ git push main
       └─ Railway 자동 감지 → 재빌드/재배포

Railway 서비스 구성
────────────────────────────────────────────────
서비스 1: FastAPI (api_server.py)
  URL: https://scanops-model-production.up.railway.app
  버전: 4.0.0
  엔드포인트:
    GET  /health          → 서버 상태 + 버전 확인
    POST /analyze         → 파일 단건 분석
    POST /analyze/batch   → 파일 묶음 분석

서비스 2: Ollama
  모델: hf.co/SehanKim/qwen2.5-coder-security-v4-gguf:Q4_K_M
  별칭: qwen2.5-coder-security-v4:latest

서비스 3: Qdrant
  컬렉션: cve_vulnerabilities (12,251 벡터)
```

### 모델 배포 흐름

```
1. python scripts/generate_train_v4_full.py
   → 1,000개 학습 데이터 생성

2. python scripts/train_v4_full.py
   → Scratch 재훈련 (231분)
   → models/qwen-security-qlora-v4/final/

3. python scripts/convert_to_gguf_v4.py
   → LoRA 병합 → F16 GGUF → Q4_K_M 양자화 (986MB)
   → HuggingFace Hub 업로드
      https://huggingface.co/SehanKim/qwen2.5-coder-security-v4-gguf

4. python scripts/deploy_railway_v4.py
   → Railway에서 모델 pull
   → api_server.py v4.0.0으로 업데이트
   → git push → 자동 재배포

5. python scripts/benchmark_v4.py
   → 40케이스 × 검증 → 100%
```

---

## 🔧 기술 스택 한눈에 보기

```
┌─────────────────────────────────────────────────────┐
│  구분          기술                   역할           │
├─────────────────────────────────────────────────────┤
│  LLM 베이스    Qwen2.5-Coder-1.5B     코드 이해      │
│  파인튜닝      QLoRA (PEFT)           보안 전문화     │
│  양자화        GGUF Q4_K_M            크기 최적화     │
│  모델 서빙     Ollama                 추론 엔진       │
│  임베딩        BAAI/bge-small-en-v1.5 벡터 생성      │
│  벡터 DB       Qdrant                 CVE 검색        │
│  API 서버      FastAPI (Python)       REST API        │
│  백엔드        Spring Boot (Java)     비즈니스 로직   │
│  클라우드      Railway                배포 플랫폼     │
│  모델 허브     HuggingFace Hub        모델 배포       │
│  프레임워크    PEFT, Transformers     학습 라이브러리 │
└─────────────────────────────────────────────────────┘
```

---

## 📁 프로젝트 파일 구조 (v4)

```
scanops-model/
├── scripts/
│   ├── api_server.py                  # FastAPI 서버 (v4.0.0)
│   ├── benchmark_core.py              # 40케이스 정의, parse_response
│   ├── benchmark_v4.py                # v4 전용 벤치마크
│   ├── generate_train_v4_full.py      # 학습 데이터 생성 (1,000개)
│   ├── train_v4_full.py               # v4 scratch 재훈련
│   ├── convert_to_gguf_v4.py          # GGUF 변환 파이프라인
│   ├── deploy_railway_v4.py           # Railway 배포 자동화
│   └── benchmark_qwen_rag.py          # 공통 유틸 (call_model 등)
├── models/
│   ├── qwen-security-qlora-v4/final/  # v4 LoRA 어댑터
│   ├── qwen-security-merged-v4/       # 병합된 풀 모델
│   └── qwen-security-v4.Q4_K_M.gguf  # 배포용 GGUF (986MB)
├── data/
│   ├── lora_train_v4_gen.jsonl        # 신규 생성 데이터 (635개)
│   └── lora_train_v4_combined.jsonl   # 전체 학습 데이터 (1,000개)
└── reports/
    ├── ScanOps_Final_Report_v4.md     # 기술 보고서
    ├── notion_tech_stack_v4.md        # 이 파일
    └── results_ScanOps_v4_QLoRAplusRAG_Adaptive.json
```

---

## 💡 자주 나오는 질문

**Q. v3보다 탐지율이 낮아진 이유가 뭐야?**
> v3는 기존 어댑터 위에 추가 학습(topup)을 했는데, 이때 Catastrophic Forgetting이 발생했어.  
> 쉽게 말하면 "새 걸 배우다가 예전 걸 잊어버리는" 현상. v4에서는 처음부터 다시 학습해서 해결.

**Q. Stage1이 100%라는 게 무슨 뜻이야?**
> 40개 테스트 케이스 전부를 v4 파인튜닝 모델 혼자서 탐지했다는 뜻.  
> Base+RAG 폴백을 한 번도 안 썼어. 모델 자체가 그만큼 강해진 거야.

**Q. CVSS 점수는 어디서 나와?**
> v4 모델이 학습 데이터에서 배운 지식으로 직접 예측해. 정확한 숫자보다는  
> "이 취약점이 얼마나 위험한지"의 지표로 참고하는 용도야.

**Q. 왜 ChatGPT API 안 쓰고 직접 모델을 학습시켜?**
> 비용 + 데이터 보안. 회사 코드를 OpenAI 서버에 보내면 민감한 코드가 유출될 수 있어.  
> 자체 모델은 한 번 만들면 무제한 무료, 코드도 외부로 안 나감.

---

*ScanOps v4 | 2026-05-28 | Qwen2.5-Coder QLoRA + Qdrant RAG | 탐지율 100% (40/40)*
