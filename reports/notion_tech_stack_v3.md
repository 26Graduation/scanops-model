# 🔍 ScanOps — AI 보안 취약점 탐지 시스템 완전 해부

> 이 문서는 ScanOps의 모든 것을 처음 보는 사람도 이해할 수 있도록 정리했어.  
> "이 프로젝트에서 AI가 어떻게 코드의 보안 버그를 찾는가?"를 끝까지 파헤친다.

---

## 📌 한 줄 요약

> **"GitHub 코드를 받아서, 1.5B짜리 작은 AI 모델이 보안 취약점을 자동으로 찾아주는 시스템"**

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
  FastAPI 분석 서버 ◄── Railway 클라우드에서 실행 중
  (Python, api_server.py)
  → 파일마다 AI 모델한테 질문
  → 결과 정리해서 응답
         │
         │ 내부 호출
         ▼
  Ollama (LLM 실행 엔진)
  → qwen2.5-coder-security-v3 모델 실행
  → 취약점 분석 결과 반환
         │
         ▼
  결과: {"vulnerability": "SQL Injection", "severity": "HIGH", "fix": "..."}
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

> 💡 비교: ChatGPT는 API 호출할 때마다 돈이 나감. 우리 모델은 한 번 다운로드하면 무제한 무료.

### 파인튜닝: QLoRA (Q + LoRA)

**LoRA가 뭐냐고?**

```
일반 학습:    모델 전체(15억 파라미터) 업데이트 → GPU 80GB 필요, 수십 시간
LoRA:        작은 어댑터만(870만 파라미터, 0.56%) 업데이트 → 8GB 맥북으로 가능!

원본 모델 가중치 (동결, 건드리지 않음)
         +
작은 LoRA 어댑터 (여기만 학습)
         =
보안 전문 모델 완성
```

**Q (Quantization)가 뭐냐고?**

```
float32 (32비트) → float16 또는 4비트로 압축
메모리 사용 반절↓, 속도 유지
이걸 합친 게 QLoRA
```

**우리 LoRA 설정:**

```
r (rank) = 32      ← 어댑터 크기 (클수록 표현력↑, 메모리↑)
alpha = 64         ← 학습 강도 조절 (alpha/r = 2.0배 스케일링)
dropout = 0.05     ← 과적합 방지
타겟 레이어: q_proj, k_proj, v_proj, o_proj (어텐션 레이어만)
```

> 💡 쉽게 말하면: 이미 만들어진 AI에 "보안 전문 렌즈"를 끼워주는 것

### 학습 데이터

```
v4 데이터셋 구성 (367개 샘플)
════════════════════════════════
형식: JSONL (한 줄 = 한 샘플)

예시 한 줄:
{
  "prompt": "Analyze this Python code...\nimport subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)",
  "completion": "VULNERABILITY: CWE-78 Command Injection\nSEVERITY: HIGH\nATTACK: shell=True로 사용자 입력을 직접 실행하여...\nFIX: subprocess.run(['cmd', arg], shell=False)"
}

언어별 분포:
Python     ████████████████░░░░ 148개 (40%)
JavaScript ████████░░░░░░░░░░░░  75개 (20%)
Java       ██████░░░░░░░░░░░░░░  55개 (15%)
C          ████████████░░░░░░░░  81개 (22%)
기타        █░░░░░░░░░░░░░░░░░░░   8개 ( 3%)

커버하는 CWE (취약점 유형): 29종
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CWE-79   SQL Injection을 일으키는 XSS
CWE-89   SQL Injection
CWE-78   Command Injection
CWE-639  IDOR (권한 없는 객체 직접 접근)
CWE-327  약한 암호화 알고리즘 사용
... 외 24종
```

### 학습 과정

```
학습 진행 곡선 (8 에포크, 265 스텝)

손실(Loss) ← 낮을수록 좋음
  2.5 ┤╮                           처음엔 많이 틀림
  2.0 ┤ ╮
  1.5 ┤  ╮
  1.0 ┤   ╮
  0.8 ┤    ╰╮
  0.6 ┤      ╰━━━━━━━━━━━━━━━━━━━   안정적으로 수렴
  0.4 ┤
      └────────────────────────► 스텝
      0   50  100  150  200  265

검증 손실 (eval loss):
  step  33: 0.976
  step  66: 0.689
  step  99: 0.619
  step 132: 0.594
  step 165: 0.593  ★ 최저점 → 이 체크포인트 사용
  step 198: 0.605  ↑ 다시 올라감 (과적합 시작)
  step 265: 0.630

학습 시간: 약 24분 (Apple M3 MPS)
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
  4. 답변: "CVE-2019-1234에 해당하는 SQL Injection입니다. 심각도 CRITICAL. 대처법:..."
```

### 벡터 검색이란?

```
텍스트를 숫자 벡터로 변환하는 과정:

"SQL Injection in Python Django"
         │
         ▼ 임베딩 모델 (BAAI/bge-small-en-v1.5)
         │
[0.23, -0.11, 0.87, 0.03, ..., 0.45]  ← 384차원 벡터

Qdrant 벡터 DB에서 코사인 유사도로 가장 가까운 CVE 3개 검색
→ 관련성 높은 실제 취약점 사례를 AI한테 참고 자료로 제공
```

### 사용한 임베딩 모델

| 항목 | 내용 |
|------|------|
| **모델** | BAAI/bge-small-en-v1.5 |
| **벡터 크기** | 384차원 |
| **크기** | 133 MB |
| **특징** | 영어 텍스트 의미 이해에 최적화, 빠름 |

### Qdrant 벡터 DB

```
Qdrant = 벡터 전용 데이터베이스

일반 DB (MySQL):   "WHERE cve_id = 'CVE-2021-44228'"  → 정확히 일치하는 것만
Qdrant:            "SQL Injection Python 관련 CVE 찾아줘" → 의미적으로 비슷한 것들 반환

컬렉션: cve_vulnerabilities
총 벡터: 12,251개 (NVD에서 수집한 CVE 데이터)
유사도: 코사인 유사도 (방향이 비슷할수록 높은 점수)
검색: top-3 (가장 관련 있는 CVE 3개 반환)
```

---

## ⚡ 핵심 3: Adaptive 2-Stage 시스템

이게 우리 시스템의 핵심 아이디어야.

```
문제:
  파인튜닝 모델  → 특정 패턴엔 정확하지만 일부는 놓침
  Base + RAG     → 느리지만 RAG 덕에 폭넓게 탐지

해결책: 둘 다 써!
```

### Stage 1: 파인튜닝 모델 (빠른 전문가)

```
입력 코드
   │
   ▼
qwen2.5-coder-security-v3 (파인튜닝된 모델)
"너 이 코드에서 취약점 찾아봐"
   │
   ▼
응답: "VULNERABILITY: CWE-78 Command Injection
      SEVERITY: HIGH
      ATTACK: ..."
   │
   ▼
검증: 이 응답이 진짜 취약점 이름인가?
      아니면 "on the second last line..." 같은 쓰레기인가?

→ 유효하면: Stage 1 성공! Qdrant로 CVE만 추가해서 최종 응답
→ 쓰레기면: Stage 2로 넘김
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
"이 코드 봐, 관련 CVE는 이것들이야, 취약점 찾아봐"
   │
   ▼
최종 응답 생성
```

### 왜 두 단계를 쓰나?

```
성능 비교:
────────────────────────────────────────────────
방법                탐지율   속도    비용
────────────────────────────────────────────────
파인튜닝 모델만      80%     빠름    무료
Base + RAG만        85%     보통    무료
Adaptive (둘 다)    95%     보통    무료
Grok API            95%     느림    유료 (호출당 과금)
────────────────────────────────────────────────
→ Adaptive가 유료 API와 같은 성능을, 무료로 달성!
```

---

## 📊 벤치마크 결과

### 20개 테스트 케이스 탐지율

```
테스트 구성:
  언어: React, Node.js, Java Spring Boot, Python, C, GitHub Actions
  취약점: XSS, SQL Injection, Command Injection, CORS, Deserialization,
          Format String, Buffer Overflow, Supply Chain Attack 등

결과:
  ✓ 01. React/Next.js       XSS
  ✓ 02. React/Next.js       XSS (javascript: URI)
  ✓ 03. React/Next.js       Code Injection via eval
  ✓ 04. React/Next.js       XSS via event handler
  ✓ 05. Node.js/Express     SQL Injection
  ✓ 06. Node.js/Express     Command Injection
  ✓ 07. Node.js/Express     Insecure CORS
  ✓ 08. Node.js/Express     Hardcoded Secret
  ✓ 09. Java Spring Boot    SQL Injection
  ✓ 10. Java Spring Boot    Command Injection
  ✓ 11. Java Spring Boot    Overly Permissive Endpoint
  ✓ 12. Java Spring Boot    Timing Attack
  ✓ 13. Python              Insecure Deserialization
  ✓ 14. Python              Command Injection
  ✓ 15. Python              Arbitrary Code Execution (YAML)
  ✓ 16. Python              Command Injection
  ✓ 17. C                   Format String Attack
  ✓ 18. C                   Buffer Overflow
  ✗ 19. GitHub Actions YAML Script Injection  ← 유일한 미탐 (v2)
  ✓ 20. GitHub Actions YAML Supply Chain Attack

v2: 19/20 = 95.0%
v3: [벤치마크 실행 후 업데이트 예정]
```

### API 응답 예시 (실제 테스트)

```json
// curl -X POST https://scanops-model-production.up.railway.app/analyze
// Python Command Injection 코드 입력 → 실제 응답

{
  "language": "Python",
  "detected": true,
  "stage": 2,
  "vulnerability": "Command Injection",
  "severity": "HIGH",
  "attack": "공격자는 user_input 매개변수에 악성 명령을 주입할 수 있으며,
             이는 subprocess.call에 의해 실행됩니다.",
  "fix": "def run_cmd(user_input):\n    if not isinstance(user_input, str):\n        raise ValueError('Invalid input')\n    subprocess.run(user_input, shell=False)",
  "cve_references": [],
  "elapsed": 20.16
}
```

---

## 🚀 배포 구조

```
코드 저장소
────────────────────────────────────────────
github.com/26Graduation/scanops-model
  └─ git push main
       └─ Railway 자동 감지 → 재빌드/재배포

Railway 서비스 구성
────────────────────────────────────────────
서비스 1: FastAPI (api_server.py)
  URL: https://scanops-model-production.up.railway.app
  엔드포인트:
    GET  /health          → 서버 상태 확인
    POST /analyze         → 파일 단건 분석
    POST /analyze/batch   → 파일 묶음 분석

서비스 2: Ollama
  모델 저장: HuggingFace Hub에서 pull
  → hf.co/SehanKim/qwen2.5-coder-security-v3-gguf:Q4_K_M
  → 별칭: qwen2.5-coder-security-v3:latest

서비스 3: Qdrant
  URL: 내부 네트워크
  컬렉션: cve_vulnerabilities (12,251 벡터)
```

### 모델 배포 흐름

```
로컬 학습
   1. python scripts/topup_v3.py
      → models/qwen-security-qlora-v3/ 어댑터 저장

   2. python scripts/convert_to_gguf_v3.py
      → LoRA 병합 → GGUF F16 변환 → Q4_K_M 양자화
      → 로컬 Ollama 등록
      → HuggingFace Hub 업로드
         (SehanKim/qwen2.5-coder-security-v3-gguf)

   3. python scripts/deploy_railway_v3.py
      → Railway Ollama에서 HF Hub 모델 pull
      → api_server.py MODEL_FT 업데이트
      → git push → Railway 자동 재배포
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

## 💡 자주 나오는 질문

**Q. 왜 ChatGPT API 안 쓰고 직접 모델을 학습시켜?**
> 비용 + 데이터 보안. 회사 코드를 OpenAI 서버에 보내면 민감한 코드가 유출될 수 있어.  
> 자체 모델은 한 번 만들면 무제한 무료, 코드도 외부로 안 나감.

**Q. 1.5B가 작다고 했는데 괜찮아?**
> 일반 대화는 크기가 중요하지만, 보안 취약점 탐지는 **특정 패턴을 학습**하는 거라  
> 학습 데이터가 좋으면 소형 모델도 충분함. 실제로 95% 탐지율 달성했음.

**Q. RAG는 왜 모든 케이스에 안 써?**
> Qdrant 검색 자체에 시간(~0.5s)이 걸리고, 파인튜닝 모델이 이미 잘 탐지하는 경우엔  
> RAG가 오히려 노이즈가 될 수 있어. Stage1 성공 시엔 CVE 보강 목적으로만 사용.

**Q. GGUF가 뭐야?**
> LLM을 효율적으로 저장하는 파일 포맷. Q4_K_M은 4비트 양자화 방식인데,  
> 품질 손실 최소화하면서 파일 크기를 원래의 1/4로 줄여줌.  
> (32비트 원본: ~4GB → Q4_K_M: ~986MB)

---

## 📁 프로젝트 파일 구조

```
scanops-model/
├── scripts/
│   ├── api_server.py          # FastAPI 서버 (핵심)
│   ├── benchmark_qwen_rag.py  # 벤치마크 실행
│   ├── benchmark_v3.py        # v3 전용 벤치마크
│   ├── topup_v3.py            # v3 토프업 학습
│   ├── convert_to_gguf_v3.py  # GGUF 변환 파이프라인
│   ├── deploy_railway_v3.py   # Railway 배포 자동화
│   ├── benchmark_core.py      # 테스트 케이스 정의, parse_response
│   └── grok_client.py         # 번역용 Grok API
├── models/
│   ├── qwen-security-qlora/   # v2 어댑터 (원본)
│   ├── qwen-security-qlora-v3/ # v3 어댑터 (신규)
│   └── qwen-security-v3.Q4_K_M.gguf  # 배포용 GGUF
├── data/
│   ├── lora_train_v4.jsonl         # 학습 데이터 (291개)
│   └── lora_train_v4_additional.jsonl  # 추가 데이터 (76개)
└── reports/
    ├── ScanOps_Final_Report_v3.md  # 기술 보고서
    └── notion_tech_stack_v3.md     # 이 파일
```

---

*ScanOps v3 | 2026-05-27 | Qwen2.5-Coder QLoRA + Qdrant RAG Adaptive System*
