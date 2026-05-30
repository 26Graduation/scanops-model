# ScanOps 교수님 제출 보고서 — Claude 채팅용 프롬프트 (v3, 실측 데이터 기반)

> **사용법**: 아래 "═══ 복사 시작 ═══" 부터 "═══ 복사 끝 ═══" 까지를 통째로
> Claude 채팅(claude.ai)에 붙여넣으세요.
> 차트 PNG 5개(`reports/charts/`)를 함께 첨부하면 보고서에 자동 삽입됩니다.

---

## 생성된 차트 파일 위치

```
scanops-model/reports/charts/
  01_learning_curves.png          — Gemma-2 LoRA vs Qwen QLoRA 학습 곡선
  02_benchmark_comparison.png     — 8개 구성 전체 벤치마크 비교 (실측값)
  03_training_data_distribution.png — CWE 분포 + 심각도 분포 (v4 데이터)
  04_system_roadmap.png           — 시스템 개발 로드맵 타임라인
  05_hyperparameter_table.png     — 전 모델 하이퍼파라미터 비교 표
```

---

═══════════════════════════════════════════════════════════════
## ▶ Claude 채팅에 붙여넣을 프롬프트 (여기서부터 복사)
═══════════════════════════════════════════════════════════════

```
아래 데이터를 바탕으로 학술 프로젝트 보고서를 작성해주세요.
.docx 형식, 한국어, A4 기준 15~20페이지, 표·차트·코드블록 포함.
첨부 이미지(차트 PNG 5개)를 보고서 내 적절한 위치에 삽입해주세요.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 기본 정보 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

보고서 제목: ScanOps — 보안 취약점 자동 탐지 LLM 시스템
부제: QLoRA 파인튜닝 + RAG 기반 경량 LLM 보안 코드 분석 파이프라인
소속: 부산대학교 정보의생명대학 정보컴퓨터공학부
팀명: ScanOps
팀장: 김세한 (202155530)
팀원: 전혜은 (202355579), 이경윤 (202155523)
제출일: 2026년 5월

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 1. 초록 (Abstract) 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[한국어 요약]
본 연구는 1GB 이하의 경량 로컬 LLM에 QLoRA 파인튜닝과 RAG를 결합하여
CVE/CWE 기반 소프트웨어 보안 취약점을 자동 탐지하는 ScanOps 시스템을 구현한다.
Apple M3 MacBook Pro 환경에서 Qwen2.5-Coder-1.5B-Instruct 모델에 QLoRA를 적용하고,
NVD CVE 792건을 Qdrant 벡터 DB에 적재한 RAG 파이프라인을 구성하였다.
RAG 파이프라인에 Grok-3 API를 결합하여 20개 테스트 케이스에서 취약점 탐지율 100%를 달성하였으며,
파인튜닝 모델(qwen2.5-coder-security)은 GGUF Q4_K_M 양자화를 통해 986MB로 경량화하여
Railway 클라우드 배포 가능 수준을 달성하였다.
파인튜닝 모델 단독 탐지율은 5%(RAG 없음)에서 Qdrant RAG 결합 시 55%로 향상되었으며,
훈련 데이터 확장 및 재훈련을 통한 성능 개선이 진행 중이다.

[영문 요약 (Abstract)]
This study implements ScanOps, a software security vulnerability detection system combining QLoRA
fine-tuning with a RAG pipeline on a local LLM (≤1GB). Applying QLoRA to Qwen2.5-Coder-1.5B-Instruct
on Apple M3 hardware and indexing 792 NVD CVE entries into Qdrant vector DB, the system achieves
100% detection rate (20 test cases) when the RAG pipeline is combined with Grok-3 API.
The fine-tuned model achieves 5% detection standalone and 55% with Qdrant RAG, demonstrating
significant RAG-assisted improvement. The model is compressed to 986MB via GGUF Q4_K_M quantization,
enabling Railway cloud deployment within a 1GB RAM constraint. Ongoing retraining with 291-sample
clean-format data (v4) targets further improvement of the fine-tuned model's standalone detection.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 2. 프로젝트 개요 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

목적: 소규모 로컬 LLM(≤1GB)에 QLoRA 파인튜닝과 RAG를 결합해
      CVE/CWE 기반 보안 취약점을 자동 탐지하고 수정 방법을 제시하는 시스템 구현.

개발 환경: Apple M3 MacBook Pro (MPS, 18GB Unified Memory)
배포 목표: Railway 클라우드 (RAM ≤1GB 제약 → Q4_K_M 양자화 필수)

핵심 기술 스택:
  - LLM (메인 파인튜닝 대상): Qwen2.5-Coder-1.5B-Instruct
  - LLM (비교 실험):          Gemma-2 2B (google/gemma-2-2b-it), TinyLlama 1.1B
  - LLM (RAG 벤치마크 비교용): Grok-3 API (xAI 클라우드, 로컬 완성 전 비교 기준선)
  - 파인튜닝 방법:            QLoRA (PEFT, rank=16→32, MPS float16 full-load)
  - 벡터 DB:                  Qdrant (Docker, port 6333)
  - 임베더:                   BAAI/bge-small-en-v1.5 (로컬, 384차원, L2 정규화)
  - CVE 데이터:               NVD (National Vulnerability Database) 792건
  - CLI:                      typer + rich (scan / chat / benchmark / db-prepare)
  - 모델 배포:                Ollama (GGUF Q4_K_M, 986MB)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 3. 시스템 아키텍처 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[전체 RAG 파이프라인]

  사용자 코드 입력 (CLI: scanops scan --code "..." 또는 파일 경로)
       │
       ▼
  [BGE 임베더] BAAI/bge-small-en-v1.5 (로컬, 384차원, L2 정규화)로 코드 벡터화
       │
       ▼
  [Qdrant 벡터 DB] CVE 792건 적재 — cosine 유사도 top-5 검색
       │  → CVE ID, severity, CVSS, CWE, description 반환
       ▼
  [프롬프트 조립] CVE 컨텍스트 + 원본 코드 + 시스템 지시문 결합
       │
       ▼
  [LLM 추론]
    현재 로컬: qwen2.5-coder:1.5b (Ollama, 파인튜닝 없음)
    파인튜닝:  qwen2.5-coder-security (QLoRA 1차, 재훈련 진행 중)
    벤치마크 비교: Grok-3 API (성능 기준선)
       │
       ▼
  [파싱 엔진] VULNERABILITY / CVE / CWE / CVSS / LOCATION / ATTACK / FIX 추출
       │
       ▼
  CLI rich 포맷 또는 JSON 결과 출력

[CVE 데이터베이스 구성]
출처: NVD JSON 피드 (2024~2025 최신)
전처리: Rejected/Deferred 제거 → 10개 필드 추출
최종 적재: 792건
  - CRITICAL: 196건 (24.7%)
  - HIGH:     327건 (41.3%)
  - MEDIUM:   178건 (22.5%)
  - LOW:       91건 (11.5%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 4. 개발 단계별 실험 흐름 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

아래 단계를 개발 순서대로 서술하세요. [차트 4 - 로드맵 이미지 삽입]

Phase 1 — 베이스 LLM 기준점 수립
  모델: Qwen2.5-Coder-1.5B (Ollama 기본 제공, 파인튜닝 없음)
  결과: 탐지율 85%, CWE 정확도 5% (BASE 모델 기준), 평균 응답 1.16s

Phase 2 — TinyLlama LoRA 초기 실험
  모델: TinyLlama/TinyLlama-1.1B-Chat-v1.0
  목적: LoRA 학습 파이프라인 검증 (코드, 하이퍼파라미터 확인)
  데이터: ~50건, rank=8, alpha=16, 5 epochs
  결과: 파이프라인 검증 성공. 탐지 품질 미흡 → 더 큰 모델로 전환

Phase 3 — Gemma-2 2B LoRA (비교 실험)
  모델: google/gemma-2-2b-it
  데이터: 훈련 데이터 v2 (lora_train_v2.jsonl, 203건), rank=16, alpha=32, 5 epochs
  결과: 최종 train loss 0.692, 학습시간 47.6분
  한계: Q4 GGUF ~1.6GB → Railway 1GB 제약 초과. 배포 불가.

Phase 4 — Qwen QLoRA 1차 (메인 모델)
  모델: Qwen2.5-Coder-1.5B-Instruct
  데이터: 훈련 데이터 v2 (lora_train_v2.jsonl, 203건), rank=16, alpha=32, 5 epochs
  결과: 최종 train loss 0.656, eval loss 0.701, 학습시간 9.3분 (556초)
  변환: PEFT merge → GGUF F16(3.09GB) → Q4_K_M(986MB) → Ollama 등록
  현황: 훈련 데이터 형식 문제(VULN_TYPE: 트리거가 베이스 모델 pretraining 패턴과 충돌)로
        단독 탐지율 5%에 그침. 재훈련(2차, rank=32, 291건 clean format)을 진행 중.

Phase 5 — RAG 파이프라인 구축 및 벤치마크
  구성: Qdrant 벡터 DB (ChromaDB에서 마이그레이션) + BGE 임베더
  이유: 파인튜닝 모델의 단독 성능 한계를 CVE 컨텍스트로 보완
  결과 (실측, 2026-05-26):
    - Qwen BASE + Qdrant RAG: 80% (RAG 컨텍스트 형식이 일부 케이스 오분류 유발)
    - Qwen QLoRA 1차 + Qdrant RAG: 55% (단독 5% 대비 +50%p 향상)
    - Grok-3 + Qdrant RAG (비교 기준선): 100%
  해석: RAG는 파인튜닝 모델의 부족한 도메인 지식을 보완하는 데 효과적.
        Grok-3 100% 달성은 강력한 기반 모델의 CVE 활용 능력 덕분.

Phase 6 — Qwen QLoRA 2차 재훈련 (진행 중)
  데이터: 훈련 데이터 v4 (lora_train_v4.jsonl, 291건, 포맷 전면 재설계)
  변경: VULN_TYPE: 트리거 제거 → VULNERABILITY: 표준 지시형 포맷. rank=32, 8 epochs
  목표: 재훈련 후 QLoRA + RAG 탐지율 80% 이상 달성

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 5. 훈련 데이터 구성 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[데이터 버전 변천표 — 표로 작성]

버전             파일명                  샘플 수  주요 내용
lora_train v1    lora_train.jsonl         ~50건   TinyLlama 파이프라인 검증용
lora_train v2    lora_train_v2.jsonl      203건   Qwen/Gemma 1차 훈련 (15종+ CWE, VULN_TYPE 형식)
lora_train v3    lora_train_v3.jsonl      296건   v2 확장 시도 (형식 불일치 포함, 미사용)
lora_train v4    lora_train_v4.jsonl      291건   포맷 전면 재설계 (VULNERABILITY: 표준 형식, 현재 사용 중)

[v4 훈련 데이터 포맷 — 형식 개선 이유 포함]
  기존 v2 형식 문제:
    prompt:     "...Analyze code...\nVULN_TYPE:"  ← "VULN_TYPE:" 완성 트리거
    completion: "SQL_INJECTION\nSEVERITY: HIGH..."
    문제: "VULN_TYPE:"이 베이스 모델 pretraining에서 템플릿 완성 패턴으로 학습됨
          → 추론 시 "___________ (select from NONE, XPATHQUERY...)" 등 garbage 출력

  개선된 v4 형식:
    prompt:     "Analyze this {언어} code for security vulnerabilities:\n\n{코드}"
    completion: "VULNERABILITY: CWE-XX 이름\nSEVERITY: LEVEL\nATTACK: ...\nFIX:\n..."
    개선: 지시형 프롬프트로 변경, 트리거 충돌 제거, 표준 출력 형식 확립

[v4 CWE 분포 (291건 기준)] — [차트 3 이미지 삽입]
  CWE-79  (XSS):              46건 (15.8%)
  CWE-89  (SQL Injection):    33건 (11.3%)
  CWE-78  (Command Injection):32건 (11.0%)
  CWE-284 (Access Control):   28건 ( 9.6%)
  CWE-22  (Path Traversal):   25건 ( 8.6%)
  CWE-77  (Code Injection):   14건 ( 4.8%)
  CWE-416 (Use-After-Free):   12건 ( 4.1%)
  CWE-798 (Hardcoded Creds):  11건 ( 3.8%)
  CWE-502 (Deserialization):  10건 ( 3.4%)
  기타 10개 CWE:              80건 (27.5%)

[심각도 분포]
  CRITICAL: 104건 (35.7%) | HIGH: 163건 (56.0%) | MEDIUM: 21건 | LOW: 3건

[대상 프로그래밍 언어]
  Python, JavaScript/Node.js, TypeScript/React, Java, C/C++,
  Go, Ruby, PHP, Kotlin, Swift, Terraform, GitHub Actions, Shell (13종 이상)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 6. Gemma-2 LoRA vs Qwen QLoRA 비교 실험 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[하이퍼파라미터 비교표] — [차트 5 이미지 삽입]

항목                    TinyLlama LoRA   Gemma-2 LoRA       Qwen QLoRA 1차       Qwen QLoRA 2차
────────────────────────────────────────────────────────────────────────────────────────────
베이스 모델             TinyLlama 1.1B   Gemma-2 2B-IT      Qwen2.5-Coder 1.5B   Qwen2.5-Coder 1.5B
학습 방식               LoRA             LoRA               QLoRA (MPS float16)  QLoRA (MPS float16)
LoRA rank (r)           8                16                 16                   32
LoRA alpha              16               32                 32                   64
target_modules          q,v              q,k,v,o            q,k,v,o              q,k,v,o
훈련 가능 파라미터      ~2.2MB           ~17.5MB            ~8.7MB               ~17.4MB
전체 파라미터 대비      ~0.20%           ~0.88%             ~0.56%               ~1.12%
훈련 샘플               ~50건            203건              203건                291건
Epochs                  5                5                  5                    8
Learning Rate           2e-4             1e-4               1e-4                 1e-4
LR Schedule             Linear           Linear             Linear               Linear
Gradient Accum          4                8                  8                    8
Max Seq Length          512              768                768                  768
최종 train loss         ~1.05            0.692              0.656                진행 중
최종 eval loss          N/A              N/A (미설정)        0.701                진행 중
학습 시간               ~15분            47.6분             9.3분 (556초)        진행 중
Q4 GGUF 크기            N/A              ~1.6GB (배포 불가) 986MB ✅             변환 예정
Railway 배포            N/A              불가 (1GB 초과)    가능 ✅              가능 예정

[하이퍼파라미터 선택 근거]
- rank 16→32: rank 4/8은 보안 도메인 특화에 부족, rank 64+는 소규모 데이터 과적합 위험.
              2차에서 rank=32로 상향 — 291건의 다양한 CWE를 캡처하기 위함.
- alpha=2×rank: LoRA 논문(Hu et al., 2021) 권장. 스케일 factor = alpha/rank = 2.0.
- lr=1e-4: SFT 표준. 사전학습 lr 대비 높게 설정해 새 도메인(보안 코드)에 빠르게 적응.
- grad_accum=8: batch_size=1 (M3 메모리 제약) → 유효 배치 8로 안정적 gradient 추정.
- target=attention only: FFN 제외로 학습 파라미터 최소화. Railway RAM 1GB 대응.
- dropout=0.05: 소규모 데이터 과적합 방지. 0.1 이상은 언더피팅 위험.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 7. 학습 곡선 분석 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[차트 1 이미지 삽입]

[Gemma-2 LoRA train loss — step 기준]
step 10→2.909 | step 20→1.649 | step 30→1.320 | step 40→1.108
step 50→1.021 | step 60→0.914 | step 70→0.844 | step 80→0.797
step 90→0.808 (소폭 상승, 이후 재수렴) | step 100→0.710
step 110→0.698 | step 120→0.711 | step 130→0.692 (최종, epoch 5.0)
※ Gemma-2는 eval loss 미설정(별도 eval split 없음)
학습시간: 47.6분

[Qwen QLoRA 1차 — train loss (실측 로그, 203건, rank=16, 5 epochs)]
step 10→2.891 | step 20→2.021 | step 30→1.519 | step 40→1.142
step 50→0.977 | step 60→0.879 | step 70→0.797 | step 80→0.737
step 90→0.698 | step 100→0.692 | step 110→0.656 (최종 train loss)
학습시간: 9.3분 (train_runtime=556.1초)

[Qwen QLoRA 1차 — eval loss (epoch별)]
epoch 1 (step 23)  → 1.532
epoch 2 (step 46)  → 0.964
epoch 3 (step 69)  → 0.801
epoch 4 (step 92)  → 0.726
epoch 5 (step 115) → 0.701 ← best checkpoint 채택

[Qwen QLoRA 2차 — 초기 train loss (진행 중)]
step 10→2.811 | step 20→1.939 | step 30→1.375

[학습 곡선 해석]
- Qwen이 Gemma 대비 초기 loss 하락 속도 빠름 → 코드 특화 사전학습 효과
- Qwen 1차: train loss(0.656)와 eval loss(0.701)가 교차하지 않음 → 과적합 없음
- Qwen 학습시간 9.3분 vs Gemma 47.6분 → Qwen 1.5B가 Gemma 2B 대비 5배 빠름
- Qwen 2차 초기값이 1차 대비 빠른 수렴 패턴 → rank=32, clean format 데이터 효과 예상
- Gemma step 80→90 구간 소폭 상승(0.797→0.808)은 정상 범위의 일시적 변동

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 8. 모델 변환 파이프라인 (LoRA → Ollama) 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: PEFT merge_and_unload()
  입력: Qwen 베이스(3GB) + LoRA 어댑터(~17MB)
  출력: merged safetensors (2.9GB)

Step 2: HuggingFace safetensors → GGUF F16
  도구: gguf PyPI 라이브러리 (GGUFWriter) — llama.cpp Python 스크립트 불필요
  출력: qwen-security.f16.gguf (3.09GB)
  메타데이터: 28 layers, 1536 hidden dim, 12/2 heads, 151936 vocab

Step 3: Q4_K_M 양자화
  도구: llama-quantize (llama.cpp, brew 설치)
  명령: llama-quantize qwen.f16.gguf qwen.Q4_K_M.gguf Q4_K_M
  출력: qwen-security.Q4_K_M.gguf (0.99GB) — F16 대비 68% 압축

Step 4: Ollama 등록
  명령: ollama create qwen2.5-coder-security -f Modelfile
  등록 크기: 986MB → Railway 1GB RAM 제약 충족 ✅

[기술적 도전 해결 사례]
①  Metal GPU 타입 오류: RMSNorm 가중치를 float16 저장 시 GGML_ASSERT 실패
    → attn_norm, ffn_norm, output_norm을 float32로 강제 저장하여 해결

②  tokenizer.ggml.merges 형식 오류:
    Qwen2 tokenizer가 merges를 [["a","b"],...] 리스트-of-페어로 저장하나
    GGUF는 "a b" 공백 구분 문자열 요구
    → merges_list = [" ".join(pair) for pair in merges_list] 로 변환

③  EOS 토큰 인식 문제:
    GGUF 변환 후 EOS 토큰(ID 151643)이 "[EMPTY_151643]"로 노출되어
    Ollama가 생성 중단을 못 함 → 무한 반복 또는 garbage 출력
    → stop 파라미터에 "[EMPTY_151643]" 추가, 후처리로 sentinel 이후 텍스트 제거

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 9. 벤치마크 결과 (실측값, 2026-05-26) 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[테스트셋 구성]
총 20개 케이스 (직접 설계, benchmark_core.py)
언어: React/Next.js(4), Node.js/Express(4), Java Spring Boot(4), Python(4), C(2), GitHub Actions(2)
취약점 유형:
  XSS(×2), SQL Injection(×3), Command Injection(×4), Hardcoded Secret,
  Deserialization, YAML Injection, Format String, Buffer Overflow,
  CORS 취약점, GitHub Actions Injection, Access Control, Timing Attack, Supply Chain

[평가 지표]
  detection_rate: 응답에 취약점 관련 키워드/CWE ID 포함 여부 (20개 중 n개)
  mean_latency:   평균 응답 시간 (초, 낮을수록 좋음)

[모델별 벤치마크 결과표] — [차트 2 이미지 삽입]

모델 구성                                    탐지율(20건)  평균 응답    비고
────────────────────────────────────────────────────────────────────────────
Gemma:2b (Ollama BASE, 파인튜닝 없음)         18/20 (90%)   4.29s     CWE 미출력, 형식 불일정
Qwen2.5-Coder-1.5B (Ollama BASE, 파인튜닝 없음) 17/20 (85%)  1.16s     빠르나 CORS/CI 탐지 취약
Grok-3 API (xAI 클라우드, 비교 기준선)        19/20 (95%)  17.66s    높은 탐지율, 느림, 유료
ScanOps RAG v1 (ChromaDB + Grok-3)            18/20 (90%)   3.85s     CVE hit율 25%
ScanOps RAG v2 (Qdrant + Grok-3) ✅          20/20 (100%)   5.45s     최고 탐지율 달성
──── 로컬 시스템 실측 (2026-05-26 추가 측정) ────────────────────────────────
Qwen BASE + Qdrant RAG                        16/20 (80%)   1.48s     RAG 컨텍스트 형식이 일부 케이스 오분류 유발
Qwen QLoRA 1차 (fine-tuned, RAG 없음)          1/20  (5%)   1.53s     훈련 데이터 형식 문제로 출력 불안정
Qwen QLoRA 1차 + Qdrant RAG                   11/20 (55%)   3.89s     RAG로 +50%p 개선, 재훈련으로 추가 향상 목표

[RAG 효과 분석]

① Grok-3 기반 RAG (기준선 비교)
  Grok-3 단독 95% → Qdrant RAG 100% (+5%p)
  CVE 컨텍스트가 GitHub Actions 인젝션 등 비전통적 취약점 식별에 결정적으로 기여
  응답 속도: Grok-3 단독 17.66s → RAG 5.45s (약 3.2배 단축)
    → RAG 프롬프트 농축으로 LLM이 처리해야 할 토큰량 감소

② 로컬 Qwen BASE + RAG
  Qwen BASE 단독 85% → Qdrant RAG 80% (-5%p)
  Qwen BASE는 RAG 없이도 85%를 달성하며, RAG CVE 컨텍스트 형식이
  일부 케이스(case #8 Hardcoded Secret, case #19 GitHub Actions)에서 오분류를 유발.
  → 소규모 모델일수록 프롬프트 복잡성에 민감함을 시사

③ QLoRA 1차 파인튜닝 + RAG
  QLoRA 단독 5% → Qdrant RAG 55% (+50%p)
  RAG CVE 컨텍스트가 파인튜닝 모델의 취약한 도메인 지식을 보완.
  단독 5%의 원인: VULN_TYPE: 트리거 충돌로 비구조화 출력 발생.
  → QLoRA 2차 재훈련(clean format) 완료 시 RAG 결합 성능 80% 이상 달성 예상

[미탐지 케이스 분석]

Gemma:2b BASE       Case #9  (Deserialization)    pickle 위험 패턴 미인식
Gemma:2b BASE       Case #20 (Supply Chain)       GitHub Actions 공급망 개념 부재
Qwen BASE           Case #7  (CORS CWE-942)       XSS로 오분류
Qwen BASE           Case #11 (Access Control)     XSS로 오분류
Qwen BASE           Case #12 (Timing Attack)      SQL Injection으로 오분류
Grok-3 API          Case #20 (Supply Chain)       unpinned 버전 위험 미인식
Qwen BASE+RAG       Case #3  (Code Injection)     CVE 컨텍스트가 prototype pollution으로 유도
Qwen BASE+RAG       Case #8  (Hardcoded Secret)   CVE 컨텍스트가 CSRF로 유도
QLoRA+RAG (11건)    Case #1,4,5,8,12,13,19,20 등  비구조화 출력, 형식 불일치

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 10. 결론 및 향후 연구 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[주요 기여]
1. 1GB 이하 경량 LLM(Qwen2.5-Coder-1.5B)에 QLoRA 파인튜닝 적용.
   동일 데이터·하이퍼파라미터에서 Gemma-2 2B LoRA(0.692) 대비 낮은 train loss(0.656) 달성.
   학습 속도: Gemma-2 47.6분 대비 Qwen 9.3분 (5배 빠름).

2. Gemma-2 LoRA vs Qwen QLoRA 비교 실험으로 코드 특화 모델 우수성 정량 검증.

3. NVD CVE 792건 기반 Qdrant RAG 파이프라인 구축.
   Grok-3 API 결합으로 20개 테스트 케이스 탐지율 100% 달성.
   QLoRA 파인튜닝 모델 + RAG: 단독 5%에서 55%로 +50%p 개선.

4. LoRA 어댑터 → GGUF Q4_K_M 변환 파이프라인 독자 구현.
   llama.cpp Python 스크립트 없이 gguf PyPI만으로 변환 성공.
   RMSNorm float32 강제 저장, tokenizer merges 형식 변환, EOS 토큰 노출 3가지 문제 해결.

5. Railway 클라우드 RAM 1GB 제약 충족하는 986MB GGUF 경량 배포 달성.

[한계점]
- 훈련 데이터 291건 — 실제 운용에는 1,000건 이상 필요
- QLoRA 1차 단독 탐지율 5% — 훈련 데이터 형식 문제(VULN_TYPE 트리거 충돌)가 원인.
  v4 clean format 데이터로 재훈련 진행 중
- MPS 환경에서 bitsandbytes 미지원 → 4-bit 진정한 QLoRA 불가.
  float16 full-load 후 LoRA 방식으로 학습 (CUDA 환경이면 메모리 50% 추가 절감 가능)
- Qwen BASE + RAG가 BASE 단독보다 탐지율 낮은 케이스 존재 (80% vs 85%).
  소규모 모델에서 CVE 컨텍스트 형식이 오분류를 유발할 수 있음 → 프롬프트 최적화 필요
- RAG 최고 성능(100%)은 Grok-3 API(클라우드) 기반 → 로컬 QLoRA 2차 재훈련으로 교체가 최종 목표

[향후 과제]
- Qwen QLoRA 2차 훈련 완료 후 GGUF 재변환 및 Ollama 재등록
- QLoRA 2차 + RAG 벤치마크 재측정 (목표: 탐지율 80% 이상)
- 훈련 데이터 1,000건 이상 확장 (CWE Top-25 전수 커버)
- RAG 프롬프트 최적화: CVE 컨텍스트 형식 개선으로 소규모 모델 오분류 제거
- CI/CD 파이프라인 통합 (GitHub Actions 자동 스캔 훅)
- CUDA GPU 환경에서 True QLoRA (4-bit 베이스 + float16 어댑터) 적용

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【 11. 보고서 목차 및 작성 지시 】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

아래 목차 구조로 .docx 보고서를 작성해주세요.
A4, 15~20페이지, 한국어, 표·그림·코드블록 포함.
첨부된 차트 PNG 5개를 지시된 위치에 삽입하세요.

목차:
1. 초록 (한국어 + 영문)
2. 프로젝트 개요 (목적, 환경, 기술 스택)
3. 시스템 아키텍처 (RAG 파이프라인, CVE DB 구성)
4. 개발 단계별 실험 흐름 (Phase 1~6, [차트 4])
5. 훈련 데이터 구성 (버전 변천, v4 포맷 개선, [차트 3])
6. 모델 비교 실험 (하이퍼파라미터 표, [차트 5])
7. 학습 곡선 분석 ([차트 1])
8. 모델 변환 파이프라인 (LoRA→GGUF→Ollama, 기술 도전 해결)
9. 벤치마크 결과 (전체 비교표, RAG 효과 분석, [차트 2])
10. 결론 및 향후 연구

[작성 시 주의사항]
① "Qwen QLoRA 1차" 학습시간은 반드시 9.3분(556초)으로 기재하세요 (이전 보고서의 16.9분은 오류).
② 100% 탐지율의 주체는 "Qdrant RAG + Grok-3 API 조합"이며, 로컬 파인튜닝 모델 단독이 아닙니다.
③ QLoRA 파인튜닝 모델(qwen2.5-coder-security) 단독 탐지율은 5% (훈련 형식 문제),
   RAG 결합 시 55%로 향상됨을 명확히 서술하세요.
④ Grok-3는 비교 기준선(벤치마크)으로만 사용된 것이며, 실제 ScanOps 시스템 기본 LLM은
   Qwen2.5-Coder-1.5B (Ollama)입니다.
⑤ 로드맵 차트(차트 4)에는 Phase 1~6이 표시됩니다.
```

═══════════════════════════════════════════════════════════════
## ▶ 복사 끝
═══════════════════════════════════════════════════════════════

---

## 데이터 출처 확인

모든 수치는 아래 실측 데이터에서 추출됨:

| 데이터 | 파일 경로 |
|--------|-----------|
| Gemma/Qwen BASE 벤치마크 | `reports/benchmark_compare.json` |
| Grok-3 API 벤치마크 | `reports/results_ScanOps_—_Grok_API_(grok-3).json` |
| RAG v1 (ChromaDB+Grok) | `reports/results_RAG_grok3.json` |
| RAG v2 (Qdrant+Grok) | `reports/results_RAG_v2_grok3.json` |
| Qwen BASE+RAG, QLoRA 1차 벤치마크 | `reports/benchmark_all_results.json` (2026-05-26 신규 측정) |
| Qwen QLoRA 학습 로그 | `reports/train_qwen_qlora.log` (train_runtime=556.1s) |
| 훈련 데이터 v4 | `data/lora_train_v4.jsonl` (291건) |
