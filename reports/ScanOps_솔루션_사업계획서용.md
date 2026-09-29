# ScanOps 모델 — 솔루션 정리 (사업계획서용 / Claude 레퍼런스)

> 목적: 사업계획서 "솔루션" 섹션 작성 + Claude가 모델을 정확히 이해하도록 한 문서로 정리.
> 작성: 2026-06-30 (V13 라운드 진행 중)

---

## 0. 한 줄 정의
**ScanOps 모델은 "보안 특화 코드 취약점 분석 엔진"이다.** 소스코드(또는 스니펫)를 입력받아
취약점 종류(CWE) · 심각도(CVSS) · 근거 · 수정 가이드를 출력한다. 범용 LLM과 달리
**(1) 보안 파인튜닝 LLM + (2) 최신 CVE RAG + (3) 정적 taint 그래프**를 결합한 하이브리드 구조다.

ScanOps 전체 서비스(ZAP 스캔 → CVSS → AI 분석 → PDF 리포트) 안에서, 이 모델은 백엔드
AI 라우터(`GPT → Claude → Gemini → CUSTOM`)의 **CUSTOM 엔진** 역할을 한다. 즉 외부 API에
의존하지 않는 **자체 보유 분석 모델**이다.

---

## 1. 문제 (왜 필요한가)
- **범용 LLM(GPT·Claude·Grok)의 한계 ①: 최신성.** 학습 컷오프 이후 공개된 신규 CVE를 모른다.
- **범용 LLM의 한계 ②: 멀티파일 taint 증명.** "사용자 입력이 어디서 위험한 sink까지 흐르는가"를
  구조적으로 증명하지 못하고 "확신 없으면 안전"으로 미탐(false negative)하는 편향이 있다.
- **외부 API 의존의 한계: 비용·데이터 유출.** 고객 소스코드를 외부 LLM에 보내야 함 + 호출당 과금.
- **기존 스캐너(ZAP 등)의 한계: 동적 분석 중심**이라 소스코드 레벨의 의미 분석엔 약함.

→ ScanOps 모델은 **자체 호스팅 + 최신 CVE 인지 + taint 경로 증명**으로 이 격차를 메운다.

---

## 2. 솔루션 아키텍처 (3-기둥 하이브리드)

```
입력: 코드 + 언어
  │
  ├─[기둥 A] 파인튜닝 LLM (Qwen2.5-Coder-7B + 보안 QLoRA 어댑터, Ollama 서빙)
  │            → 취약/안전 1차 판정 + CWE/CVSS
  │
  ├─[기둥 B] RAG (BGE 임베딩 → Qdrant 최신 CVE 8,883건 검색)
  │            → "이 코드와 유사한 신규 CVE" 컨텍스트 보강 (최신성 담당)
  │
  └─[기둥 C] 정적 taint 그래프 (multi_graph, 규칙기반 7개 언어)
               → source→sink→sanitizer 경로로 vuln/safe/unknown 판정
  │
  ▼
하이브리드 결합기:
   그래프 'vuln' → 취약 확정 / 그래프 'strong-safe' → 안전 확정(veto) /
   'unknown' → LLM 판단에 위임
  │
  ▼
출력: 취약점 목록 + CWE + CVSS + 근거(graph_evidence) + 수정 스니펫
```

### 기둥 A — 보안 파인튜닝 LLM
- 베이스: **Qwen2.5-Coder-7B-Instruct**, 위에 **QLoRA 어댑터**(r=32/alpha=64/dropout=0.05)를 학습.
- 서빙: **Ollama ADAPTER 방식**(베이스 + 어댑터 GGUF, 병합 없이) — 어댑터만 ~40MB라 교체·배포 경량.
- 출력 포맷: 3줄 구조화(`VULNERABILITY / SEVERITY / CVSS`)로 강제 — 파싱·일관성 확보.

### 기둥 B — RAG (최신성 담당)
- 임베딩: **BAAI/bge-small-en-v1.5** (384차원, L2정규화).
- 벡터DB: **Qdrant** — **2026년 신규 NVD CVE 8,883건**(무효/반려 제거 후) 적재.
- 역할: 범용 LLM이 "학습 못 한 신규 취약점"을 검색 컨텍스트로 보강. **차별점의 핵심.**

### 기둥 C — 정적 taint 그래프 (판별 근거 담당)
- **규칙기반** source→sink→sanitizer 분석. Java 전용 + JS/TS 멀티파일(Neo4j) + 7개 언어
  generic(Python/PHP/Go/C#/Ruby/Node/TS).
- 커버 CWE: SQLi(89)·CmdI(78)·XSS(79)·Path Traversal(22)·SSRF(918)·Deserialize(502)·
  Code Injection(94)·Weak Crypto(327/328)·Insecure Random(330)·Hardcoded Secret(798).
- 설계 원칙: **"확신할 때만 vuln/safe, 애매하면 unknown→LLM 위임"** — 미탐(false-negative) 최소화.
- 가치: LLM이 못 잡는 taint 경로를 증명해 **재현율↑** + 명백한 안전 케이스 **오탐↓**(strong-safe veto).

---

## 3. 차별점 (경쟁 우위)

| 항목 | 범용 LLM (Grok 등) | 기존 스캐너(ZAP) | **ScanOps 모델** |
|---|---|---|---|
| 신규 CVE 인지 | ✕ (학습 컷오프) | △ | ✅ RAG 8,883 최신 CVE |
| 멀티파일 taint 증명 | ✕ (미탐 편향) | △ | ✅ 그래프 엔진 |
| 자체 호스팅(데이터 보안) | ✕ 외부 API | ✅ | ✅ Ollama 로컬 |
| 호출 비용 | 과금 | — | ✅ 자체 모델(무과금) |
| 소스코드 의미 분석 | ✅ | ✕ 동적 위주 | ✅ |

- **그래프 단독 벤치(2026-06)**: 멀티파일 XSS/SSRF 100케이스에서 ScanOps 그래프 100% vs Grok 67%
  (Grok은 fetch/axios SSRF·img-XSS를 "확신없으면 SAFE"로 미탐). → **taint 경로 증명이 구조적 우위.**

---

## 4. 진행 상황 (어디까지 왔나)

### 모델 버전 히스토리
- **v2 (2026-05)**: 203개 데이터 QLoRA + RAG 어댑티브 → 표준 20케이스 탐지율 95%, Grok 대비 6.5배 빠름.
- **v4~v11**: 데이터·그래프 점진 확장. 단, OWASP를 학습+평가에 같이 써 **데이터 누수(과적합)** 발견.
- **v12 (2026-06-29)**: 누수 차단 — OWASP를 학습서 완전 제외하고 **zero-shot 평가**로 정직화.
  7B 배포 확정. **한계 측정됨**: 학습셋이 264개로 너무 작아 실제 CVE 판별력 부족.
- **v13 (진행 중)**: 학습셋 13배 확장 + RAG 11배 확장 (아래 §5).

### v12 정직한 베이스라인 (2026-06-30 측정, `reports/V13_BASELINE.md`)
| 벤치 | 시스템 | F1 | 재현율 | 정확도 |
|---|---|---|---|---|
| **CVEfixes 157**(실제 CVE) | v12 7B + 그래프 | 2.5 | **1.2%** | 49.7% |
| | Grok | 40.0 | 30.0% | 54.1% |
| **OWASP 110** | v12 7B + 그래프 | 75~84* | 92.7% | 69~83%* |
| | Grok | 83.5 | 96.4% | 80.9% |

- *입력 추출 방식에 따라 그래프 strong-safe veto 작동 여부가 갈려 F1 75~84.
- **정직한 현주소**: OWASP 같은 패턴형 취약점은 그래프로 Grok에 필적/추월. 그러나 **실제 미묘한 CVE는
  현재 7B가 판별력 부족(재현율 1.2%)** — 이게 v13이 겨냥하는 약점.

---

## 5. 현재 디벨롭 중 (V13 라운드)

**목표: "자체 7B + 그래프가 대표 벤치에서 Grok을 정직하게 능가"**

1. **학습 데이터 13배 확장** ✅ 완료
   - 출처: HuggingFace `cvefixes`(실제 CVE 패치 커밋의 취약/수정 코드쌍).
   - 264개 → **3,483개** (10개 언어 균형). 누수 차단: held-out CVE 141건 제외 + 코드해시 dedup +
     OWASP 흔적 제외 + train/val CVE 단위 분리.
2. **RAG 인덱스 11배 확장 + 정제** ✅ 완료
   - Qdrant 792 → **8,883** (2026 신규 CVE). **무효·반려(REJECT/DISPUTED) 26건 + 중복 225건 제거.**
   - 전처리 파이프라인의 반려 필터 누락 버그 영구 수정.
3. **7B QLoRA 재학습** ⏳ 진행 예정 (Colab A100, 노트북 준비 완료)
   - GPU 자동감지(bf16/fp16) 노트북 + 어댑터→GGUF 변환 + Ollama 배포까지 자동화.
4. **재평가** ⏳ 학습 후
   - OWASP zero-shot + CVEfixes held-out 141 + Grok 비교. 베이스라인(재현율 1.2%) 대비 향상 측정.
5. **그래프 개선** ⏳ full-file에서도 strong-safe 탐지가 켜지도록 — OWASP에서 Grok 확실히 추월.

---

## 6. 사업계획서 솔루션 섹션 — 핵심 메시지 (요약문)

> ScanOps는 ZAP 동적 스캔에 더해, **자체 보유 보안 특화 AI 엔진**으로 소스코드를 정적 분석한다.
> 이 엔진은 ① 보안 파인튜닝된 코드 LLM(Qwen-7B), ② 최신 NVD CVE 8,883건을 검색하는 RAG,
> ③ 7개 언어 taint 그래프를 결합한 하이브리드 구조로, **범용 LLM이 못 보는 신규 CVE를 인지**하고
> **멀티파일 취약 경로를 증명**한다. 외부 API에 의존하지 않아 **고객 코드를 외부로 보내지 않고
> 호출 비용도 없다.** 현재 실제 CVE 데이터셋으로 학습을 13배 확장(264→3,483)해 판별력을
> 끌어올리는 V13 고도화를 진행 중이며, 대표 벤치마크에서 상용 모델(Grok) 대비 동등~우위를
> 목표로 한다.

---

## 부록: 기술 사실 체크리스트 (Claude가 글 쓸 때 참고)
- 베이스 모델: Qwen2.5-Coder-7B-Instruct (이전엔 1.5B/Gemma-2/3B도 실험).
- 파인튜닝: QLoRA 4-bit, r=32/alpha=64/dropout=0.05, target q/k/v/o_proj, 3 epoch, lr=1e-4.
- 임베딩: bge-small-en-v1.5 (384d). 벡터DB: Qdrant cosine, 8,883 CVE.
- 서빙: Ollama, ADAPTER 방식(병합 없음), rp=1.3, temperature 0.
- 그래프: 규칙기반(정규식 taint), Java/JS-TS(Neo4j)/7개 언어 generic, 판정 vuln|safe|unknown.
- 정직성 원칙: 벤치마크 케이스에 규칙/데이터를 맞추지 않음(과적합 방지), 누수 차단, 수치는 실측만.
- 숫자(현재): 학습 3,483 / RAG 8,883 / 지원 언어 ~10 / 커버 CWE ~11종.
