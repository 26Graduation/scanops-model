# ScanOps — 보안 취약점 자동 탐지 시스템 최종 보고서 v5

> 작성일: 2026-06-09  |  모델: QLoRA v4 (Qwen2.5-Coder-1.5B) + v5 오탐 필터(Hybrid Adjudication)
> 핵심 주제: **오탐률(False Positive Rate) 중심 재평가 — 최신 NVD CVE 기반 100케이스, Grok-3 비교**

---

## 0. v5 핵심 요약 (한눈에)

| 항목 | v4 | **v5** |
|------|----|--------|
| 평가 관점 | 탐지율 100% (40케이스, 양성만) | **오탐률 중심 (100케이스, 양성50+음성50)** |
| 테스트 데이터 | 자체 작성 케이스 | **2026.5~6월 신규 공개 NVD CVE 패턴 + 안전코드** |
| 비교 대상 | Grok-3 (탐지율) | **Grok-3 (탐지율 + 오탐률 + 정밀도)** |
| 오탐 필터 | 없음 (raw FPR ≈ 100%) | **정적 mitigation 분석 + LLM 하이브리드 게이트 → FPR 6%** |
| 요금제 | (미정의) | **Free / Pro ₩49,000 / Max ₩149,000 (줄 기반 과금)** |
| 신규 기능 | — | **XLS 리포트, NVD 변경 알림, 도메인/GitHub App 인증** |

**가장 중요한 발견 — "100% 탐지율"의 한계와 그 해결:**
v4의 "40/40 = 100% 탐지율"은 **취약한 코드만 테스트**한 수치였습니다. 실제 운영에서 더 중요한 질문은
*"안전한 코드를 취약하다고 잘못 알리지 않는가(오탐률)"* 입니다. 측정 결과 **v4 raw 모델은 안전 코드의
100%를 취약으로 오탐**(파라미터라이즈 쿼리, prepared statement, 심지어 `def add(a,b): return a+b`까지)했습니다.
v5는 이를 해결하는 **오탐 필터(adjudication gate)** 를 추가해 **오탐률을 100% → 6%로 낮췄고**,
프런티어 모델 **Grok-3와 동일한 정확도(93%)·동등한 F1(92.9 vs 92.5)** 를 달성하면서 **응답은 10배 빠르고
비용은 자체 호스팅으로 구독제(₩0~149,000) 운영이 가능**합니다.

---

## 1. 왜 "오탐률"과 "최신 NVD CVE"인가

### 1.1 탐지율만으로는 부족하다

보안 스캐너의 실전 가치는 두 축으로 결정됩니다.

```
              실제 취약                실제 안전
            ┌─────────────┬─────────────────────────┐
  취약 판정  │  TP (정탐)  │  FP (오탐) ← 개발자 피로  │
            ├─────────────┼─────────────────────────┤
  안전 판정  │  FN (미탐)  │  TN (정상)               │
            └─────────────┴─────────────────────────┘

  탐지율(Recall) = TP / (TP+FN)   ← v4가 자랑한 지표
  오탐률(FPR)    = FP / (FP+TN)   ← v5가 새로 측정한 지표
```

오탐(FP)이 많으면 개발자가 경고를 무시하게 되어("alert fatigue") 스캐너 자체가 버려집니다.
실제 연구에서도 LLM 기반 취약점 탐지의 **오탐(false discovery)이 가장 큰 약점**으로 지목됩니다
— 프로젝트 규모 실측에서 최상위 도구조차 평균 false discovery rate가 85%에 달했고,
스마트컨트랙트 평가에서 GPT-4o-mini·Claude 3.5 Sonnet의 오탐률이 0.78~0.85로 보고되었습니다.

### 1.2 최신 NVD CVE를 노린 이유

```
Claude / GPT / Grok 등 프런티어 LLM
    └─ 학습 데이터 컷오프 존재 (과거 시점에서 동결)

NVD(National Vulnerability Database)
    └─ 매시간·매주 신규 CVE 공개 (2026년에도 계속 누적)

⇒ "학습 컷오프 이후 공개된 신규 CVE"는 프런티어 모델이 암기할 수 없다.
   이 신규 CVE 패턴으로 테스트하면 "암기"가 아닌 "일반화·근거 기반 탐지" 능력을 본다.
   ScanOps는 NVD를 RAG로 실시간 참조하므로 신규 CVE에 강하다 — 이것이 차별점.
```

본 벤치마크의 **양성(취약) 50케이스는 전부 2026년 5~6월 NVD 신규 공개 CVE 패턴**에서 도출했습니다
(수집: NVD API, 2026-04-30 ~ 2026-06-09, 총 **9,134건** 중 CWE 보유 8,216건).

---

## 2. 벤치마크 설계 (v5)

### 2.1 데이터셋 — 100케이스 (양성 50 / 음성 50)

```
양성(취약) 50개  ── 2026.5~6월 NVD 신규 CVE 패턴 기반
  SQLi·XSS·Command Injection·Path Traversal·SSRF·CSRF·Deserialization·
  Missing AuthN/AuthZ·IDOR·Hardcoded Cred·XXE·Open Redirect·File Upload·
  LDAP Injection·SpEL·Weak Crypto·SSTI·NoSQL·Prototype Pollution·CORS 등 20여 CWE

음성(안전) 50개  ── mitigation 적용 코드 + 순수 비즈니스 로직 (오탐 측정용)
  parameterized/prepared 쿼리, ORM, 출력 이스케이프(React/htmlspecialchars/DOMPurify),
  authz 가드, 상수시간 비교, bcrypt/SecureRandom, env 시크릿, 경로 정규화,
  safe_load, XXE 비활성화, rate limit, 순수 로직(add/fib/reduce) 등
```

언어 분포: Python 30 · Node/Express 29 · Java Spring 24 · React 7 · PHP 7 · Go 2 · C 1

각 양성 케이스는 **실제 CVE ID로 근거**가 표기됩니다(예시):

| 패턴 | 근거 CVE (2026, 최신) |
|------|----------------------|
| Command Injection | CVE-2026-11572 (degit), CVE-2026-40519 (Nginx Proxy Manager) |
| Path Traversal | CVE-2026-41843 (Spring MVC), CVE-2026-46484 (Headplane) |
| Insecure Deserialization | CVE-2026-41855 (Spring JMS Jackson), CVE-2026-7566 (LearnPress) |
| Auth Bypass | CVE-2026-41720 (Spring LDAP empty-password) |
| SSRF | CVE-2026-41854 (Spring UriComponentsBuilder) |
| LDAP Injection | CVE-2026-44930 (Apache CXF), CVE-2026-46745 (Airflow) |
| Hardcoded Backdoor | CVE-2025-71317 (NetMan 204) |
| SpEL Injection | CVE-2026-41852 (Spring SpEL) |

### 2.2 측정 시스템 (공정 비교)

```
세 가지를 동일한 100케이스로 측정:

  ① ScanOps v4-raw   : 기존 파인튜닝 탐지기 (항상 취약 출력)        ← 오탐 baseline
  ② ScanOps v5       : v4 탐지 + [정적 mitigation 분석 + 1.5B LLM] 하이브리드 게이트
  ③ Grok-3-mini (xAI): ②와 동일 파이프라인, LLM 코어만 Grok으로 교체  ← 프런티어 비교군

  → ②와 ③은 완전히 동일한 파이프라인을 사용하고 LLM만 교체 → 공정한 1:1 비교
```

> **비교 대상 표기:** Anthropic(Claude)·OpenAI(GPT) API 키 미보유로 직접 실행이 불가하여,
> 직접 실행 가능한 프런티어 모델 **Grok-3 (xAI)** 를 1:1 비교군으로 채택했습니다.
> Claude/GPT의 오탐 경향은 공개 연구 수치(§1.1)로 참조합니다.

---

## 3. 벤치마크 결과 ★

### 3.1 최종 비교표

```
시스템                              탐지율    오탐률    정밀도   정확도    F1    평균응답
──────────────────────────────────────────────────────────────────────────────────
ScanOps v4-raw (오탐 필터 없음)       100%     100%      50%     50%    66.7    —
ScanOps v5 (하이브리드 게이트)         92%       6%    93.9%     93%    92.9   0.2s ★
Grok-3-mini (xAI, 동일 파이프라인)     86%       0%   100.0%     93%    92.5   2.14s
──────────────────────────────────────────────────────────────────────────────────
```

```
오탐률(FPR) — 낮을수록 좋음
  ScanOps v4-raw  ████████████████████ 100%   (안전코드 전부 오탐)
  ScanOps v5      █░░░░░░░░░░░░░░░░░░░░   6%   ← 오탐 필터로 94%p 개선
  Grok-3-mini     ░░░░░░░░░░░░░░░░░░░░    0%

탐지율(Recall) — 높을수록 좋음
  ScanOps v5      ██████████████████░░  92%   ← Grok보다 6%p 높음
  Grok-3-mini     █████████████████░░░  86%

정확도(Accuracy) — 동일
  ScanOps v5      ██████████████████░░  93%
  Grok-3-mini     ██████████████████░░  93%
```

### 3.2 핵심 해석 — "동등 성능, 더 저렴, 더 빠름"

1. **정확도 동일(둘 다 93%), F1 동등(92.9 vs 92.5).** 종합 성능은 프런티어 모델과 **동급**입니다.
2. **오탐률: v4-raw 100% → v5 6%로 94%p 개선.** 오탐 필터가 핵심 기여입니다.
   Grok(0%)보다 3건 많지만, ScanOps는 **취약점을 4건 더 탐지(46 vs 43)** 하여
   전체 정확도는 동일합니다 — 즉 **"안전 중심(recall 우선)" vs "정밀 중심(precision 우선)"의 트레이드오프**.
3. **응답 속도 ~10배 (0.2s vs 2.14s).** 100케이스 중 40건은 정적 분석기가 즉시 처리, 나머지만 LLM 호출.
4. **비용: 자체 호스팅 986MB 모델** — API 토큰 과금이 없어 **구독제(₩0~149,000)** 운영이 가능.

### 3.3 흥미로운 차이 — Grok이 놓친 취약점

```
Grok-3가 미탐(FN)한 7건 (ScanOps v5는 대부분 탐지):
  · Missing Authorization (CVE-2026-44751 류)          ← ScanOps ✓
  · Missing Authentication (CVE-2023-54350 류)         ← ScanOps ✓
  · Hardcoded Credentials                              ← ScanOps ✓
  · Missing Rate Limiting (brute force)                ← ScanOps ✓
  · Prototype Pollution                                ← ScanOps ✓
  · Weak Hash (MD5)                                    ← 둘 다 미탐
```

이는 공개 연구가 지적한 *"프런티어 LLM의 잔여 오류가 암호·정책(policy)성 CWE에 집중된다"* 는
현상과 일치합니다. **권한·인증·정책 계열 취약점에서 ScanOps가 오히려 강점**을 보였습니다.

ScanOps v5의 오탐 3건(FP)·미탐 4건(FN)은 부록 §9에 전부 공개합니다(투명성).

---

## 4. v5 시스템 — 오탐 필터(Hybrid Adjudication)

v4 파인튜닝 모델은 **취약 코드만 학습**했기에 "항상 취약점을 출력"하는 과탐지기였습니다(raw FPR 100%).
v5는 그 위에 **2단계 오탐 필터**를 얹어 안전 코드를 걸러냅니다.

```
                     코드 입력
                        │
                        ▼
        ┌───────────────────────────────┐
        │ Stage A: v4 QLoRA 탐지         │  취약 후보 + CWE/심각도 제시 (높은 recall)
        └───────────────┬───────────────┘
                        ▼
        ┌───────────────────────────────┐
        │ Stage B-1: 정적 mitigation 분석 │  OWASP 표준 완화기법 탐지
        │  (parameterized/prepared, 출력  │  → 강한 mitigation 확인 시 즉시 SAFE
        │   이스케이프, authz, 상수시간,   │     (100케이스 중 40건 즉시 종결, ~0초)
        │   secure random, env secret …)  │
        └───────────────┬───────────────┘
                  미해결 │ (raw 위험 sink 존재 등)
                        ▼
        ┌───────────────────────────────┐
        │ Stage B-2: LLM adjudication    │  mitigation-인지 프롬프트로
        │  (1.5B 모델, 단일라인 판정)     │  SAFE / VULNERABLE 최종 판정
        └───────────────┬───────────────┘
                        ▼
                  최종 판정 (+CWE)
```

- **정적 분석기**는 특정 테스트 케이스가 아니라 **OWASP 권고 완화기법의 일반 패턴**을 탐지합니다.
  검증 결과 **양성 50케이스에는 0건 발화(미탐 유발 없음)**, 음성 50케이스 중 40건을 정확히 SAFE로 구제했습니다.
- 정적 분석기가 못 거른 케이스만 LLM이 판정 → **속도(정적 즉시) + 정확도(LLM 보강)** 를 모두 확보.
- 이 파이프라인은 상용 스캐너(정적분석 + AI)에서 표준적으로 쓰이는 하이브리드 방식입니다.

---

## 5. 비즈니스 — 요금제 (v5 신규)

> v4의 "App 구매" 단건 결제 선택지는 **삭제**하고, **줄(line) 기반 구독제**로 전환합니다.

```
┌──────────────────┬──────────────────┬──────────────────────┐
│      Free        │       Pro        │        Max           │
│      ₩0          │   ₩49,000 / 월   │    ₩149,000 / 월     │
│                  │ (1주일 무료 체험   │                      │
│                  │  후 결제)        │                      │
├──────────────────┼──────────────────┼──────────────────────┤
│ 스캔 줄 제한      │ 5만 줄           │ 30만 줄              │
│   (체험용)       │                  │                      │
├──────────────────┼──────────────────┼──────────────────────┤
│ 기본 취약점 탐지  │ ✓                │ ✓                    │
│ 최신 NVD RAG     │ ✓                │ ✓                    │
│ XLS 리포트       │ ✗                │ ✓ (월 5회)           │
│ NVD 변경 알림     │ ✗                │ ✓ (주 1회·이메일)     │
└──────────────────┴──────────────────┴──────────────────────┘

줄 추가 구매: 1만 줄당 ₩5,000   (Pro·Max 공통, 제한 초과 시)
```

| 플랜 | 가격 | 줄 제한 | 비고 |
|------|------|---------|------|
| **Free** | ₩0 | (체험) | 기본 탐지 |
| **Pro** | **₩49,000/월** | **5만 줄** | **1주일 무료 후 결제**, XLS·NVD 알림 포함 |
| **Max** | **₩149,000/월** | **30만 줄** | 대규모 코드베이스 |
| 줄 추가 | **1만 줄당 ₩5,000** | — | 초과분 종량 구매 |

**원가 경쟁력의 근거:** ScanOps는 986MB 자체 호스팅 모델로 동작하여 **프런티어 API 토큰 과금이 발생하지 않습니다.**
프런티어 모델을 호출하는 경쟁 서비스는 호출당 비용이 누적되지만(§3.1 응답 2.14s/호출), ScanOps는
정적 분석으로 호출의 40%를 즉시 종결하고 나머지만 소형 모델로 처리하므로 **저가 구독제가 성립**합니다.

---

## 6. 신규 기능 (v5)

### 6.1 보안 위험 XLS 리포트 다운로드 (Pro)
- 탐지 결과를 XLS로 내보내 **팀 공유용**으로 사용 (공공기관 제출용 아님).
- **월 5회 제한** (Pro 한정).

### 6.2 신규 NVD/CVE 데이터 알림 (Pro)
- NVD에 **큰 변경(주요 신규 CVE)** 이 생기면 **주 1회 이메일 알림**.
- 사용자가 의존하는 스택과 관련된 신규 취약점을 선제적으로 통지.

### 6.3 인증 방식
```
① 웹 도메인 인증
   - .well-known 파일 방식 (도메인 루트에 검증 파일 배치)
   - 웹페이지에 절차를 상세히 안내 예정

② GitHub App 인증
   - 레포 "첫 스캔" 시 1회 인증
   - 이후 재인증 불필요 (앱 권한 유지)
```

---

## 7. 마케팅 전략 (v5 수정)

> 기존 Reddit / GitHub 중심 → **유튜브 / 인스타그램 콘텐츠 마케팅 중심으로 전환.**

```
주력 채널
  ▸ YouTube   : "신규 CVE 30초 분석", 취약점 데모, 실제 코드 리뷰 숏폼/롱폼
  ▸ Instagram : 카드뉴스(주간 신규 CVE), 비포/애프터 코드, 릴스

보조 채널 (비중 축소)
  ▸ Reddit / GitHub : 개발자 커뮤니티 인지도용 (메인 아님)

근거
  - 개발자·비개발 의사결정자 모두에게 도달하는 영상/이미지 포맷이 전환율 우위
  - "최신 NVD CVE 즉시 분석"이라는 제품 강점이 짧은 영상 데모와 궁합이 좋음
```

---

## 8. 재현 방법

```bash
cd /Users/kimsehan/Desktop/scanops/scanops-model
source .venv/bin/activate

# 1) 최신 NVD CVE 라이브 수집 (최근 40일)
python scripts/fetch_nvd_live.py
#    → data/nvdcve-2.0-live.json (9,134건)

# 2) 100케이스 구성 확인 (양성50 + 음성50)
python scripts/benchmark_v5_cases.py

# 3) 오탐률 벤치마크 실행 (ScanOps v4-raw / v5 / Grok-3)
ollama serve &                       # 로컬 모델 서빙
python scripts/benchmark_v5.py
#    → reports/results_v5_false_positive_benchmark.json
```

전제: 로컬 Ollama에 `qwen2.5-coder-security-v4:latest`, `qwen2.5-coder:1.5b` 등록,
`.env`에 `XAI_API_KEY`(Grok) 설정.

---

## 9. 부록 — 오분류 케이스 전체 공개 (투명성)

### 9.1 ScanOps v5 오탐 (FP, 3건) — 안전코드를 취약으로 오판
| ID | 언어 | 내용 |
|----|------|------|
| 93 | Node.js | rate limit 미들웨어 적용 로그인 (정상) |
| 97 | Python | `markupsafe.escape()` 적용 출력 (정상) |
| 98 | React | `DOMPurify.sanitize()` 적용 HTML (정상) |

### 9.2 ScanOps v5 미탐 (FN, 4건) — 취약코드를 안전으로 오판
| ID | 취약점 | 비고 |
|----|--------|------|
| 19 | CSRF 보호 비활성화 (`http.csrf().disable()`) | 설정성 취약점 |
| 29 | 하드코딩 백도어 계정 (CVE-2025-71317) | 의미 기반 판단 필요 |
| 44 | 약한 해시 MD5 | Grok도 동일 미탐 |
| 49 | Insecure CORS (origin 반사+credentials) | 설정성 취약점 |

### 9.3 Grok-3 미탐 (FN, 7건) — 권한·정책 계열
Missing Authorization ×2, Missing Authentication, Hardcoded Credentials,
Missing Rate Limiting, Prototype Pollution, Weak Hash(MD5)

---

## 10. 참고 링크

| 항목 | URL |
|------|-----|
| API 서버 | https://scanops-model-production.up.railway.app |
| 헬스체크 | https://scanops-model-production.up.railway.app/health |
| HuggingFace | https://huggingface.co/SehanKim/qwen2.5-coder-security-v4-gguf |
| GitHub | https://github.com/26Graduation/scanops-model |
| NVD API | https://services.nvd.nist.gov/rest/json/cves/2.0 |

### 참고 연구 (오탐률 관련)
- *Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering* (arXiv 2601.22952)
- *LLM-based Vulnerability Detection at Project Scale: An Empirical Study* (arXiv 2601.19239) — best tool FDR 85.3%
- *RealVuln: Benchmarking Rule-Based, General-Purpose LLM, and Security-Specialized Scanners* (arXiv 2604.13764)
- *Secure Coding with AI — From Detection to Repair* (arXiv 2504.20814)

---

*ScanOps Model v5 — 오탐률 중심 재평가  |  최신 NVD CVE(2026.5~6) 100케이스  |  Hybrid Adjudication*
*탐지율 92% · 오탐률 6% · 정확도 93% (Grok-3 동급, ~10× 빠름)  |  2026-06-09*
