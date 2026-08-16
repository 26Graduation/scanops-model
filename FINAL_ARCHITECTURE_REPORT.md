# ScanOps — 최종 아키텍처·측정 보고서

> 작성 2026-08-17. 이 문서의 **모든 성능 문장에는 (수치, 파일, 절)** 이 붙는다.
> 판정은 각 세션에서 **사전 등록한 기준** 그대로 적는다.

---

## §0 Executive Summary

1. **만든 것**: 파인튜닝 LLM 단독 탐지(Qwen3.5-9B QLoRA) + 자체 정규식 graph 폴백 +
   Joern v4 데이터흐름 **근거(evidence) 수집** + 외부 호출 0 온프레미스 배포 패키지.
2. **측정한 것**: 내부 test AUC/F1은 `rebuild/out/test_report.json`,
   외부 벤치는 CleanVul·PrimeVul(§3), Joern v4 단독 precision은
   CleanVul 240건 **0.5909** (`joern_v4_eval_sample.json`, JOERN_HYBRID_REPORT_V4.md §4)와
   OWASP taint 전용 110건 **0.5172** (`owasp_joern_v4_final_metrics.json`, §3-2).
3. **죽인 것**: LLM Critic 노선 — CTX-1(2026-08-15) · V3(08-16) · V4(08-17) 세 번 모두
   사전 등록 게이트에서 탈락. 마지막에는 **외부 상용 모델과 베이스 모델까지 같은 답**을 냈다(§4).
4. **왜 죽었나**: 질문의 근거가 입력에 없었다 — sanitizer 패치 줄이 Joern 슬라이스에 등장하는
   비율 **4.8%**, 쌍의 **38%** 는 vuln/safe 슬라이스가 글자까지 동일(§4).
5. **남은 것**: Joern은 판정에서 빠지고 **evidence 전용**으로 남았다(§1). 온프레미스 스택은
   실제로 기동해 데모 응답을 받았다(§5·§6). **아직 목표(precision 0.70)에 도달한 arm은 없다**(§3).

---

## §1 아키텍처

### SaaS 경로
```mermaid
flowchart LR
  U[코드/PR] --> B[백엔드 Spring]
  B -->|analyze| M[model-api api_rebuild]
  M -->|판정 관여| L[LLM Qwen3.5-9B QLoRA<br/>RunPod serverless]
  L --> J{detected?}
  J -- yes --> V[vuln]
  J -- no --> G[자체 graph]
  G -->|판정 관여 - 폴백| V
  G -->|그 외| S[safe]
  JO[Joern v4 워커] -.evidence 전용.-> V
  JO -.evidence 전용.-> S
  Q[(Qdrant CVE)] -.설명 전용.-> V
```

### 온프레미스 경로 (외부 호출 0)
```mermaid
flowchart LR
  U[코드] --> B2[backend :8080]
  B2 --> M2[model-api :8100]
  M2 -->|판정 관여| L2[llama-server :8080<br/>GGUF 로컬]
  M2 -.evidence 전용.-> J2[joern-worker :8200<br/>image :final]
  M2 --> P[(postgres)]
  subgraph 선택
    Z[zap] ; QD[(qdrant)]
  end
```

> **화살표 표기**: "판정 관여"는 `detected` 값을 바꿀 수 있는 경로,
> "evidence 전용"은 응답에 근거만 싣고 판정을 바꾸지 않는 경로다.
> Joern이 evidence 전용인 근거는 §3-1·§3-2의 precision 측정이다.

---

## §2 실험 연대기

각 행은 **질문 / 사전등록 기준 / 결과 / 판정 / 배운 것**이다. 실패도 같은 크기로 적는다.

| # | 실험 | 질문 | 사전등록 기준 | 결과 | 판정 | 배운 것 | 파일 |
|---|---|---|---|---|---|---|---|
| 1 | **V3 자율실행** | 여러 MUST 개선안이 듣는가 | 각 MUST별 사전등록 | MUST 전부 실패, F1 지표 무효 | 기각 | self-consistency만 유효 | `V3_RUN_SPEC` |
| 2 | **CTX-1 문맥주입** | 같은 파일 문맥을 주면 나아지는가 | ①식별자 포함률 ≥60% ②쌍내부 이동 > 전체이동 | 포함률 **17.1%**, 0.198 vs 0.550 | **KILL** | 문맥에 정보가 없었다. AUC보다 **정보 유입을 먼저 재라** | `CTX_RESULTS.md` |
| 3 | **ABLATION** | 자체 graph가 하이브리드에 기여하는가 | ΔF1 CI가 0을 배제 | ΔF1 −0.0014, CI 0 포함. unknown 91.6% | 기여 없음 | graph는 **거의 답을 안 한다** | `ABLATION_RESULTS.md` |
| 4 | **Joern v1/v2** | Joern taint가 graph보다 나은가 | precision CI하한 ≥0.80(TRUST) / 점추정 ≥0.60(SIGNAL) | 전건 1,878건 precision **0.5068** CI [0.4715, **0.5434**] | **JOERN-NO-BETTER** | CI 상한이 0.60에 미달 = 통계적 배제. 규칙 v2로 과탐 절반 줄여도 precision 불변 | `JOERN_HYBRID_REPORT.md` §4-5 |
| 5 | **Joern v3 + Critic** | 흐름 슬라이스를 LLM에 주면 sanitizer를 가리는가 | T1 마진 ≥0.15, T2 ≥0.60, T3 성립 | YES **0건**, T1 마진 **0.000**, T2 0.8265 | **CRITIC-KILL** + **V3-FAIL** | T2는 통과했으나 T1 마진 0 | `JOERN_HYBRID_REPORT_V3.md` |
| 6 | **Joern v4 결함수정** | self/this 제외·sanitizer applies_to로 나아지는가 | precision 점추정 ≥0.70 | self/this source **35/98 → 0/89**, precision 0.5652→**0.5909** | **V4-FAIL** | 결함은 고쳐졌으나 다른 흐름이 자리를 채운다 | `JOERN_HYBRID_REPORT_V4.md` §2 |
| 7 | **전략 A (외부 모델)** | 더 강한 모델이면 되는가 | 마진 ≥0.15, YES ≥5, UNP <0.20 | UNPARSED **0%**, YES **0**, 마진 **0.000** | 미통과 | **모델 탓 근거가 사라졌다** | `critic_v4_A_external_metrics.json` |
| 8 | **전략 E (union 슬라이스)** | 순환 제거하면 되는가 | 위와 동일 | 흐름 1→3.9개로 넓혔으나 sanitizer 포함률 **4.8% 불변**, YES 0 | 미통과 | 넓히는 것으로는 해결 안 됨 | `critic_v4_E_union_external_metrics.json` |
| 9 | **전략 D (베이스 모델)** | 어댑터 과적합인가 | 위와 동일 | UNPARSED 0%, YES **0**, 마진 0.000 | 미통과 | 형식은 어댑터 문제가 맞으나(v1 27.6% vs 베이스 0%) **판정은 안 바뀜** | `critic_v4_D_base_metrics.json` |
| 10 | **OWASP taint 전용** (오늘) | taint 계열만 보면 Joern이 나은가 | 사전등록: precision/recall/FPR/F1 + 자명 기준선 | precision **0.5172** CI [0.4023, 0.6207] | 가설 **미지지** | taint 전용이라고 나아지지 않는다 | `owasp_joern_v4_final_metrics.json` |

---

## §3 성능표

### §3-1 CleanVul_v2 (외부 벤치, 실제 커밋 유래) — 층화 240건

| arm | precision | 95% CI | recall | FPR | F1 |
|---|---|---|---|---|---|
| **all-vuln (자명 기준선)** | 0.5000 | [0.4333, 0.5625] | 1.0000 | 1.0000 | **0.6667** |
| LLM only | 0.5872 | [0.4954, 0.6789] | 0.5333 | 0.3750 | 0.5590 |
| **LLM + 자체graph (현재 채택)** | 0.5909 | [0.5091, 0.6909] | 0.5417 | 0.3750 | 0.5652 |
| Joern v3 단독 | 0.5652 | [0.4130, 0.6957] | 0.2167 | 0.1667 | 0.3133 |
| **Joern v4 단독** | **0.5909** | [0.4318, 0.7273] | 0.2167 | 0.1500 | 0.3171 |
| v4 + Critic | 0.5909 | [0.5076, 0.6742] | 0.6500 | 0.4500 | 0.6190 |

출처: `rebuild/out/joern_v4_eval_sample.json`, JOERN_HYBRID_REPORT_V4.md §4.

> **어떤 arm도 자명 기준선 F1 0.6667을 넘지 못한다**(최고 0.6190).
> 이 벤치에서 **F1로 성능을 주장할 수 없다.** 대외 자료에는 AUC를 쓴다.

### §3-2 OWASP Benchmark holdout (합성 벤치, taint 계열 전용) — 110건

| arm | precision | 95% CI | recall | FPR | F1 |
|---|---|---|---|---|---|
| **all-vuln (자명 기준선)** | 0.5000 | [0.4091, 0.5909] | 1.0000 | 1.0000 | **0.6667** |
| **Joern v4 단독** | **0.5172** | [0.4023, 0.6207] | 0.8182 | 0.7636 | 0.6338 |

혼동행렬 TP=45 FP=42 FN=10 TN=13. 카테고리 분포: xss 76 / cmdi 10 / crypto 7 /
pathtraver 6 / hash 4 / weakrand 4 / sqli 3. 출처: `rebuild/out/owasp_joern_v4_final_metrics.json`.

**sanitizer 판정의 부분 성과**: `safe_sanitized` 23건 중 gold=safe가 13건(56.5%).
sanitizer 로직이 없었다면 전부 vuln이 되어 precision은 0.5000(=자명)이므로,
sanitizer가 **0.5000 → 0.5172** 만큼 기여했다.

> **주의 (반드시 함께 읽을 것)**
> - OWASP는 **합성 벤치**다. 자체 정규식 graph는 여기에 손튜닝된 이력이 있다.
> - **Joern v4 쿼리는 OWASP를 보고 만들지 않았다.** `taint_v4.sc`·`sanitizers.json`은
>   CleanVul 실패 사례에서만 도출됐다(커밋 이력 `49ce14d` 이전에 OWASP 참조 없음).
> - **이 표의 숫자를 §3-1(CleanVul)과 섞지 않는다.** 벤치 성격이 다르다.

> **가설 미지지**: "taint 계열만 보면 Joern이 낫다"는 기대가 있었으나,
> precision 0.5172는 CleanVul의 0.5909보다도 낮다. recall은 0.8182로 훨씬 높지만
> FPR이 0.7636이라 자명 기준선(FPR 1.0)에 가까워지는 방향이다.

---

## §4 CleanVul 벤치에 대한 발견 — 사실만

### §4-1 측정한 숫자 (Critic 대상 98건 / safe 측 48건, tune split)

| 측정 | 값 | 뜻 |
|---|---|---|
| sanitizer 성 패치의 **그 줄이 Joern 슬라이스에 등장** | **1/21 (4.8%)** | union으로 넓혀도 동일 |
| safe 측 패치가 **sanitizer 호출 추가가 아님** | **26/48 (54.2%)** | sink 교체·리팩터링·시그니처 축소 등 |
| 쌍의 vuln/safe 슬라이스가 **글자까지 동일** | **16/42 (38%)** | 같은 입력에 다른 답을 요구한 셈 |
| Critic이 고칠 수 있는 상한 (슬라이스에 sanitizer 토큰 존재 ∧ gold=safe) | **5/98 (5.1%)** | 완벽한 Critic이어도 이 이상 불가 |

출처: JOERN_HYBRID_REPORT_V4.md §3-2·§3-4.

### §4-2 대표 사례 `cvh_124`

패치는 **한 줄**이었다:
```diff
+            body = StringEscapeUtils.escapeHtml4andJS(body);
```
그런데 sink는 `mapper.readValue(body, PushEvent.class)` — **Jackson 역직렬화**다.
HTML 이스케이프는 역직렬화를 안전하게 만들지 않는다.

**세 모델이 독립적으로 같은 답(NO)을 냈고, 그중 둘은 이유까지 댔다**:
- 베이스 Qwen3.5-9B: "the `escapeHtml4andJS` function only sanitizes HTML/JS characters
  but does not validate or deserialize the JSON structure"
- 외부 Claude Haiku 4.5: 같은 취지
- v1 어댑터: NO (근거는 카테고리 문구 재생)

### §4-3 CleanVul이 무엇을 라벨링한 데이터인가 (Q1)

공식 출처: **arXiv:2411.17274**, *"CleanVul: Automatic Function-Level Vulnerability Detection
in Code Commits Using LLM Heuristics"* (초록 원문 확인, <https://arxiv.org/abs/2411.17274>).

초록에서 확인된 사실(인용):
> "the automatic and indiscriminate labeling of **all changes in vulnerability-fixing commits (VFCs)**
> as vulnerability-related… not all changes in a commit aimed at fixing vulnerabilities pertain to
> security threats; many are routine updates like bug fixes or test improvements"

> "the first methodology that uses the Large Language Model (LLM) with a heuristic enhancement to
> **automatically identify vulnerability-fixing changes from VFCs**, achieving an F1-score of 0.82"

> "CleanVul, a high-quality dataset comprising 8,198 functions… demonstrating **Correctness (90.6%)**"

**따라서**: CleanVul의 라벨은 "**이 변경이 취약점을 고치는 변경인가**"를 LLM 휴리스틱(VulSifter,
그 과제에서 F1 0.82)으로 판정한 결과다. "**이 sink가 이제 안전한가**"를 정적 분석으로 판정한 것이 아니다.

**이 벤치가 무엇을 재는지**:
CleanVul은 **함수 단위 취약점 존재 여부**를 재기에는 적합하다(Correctness 90.6%).
그러나 **"이 데이터흐름이 sanitize 되었는가"를 묻는 질문**에는 부분적으로만 맞는다 —
취약점 수정은 sanitizer 추가만이 아니라 **sink 교체·구조 변경**으로도 이뤄지고,
우리 측정에서 그런 유형이 54.2%였기 때문이다.

> **라벨이 틀렸다는 주장이 아니다.** 우리가 던진 질문("SANITIZED YES/NO")이
> 라벨이 담은 의미의 **일부만** 덮는다는 뜻이다.
> 이것이 §2 #5·#7·#8·#9에서 네 번 연속 YES 0건이 나온 구조적 이유다.

### §4-4 자기 정정

JOERN_HYBRID_REPORT_V3.md는 T2=0.8265를 근거로 "정보 전달은 성공했다"고 적었다.
**이 문장은 2026-08-17에 철회됐다.** T2는 "바뀐 줄의 **식별자**가 슬라이스 텍스트에 있는가"를
셌는데, `self`·`kwargs`·`results` 같은 흔한 이름이면 자동 통과한다.
**판단 근거(sanitizer 호출 자체)로 다시 재면 4.8%다**(§4-1).

---

## §5 온프레미스 배포

파일: `scanops-infra/docker-compose.onprem.yml`, `.env.onprem.example`, `README_onprem.md`

### §5-1 실측 사양 (2026-08-17, macOS M3 / Docker Desktop 7.65GiB 할당)

| 서비스 | 메모리 실측 | cold start (healthy까지) | 비고 |
|---|---|---|---|
| `llama-server` (Qwen3.5-9B Q4_K_M) | **5.43 GiB** | 약 60초 | CPU 추론. GGUF 5.68GB를 볼륨 마운트 |
| `joern-worker` (:final) | **22.8 MiB** (유휴) | 약 20초 | 분석 중에는 JVM 힙까지 최대 8GB (`JOERN_MEM_LIMIT`) |
| `model-api` (api_rebuild) | **52.4 MiB** | 약 30초 | joern healthy 후 기동 |
| `postgres` | — | 약 10초 | 데모에서는 미기동(§9) |

**권장 최소 사양**: RAM 16GB(LLM 5.5GB + Joern 힙 4~8GB + OS), 디스크 20GB(이미지 + GGUF).
측정 환경의 Docker 할당은 7.65GiB였고, **이 상태로 세 서비스가 동시에 healthy** 했다.

### §5-2 외부 호출 차단

`.env.onprem.example`에서 다음을 **전부 빈 값**으로 둔다:
`RUNPOD_ENDPOINT_ID`, `RUNPOD_API_KEY`, `OPENAI_API_KEY`, `CLAUDE_API_KEY`, `GEMINI_API_KEY`,
`ANTHROPIC_API_KEY`, `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, `GITHUB_TOKEN`.

- `RUNPOD_ENDPOINT_ID`가 비면 `llm_client.use_runpod()`가 False가 되어 `LLAMA_SERVER_URL`로 폴백한다
  (`scanops/core/llm_client.py:30-36`).
- 백엔드 `application.yml`에서 확인된 **외부 참조 1건**: OAuth `redirect-uri` 기본값이
  `https://scanops-backend-production.up.railway.app/...` 이다. `.env.onprem`에서
  `GITHUB_OAUTH_REDIRECT_URI=http://localhost:8080/...`로 덮는다.
  **다만 OAuth 로그인 자체는 github.com에 접속해야 동작한다** — 온프레미스에서 GitHub 로그인을
  쓰려면 외부 접속이 필요하다. 에어갭에서는 사내 IdP/로컬 계정으로 대체해야 한다(§7).

### §5-3 기동 중 발견해 고친 결함 2건 (오늘)

| # | 증상 | 원인 | 수정 |
|---|---|---|---|
| 1 | `model-api`가 재시작 루프 | compose가 미설정 변수를 **빈 문자열**로 넘기는데 `hybrid._load_tuned`가 `float("")` 실행 | 빈 문자열/파싱 실패를 폴백으로 (`ac562d0`) |
| 2 | 모든 Joern 요청이 `unknown` | `tmpfs: /tmp`가 **noexec**라 Joern이 zstd 네이티브 바이너리를 실행 못 함 (`"the configured temp directory (/tmp) is mounted with noexec flag"`) | `/tmp:size=4g,exec` |

두 결함 모두 **실제로 띄워보지 않았으면 발견되지 않았다.** `config` 통과만으로는 잡히지 않는다.

---

## §6 데모 응답 3건 (실행 원본, 고치지 않음)

**실행 조건**: 온프레미스 스택, `docker compose -p scanops-onprem-demo --profile llm`.
전문은 `scanops-infra/demo/response_{a,b,c}.json`, 해석은 `scanops-infra/demo/NOTES.md`.

### ⚠️ 이 데모의 LLM은 프로덕션 모델이 아니다

| | 프로덕션(SaaS) | **이 데모** |
|---|---|---|
| 모델 | `scanops-rebuild-9b-q4km.gguf` (Qwen3.5-9B **QLoRA**) | **베이스 `Qwen3.5-9B-Q4_K_M`** |
| 이유 | RunPod 볼륨 | **v1 어댑터 GGUF가 로컬에 없다** (로컬은 7B LoRA뿐) |

### 결과

| 샘플 | detected | vulnerability | source | status | elapsed |
|---|---|---|---|---|---|
| (a) Java SQLi (문자열 연결→executeQuery) | **false** | NONE | llm | DONE | 77.4s |
| (b) Python cmdi (request.args→os.system) | **false** | NONE | llm | DONE | 142.4s |
| (c) Java 안전 (PreparedStatement.setString) | **false** | NONE | llm | DONE | 174.4s |

세 건 모두 `joern_evidence = {"joern_verdict":"unknown","advisory_only":true}`.

### 미탐의 원인 — 측정으로 확인

llama-server 원문 출력을 직접 받아봤다:
```
'<think>\nThinking Process:\n\n1.  **Analyze the Request:** ...'
```
베이스 모델은 `<think>`부터 낸다. `_detect`는 `n_predict=200`으로 호출하므로
**사고에 예산이 다 쓰여 4줄 서식에 도달하지 못한다** → 파싱 실패 → `NONE`.
파인튜닝 어댑터는 정확히 그 4줄 서식을 내도록 학습된 모델이다.

> **따라서 이 미탐은 "다른 모델을 끼운 결과"이지 파이프라인 결함이 아니다.**
> 다만 그것을 **측정으로 확인했을 뿐이고, 어댑터를 끼운 데모는 오늘 확보하지 못했다**(§9).
> `joern_evidence`가 빈 것은 §5-3의 noexec 결함 때문이며, **수정 후 재검증에서는
> 같은 SQLi 스니펫에 대해 `verdict=vuln`, `categories=['sqli']`, 4스텝 path가 나왔다**
> (`demo/NOTES.md` 마지막 절).

### 확인된 것

미탐이더라도 **응답 계약은 설계대로** 나왔다:
`source="llm"`, `status="DONE"`, `joern_evidence.advisory_only=true`(판정 미개입),
`evidence`·`score` 필드 존재. 백엔드 `ScanopsModelClient` 계약과 호환된다.

---

## §7 한계와 다음 단계 (근거 순)

### 7-1 지금 상태에서 말할 수 있는 것 / 없는 것

| 말할 수 있다 | 말할 수 없다 |
|---|---|
| 내부 test split에서 F1 80.5 (`rebuild/out/test_report.json`) | 그 숫자가 외부 데이터에서 재현된다 |
| 외부 CleanVul 240건에서 LLM+graph arm precision 0.5909 (§3-1) | precision 0.70(사업계획서 "오탐 1/3") 달성 |
| Joern v4가 taint 흐름과 sanitizer 적중을 **근거로** 제시한다 (§6 재검증) | Joern이 판정 정확도를 올린다 (§3-1·§3-2 둘 다 미달) |
| 외부 호출 0 스택이 실제로 기동한다 (§5-1 실측) | 에어갭에서 GitHub OAuth 로그인이 된다 (§5-2) |

### 7-2 다음 단계 — 근거가 강한 순

1. **Critic 노선 종료 유지.** 상한이 5.1%로 측정됐다(§4-1). 재개하려면 먼저
   **"패치가 흐름 안에 있는 벤치"** 를 만들어야 한다 — CleanVul에서 그 조건을 만족하는
   쌍만 추리면 소수(4.8%)라 새 데이터가 필요하다.
2. **Joern은 evidence 전용으로 고정.** 판정 개입은 두 벤치 모두에서 미달이다.
   evidence의 값어치는 §6 재검증처럼 "왜 그렇게 봤는지"를 보여주는 데 있다.
3. **모델 쪽**: self-consistency(V3에서 유일하게 유효했던 것, `V3_RUN_SPEC`)의
   비용/이득 재측정. 오늘 세션에서는 다루지 않았다.
4. **원가 실측**: 이번 세션 RunPod 소진 $0(GPU 호출 0). 온프레미스는 하드웨어 원가만.
   SaaS 원가는 별도 측정이 필요하다.

### 7-3 미완 (§9와 중복 없이)

- v1 어댑터 GGUF로의 데모 — 로컬에 파일이 없다.
- 백엔드(Spring) 컨테이너 기동 — 시간상 미실행(§9).
- 전건 1,878건 v4 확장 — 사전등록 `V4-FAIL`이라 **의도적으로** 안 함.

---

## §8 사업계획서 정정 목록 (누적, 최신)

| # | 계획서 표현 | 실측 | 상태 |
|---|---|---|---|
| 1 | "오탐률 1/3 (precision ~0.70+)" | CleanVul 240건 최고 arm precision **0.5909** (§3-1), OWASP **0.5172** (§3-2) | **미달** |
| 2 | "F1 80.5" | 내부 test split 기준. **외부 벤치에서는 어떤 arm도 자명 기준선 F1 0.6667을 못 넘음** | **조건 명시 필요** |
| 3 | "지식그래프가 오탐을 걸러낸다" | ABLATION ΔF1 −0.0014, CI 0 포함, unknown 91.6% | **기여 없음** |
| 4 | "Joern CPG 하이브리드로 정밀도 향상" | v1~v4 전부 사전등록 게이트 미달 (§2 #4·#6·#10) | **미달, evidence 전용으로 축소** |
| 5 | "LLM이 흐름을 검증한다(Critic)" | 세 번 KILL. 상한 5.1% (§4-1) | **종료** |
| 6 | "온프레미스 완전 격리" | 스택 기동 확인(§5-1). 단 **GitHub OAuth는 외부 접속 필요**(§5-2) | **조건부 사실** |

> 대외 자료에는 **AUC**를 쓰고, F1을 쓸 때는 **자명 기준선(all-vuln F1 0.6667)** 을 함께 적는다.

---

## §9 용어 사전

| 용어 | 뜻 |
|---|---|
| **자명 기준선(trivial baseline)** | "전부 취약"이라고 답하는 분류기. 1:1 균형 데이터에서 F1 0.6667 |
| **precision / recall / FPR** | 정밀도 = 취약 판정 중 실제 취약 비율 / 재현율 = 실제 취약 중 잡은 비율 / 오경보율 = 안전한 것 중 취약이라 한 비율 |
| **taint flow** | 사용자 입력(source)이 위험 지점(sink)까지 흐르는 데이터 경로 |
| **sanitizer** | 그 흐름 중간에서 값을 검증·이스케이프·파라미터화하는 호출 |
| **CPG** | Code Property Graph. Joern이 만드는 코드 표현 |
| **사전 등록(pre-registration)** | 측정 **전에** 성공/실패 기준을 문서에 적고, 결과를 본 뒤 바꾸지 않는 규율 |
| **evidence 전용** | 응답에 근거만 싣고 `detected` 값을 바꾸지 않는 경로. `advisory_only: true`로 표시 |
| **CRITIC-KILL / V3-FAIL / V4-FAIL** | 각 세션에서 사전 등록한 게이트를 통과하지 못했다는 판정 이름 |

---

## §10 재현 명령어

```bash
# 온프레미스 기동 (프로젝트명 격리 필수 — 기존 컨테이너와 섞이지 않게)
cd scanops-infra
cp .env.onprem.example .env.onprem     # GGUF_DIR 를 실제 경로로
docker compose -p scanops-onprem-demo -f docker-compose.onprem.yml \
  --env-file .env.onprem --profile llm up -d joern-worker llama-server model-api

# 데모
curl -X POST localhost:8100/analyze -H "Content-Type: application/json" \
  -H "X-API-Key: onprem-local-key" -d @demo/a_java_sqli.json

# 정리 (프로젝트명 반드시 지정)
docker compose -p scanops-onprem-demo -f docker-compose.onprem.yml down -v

# 벤치 재현 (scanops-model)
python3 joern/bench_owasp_final.py                  # OWASP taint 110건
python3 joern/bench_joern_v4.py sample              # CleanVul 240건
python3 joern/eval_v4.py sample
./joern/setup_local.sh status                       # 로컬 macOS astgen 링크
```

---

## §11 결정 로그 (세션별 원문)

| 세션 | 파일 | 결정 로그 |
|---|---|---|
| Joern 하이브리드 v1/v2 | `JOERN_HYBRID_REPORT.md` | §8 |
| sanitizer v3 + Critic | `JOERN_HYBRID_REPORT_V3.md` | §8 |
| v4 + 전략 A/D/E | `JOERN_HYBRID_REPORT_V4.md` | §8 (D-0 ~ D-5) |
| CTX-1 문맥주입 | `rebuild/out/CTX_RESULTS.md` | §6·§7 |
| ABLATION | `rebuild/out/ABLATION_RESULTS.md` | §0·§8 |
