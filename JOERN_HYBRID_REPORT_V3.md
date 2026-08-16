# ScanOps — Joern v3 (sanitizer-aware) + Targeted LLM Critic

> 어젯밤(`JOERN_HYBRID_REPORT.md`) 결론: **Joern taint reachability 만으로는 sanitizer 유무를
> 못 가려 precision 0.5068 (CI [0.4715, 0.5434])** → 판정 `JOERN-NO-BETTER`.
> 오늘 가설: **정확한 데이터 흐름 슬라이스만 LLM 에 주면** sanitizer 유무를 가릴 수 있다.

---

## §0 STATUS

**최종 갱신: 2026-08-16 22:35 KST**

| Phase | 상태 | 커밋 |
|---|---|---|
| Phase 0 어젯밤 결과 확정 + 환경 | ✅ 완료 (§1) | — |
| Phase 0-e **Docker push** | ✅ **로그인 성공 (어젯밤 실패 지점 해결)** / 🔄 이미지 빌드 진행 중 | — |
| Phase 1 sanitizer-aware 쿼리 v3 | ✅ 코드 완료 + 스모크 통과 / 🔄 배치 실행 중 | `a5de161` `084798c` |
| Phase 2 LLM Critic | ✅ 모듈·파싱 단위테스트 6/6 / ⏳ tune 게이트 대기 | — |
| Phase 3 v3 파이프라인 벤치 | ⏳ 대기 | — |
| Phase 4 hybrid.py 갱신 | ⏳ 대기 | — |
| Phase 5 문서 | 🔄 작성 중 | — |
| Phase 6 마무리 | ⏳ 대기 | — |

**RunPod 잔액**: 세션 시작 (22:28) **$28.3058024938**, `currentSpendPerHr=$0.005`, pods 0.
상한 = min(28.31 − 5, 10) = **$10.00**.

---

## §3-0 사전 등록 (측정 전 확정 — 결과 본 뒤 변경 금지)

> 기록 시각 **2026-08-16 22:35 KST**. 이 시점에 Critic 은 **단 한 건도 실행하지 않았다.**
> v3 배치는 실행 중이나 게이트 지표는 아직 계산하지 않았다.

### Phase 2 — Critic tune 게이트

측정 대상: `out/joern_v3_raw_cleanvul_v2_tune.jsonl` 에서 `joern_verdict=="vuln"` 인 케이스 전부.
0건이면 `CRITIC-KILL(대상 없음)`.

| 지표 | 정의 |
|---|---|
| **T1** Critic 정확도 | (YES∧gold_safe + NO∧gold_vuln) / (YES+NO). **UNPARSED 제외**하고 비율 별도 기록. 자명 기준선 "항상 NO" 정확도 병기 |
| **T2** CTX 조건① | path 안에 그 쌍의 패치 diff 식별자가 포함된 비율 **≥ 0.60**. 대상 = T1 대상 중 쌍 상대편이 tune 에 있는 케이스 |
| **T3** CTX 조건② | **양쪽(vuln/safe) 모두 v3 vuln 이고 path 가 있는 쌍**만 대상. 쌍 내부 YES 확률 차이 > 전체 평균 이동. **대상 쌍 < 10 이면 `UNMEASURED`(PASS 아님)** |

| 판정 | 조건 | 처리 |
|---|---|---|
| **CRITIC-GO** | T1 ≥ 자명기준선 + 0.15 **AND** T2 ≥ 0.60 **AND** T3 성립 | report 에 적용 |
| **CRITIC-WEAK** | T1 ≥ 자명기준선 + 0.15 인데 T2 미달 또는 T3 미달/UNMEASURED | 적용하되 "근거 약함" — safe 덮어쓰기 금지, confidence 하향만 |
| **CRITIC-KILL** | T1 < 자명기준선 + 0.15 (또는 대상 0건) | report 미적용, Joern v3 단독 |

### Phase 3 — v3 파이프라인 게이트 (report 240건)

| 판정 | 조건 | 처리 |
|---|---|---|
| **V3-SUCCESS** | precision CI 하한 ≥ 0.70 **AND** recall ≥ 어젯밤 recall − 0.05 | 전건 1,878건 확장 |
| **V3-PARTIAL** | precision 점추정 ≥ 0.70 인데 recall 손실 > 0.05 | 확장하되 트레이드오프 명시 |
| **V3-FAIL** | precision 점추정 < 0.70 | 확장 안 함. Critic 오판 5건 + Joern v3 오판 5건 원문·원인분류 |

**어젯밤 기준선** (`JOERN_HYBRID_REPORT.md` §4-5, 동일 240건 표본의 상위 집합인 전건 기준):
LLM+자체graph arm recall **0.4366**, FPR 0.2620, precision 0.6250, F1 0.5141.
Joern 단독 precision **0.5068** (CI [0.4715, 0.5434]).
자명 기준선 all-vuln F1 **0.6667** — **어떤 arm 도 이걸 넘은 적이 없다.**

---

## §1 어젯밤 결과 확정표 (Phase 0-a)

| 항목 | 값 | 출처 |
|---|---|---|
| 채택 policy | `JOERN-NO-BETTER` | `JOERN_HYBRID_REPORT.md` §4-5 |
| Joern precision (전건 1,878) | **0.5068**, 95% CI **[0.4715, 0.5434]** | §4-5 |
| joern_vuln 건수 | 738 | §4-5 |
| unknown 비율 | 0.0075 (parse_fail 14, timeout 0) | §4-5 |
| Java | n=890, vuln 390, prec 0.5128, CI [0.4615, 0.5615] | §4-5 |
| Python | n=576, vuln 265, prec 0.5019, CI [0.4415, 0.5623] | §4-5 |
| JavaScript | n=412, vuln 83, prec 0.4940, CI [0.3855, 0.6024] | §4-5 |
| 파싱 실패율 | 0.75% 전체 (Java 0.67 / Python 0.69 / JS 0.97) — **제외된 언어 없음** | §4-5 |
| wrap_level=1 로 살아난 건수 | 358 / 1,878 | §4-5 |
| DELTA / TAU 선정값 | δ=0.5, τ=0.4375 (tune 사전등록) | §4-2 |
| 자체 graph 대조 | 같은 표본에서 vuln 20건, precision 0.60 — ABLATION §2-0 과 일치 | §4-5 |
| RunPod 최종 잔액(어젯밤) | $28.3933024936, 소진 $0.0049 (standby 설정분, GPU 호출 0건) | §0 |

### Docker push 실패 원인과 오늘의 해결 (Phase 0-e)

| 항목 | 어젯밤 | 오늘 |
|---|---|---|
| 증상 | `docker login`/push 가 **credential helper 무응답으로 행** | — |
| 원인 | `~/.docker/config.json` 의 `credsStore: "desktop"` — Docker Desktop 헬퍼가 응답하지 않음 | — |
| 오늘 재시도 | — | `docker-credential-desktop get` 이 **10초 내 정상 응답** (rc=0, Username=`hansekim31`) |
| 조치 | — | 헬퍼가 돌려준 자격증명을 `--password-stdin` 으로 비대화형 로그인 → **Login Succeeded** |
| 결과 | push 불가 | **로그인 성공**, `hansekim31/scanops-joern-worker:v3` buildx(amd64) 빌드·push 진행 |

> 어젯밤 진단(“credential helper 무응답”)은 정확했고, 오늘은 같은 헬퍼가 응답했다.
> 즉 **환경 일시 장애**였지 설정 오류가 아니었다. config.json 은 백업해 두었고(§7) 수정하지 않았다.

### path 보유율 — 오늘 작업의 출발점 (Phase 0-b)

| 파일 | 건수 | joern_vuln | **path 보유** |
|---|---|---|---|
| `joern_raw_cleanvul_v2_tune.jsonl` | 468 | 217 | **0 (0.0%)** |
| `joern_raw_cleanvul_v2_sample.jsonl` | 240 | 94 | **0 (0.0%)** |
| `joern_raw_cleanvul_v2_report.jsonl` | 1,878 | 738 | **0 (0.0%)** |

**어젯밤 raw 에는 `path` 필드 자체가 없다.** 쿼리는 path 를 내보냈지만
`bench_joern.py:128-138` 이 `findings` 를 저장하지 않고 버렸다.
폴백 규칙(“보유율 < 50% → Phase 1에서 path 추출 먼저 고친다”)이 발동했고,
Phase 1 에서 드라이버가 path 를 저장하도록 고쳤다 → **v3 에서 vuln 의 path 보유율 100%** (§2).

### CTX-1 재도전 조건 (Phase 0-c)

`rebuild/out/CTX_RESULTS.md` §6 원문:

1. 문맥에 **패치 관련 식별자가 실제로 포함된 비율 ≥ 60%** (당시 **17.1%**) — 정보가 들어갔음을 먼저 증명
2. **쌍 내부 이동량 차이 > 이동량**의 역전 (당시 **0.198 vs 0.550**) — 편향이 아니라 신호임을 증명

> "이 두 개를 **AUC보다 먼저** 재는 것이 이번 실행에서 얻은 방법론적 소득이다."
> 오늘 Critic 은 이 두 조건을 tune 에서 먼저 통과해야 report 에 적용한다(§3-0 T2·T3).

### Critic LLM 경로 (Phase 0-d)

| 항목 | 값 | 출처 |
|---|---|---|
| 경로 | `scanops/core/llm_client.chat()` (chat 템플릿) | `scripts/api_rebuild.py:262` `_gen_meta` 와 동일 경로 |
| 근거 | "QLoRA는 판정 서식 특화지만 베이스 능력을 보존 — chat 템플릿 경로로 호출하면 일반 지시수행이 동작한다" | `api_rebuild.py:265-266` 주석 |
| `<think>` 처리 | 워커가 블록을 제거해 반환. Critic 은 방어적으로 한 번 더 제거 | `api_rebuild.py:283`, `llm_critic.strip_think` |
| 서빙 | `RUNPOD_ENDPOINT_ID` 설정 시 RunPod, 미설정 시 `LLAMA_SERVER_URL` | `llm_client.py:30-36` |


---

## §2 Sanitizer-aware Joern v3 — 설계와 실측

### 2-1. 핵심 설계 결정 — flow 원소는 "식"이지 "문장"이 아니다

첫 스모크에서 sanitizer 가 **하나도 안 걸렸다.** 원인을 보니 Joern 의 dataflow flow 원소는
추적되는 **식**이었다:

```
[source] line 1: String name
[intermediate] line 3: name
[intermediate] line 3: ps          ← ps.setString(1, name) 이 아니라 그냥 `ps`
[sink] line 4: ps.executeQuery()
```

`ps.setString(1, name)` 이라는 **문장 자체가 flow 원소로 등장하지 않는다.** 노드 코드만
대조하면 sanitizer 를 영영 못 본다. → **노드 자신 + 상위 AST 3단계**의 code 를 함께 검사하도록
`enclosingCodes()` 를 넣었다(`taint_v3.sc`). 흐름에 국한되므로 "파일 어딘가에 setString 이
있으면 안전" 같은 과광의 매칭은 되지 않는다.

수정 후 같은 스모크: `safe → safe_sanitized` (hit: `ps.setString(1, name)`), `vuln → vuln` (문자열 연결).

### 2-2. path 를 실제로 저장한다 (어젯밤 결함 해소)

어젯밤 raw 의 path 보유율은 **0%** 였다 — 쿼리는 내보냈는데 드라이버가 버렸다(§1).
v3 에서는 `{line, code, role}` 구조로 저장하고, **vuln 인데 path 가 비면 `unknown(no_path)`** 로
낮춘다.

| | 어젯밤 v2 | **오늘 v3** |
|---|---|---|
| vuln 의 path 보유율 | 0% | **100% (98/98)** |
| `no_path` 로 낮춰진 건수 | — | **0** |

### 2-3. sanitizer 표는 데이터로 분리

`joern/sanitizers.json` (시드 = `scanops/core/multi_graph.py:114` `SANITIZERS`).
언어별 44/41/40 패턴(JAVASRC/PYTHONSRC/JSSRC). `_any` 는 전 카테고리 공통.

> **지시서와의 편차(명시)**: 지시서는 "flow 의 **중간** 노드"만 검사하라고 했으나,
> 지시서가 든 예시(`PreparedStatement.set*`, `parameterized execute(sql, params)`)가 전부
> **sink 쪽** 신호다. 그래서 모든 노드를 검사하고 걸린 노드의 role 을 기록한다.

### 2-4. v2 → v3 전이 행렬 (tune 468건, 같은 case_id)

| v2 | → v3 | 건수 |
|---|---|---|
| safe | safe | 357 |
| **vuln** | **vuln** | **98** |
| **vuln** | **safe_sanitized** | **6** |
| unknown | unknown | 7 |

**손실 없이 깨끗하다** — v2 의 vuln 104건 중 6건만 sanitizer 로 걸러졌고, 나머지는 그대로다.

### 2-5. 단위 테스트 — 걸러진 6건이 옳게 걸러졌나

지시서는 "과탐 10건 + 진탐 10건"을 요구했으나, **v2-vuln 104건 전체를 v3 로 재실행**한
것이 같은 측정의 상위집합이므로 그것으로 대신한다(표본이 5배 크다).

| 결과 | 건수 |
|---|---|
| **과탐 제거 성공** (gold=safe 인데 v2 가 vuln 이라 했던 것) | **5** |
| **진탐 손실** (gold=vuln 인데 safe_sanitized 로 낮춤) | **1** |

진탐 손실(1) < 과탐 제거(5) 이므로 **사전 규칙상 패턴을 좁히지 않는다.**

다만 유일한 손실 `cvh_94|vuln` 은 시사적이다: 패턴 `new\s+URL\(` 이 **쌍의 양쪽 모두**에
걸렸다(`new URL(serviceCall)`). URL 을 파싱하는 것은 검증이 아니므로 이 패턴은
sanitizer 신호로서 판별력이 없다. → §12 에 후보로 남긴다.

### 2-6. v3 단독 성능 (tune) — sanitizer 만으로는 거의 안 움직인다

| | vuln 건수 | precision |
|---|---|---|
| v2 (어제) | 104 | 0.4904 |
| **v3 (오늘)** | **98** | **0.5102** |

| 언어 | n | vuln | precision | safe_sanitized | parse_fail |
|---|---|---|---|---|---|
| Java | 222 | 25 | 0.4800 | 2 | 1.4% |
| Python | 144 | 59 | 0.5593 | 4 | 1.4% |
| JavaScript | 102 | 14 | 0.3571 | 0 | 2.0% |

**세 언어 모두 parse_fail < 30%** → 제외된 언어 없음.
sanitizer 는 v2-vuln 의 **5.8%(6/104)** 에만 걸렸다. 즉 **v3 단독으로는 어제 문제가 해결되지
않는다.** 가설의 무게는 전적으로 Critic(§3)에 실린다.
