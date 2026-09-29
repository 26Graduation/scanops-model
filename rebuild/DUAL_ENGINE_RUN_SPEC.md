# DUAL-ENGINE — 사전 등록 사양 (2026-08-17 네 번째 무인 세션)

> **이 문서는 측정 결과를 보기 전에 커밋한다.** 판정선·표본·arm·폴백을 여기에 먼저 적고,
> 결과를 본 뒤에는 바꾸지 않는다. 바꾸면 §11 에 "바꿨다 + 이유"를 남긴다.
>
> 결정 로그: `rebuild/out/SESSION_DECISIONS_20260817D.md`
> 산출 디렉터리: `rebuild/data/repo_bench/`, `rebuild/out/`, `presentation/`

---

## §0 오늘의 질문과 한 줄 주장

**주장(검정 대상):** ScanOps 는 **PR 변경 맥락(`[DIFF]`)을 읽는 LLM + 레포 전체를 훑는
멀티파일 코드그래프** 의 듀얼 엔진이다.

이 주장을 측정으로 세운다. **안 나오면 안 나온 대로 쓴다.**
사용자가 미리 동의한 것: **레포 벤치 판정이 TIE/LOSE 면 그래프는 "보조 + 근거 표시"로 발표한다.**

우선순위(시간 부족 시 위부터 지킨다):
① Phase B 레포 벤치 ② Phase C `[DIFF]` 이식 ③ Phase D 발표 패키지 ④ Phase A 단건 헤드투헤드

---

## §1 Phase 0-a — 기존 점수 파일 (없는 것만 채점한다)

이미 있는 v1 / 외부 점수. **재채점하지 않는다.**

| 벤치 | 우리(v1) | 외부(Claude) | 파일 |
|---|---|---|---|
| 내부 test 1,197 | 있음 (AUC 0.9052 / F1 0.8051) | **있음** — `claude-sonnet-5` | `out/test_report.json`, `out/compare_claude_report.json` |
| PrimeVul 360(쌍 180) | 있음 | **있음** — `claude-sonnet-5` | `out/external_primevul_report.json`, `out/compare_claude_primevul_report.json` |
| CleanVul 11,580 | 있음 | **있음** — `claude-sonnet-5` | `out/external_cleanvul_report.json`, `out/compare_claude_cleanvul_report.json` |
| CleanVul_v2 report 2,706 | 있음 | 없음 | `out/external_cleanvul_v2_report.json` |
| CyberNative 154 | 있음 (AUC 0.9126) | **없음** | `out/oppoint_op_v1.json` |
| CVEfixes 157 | 있음 (AUC 0.8732) | **없음** | `out/oppoint_op_v1.json` |
| PR 쌍 400 (P0·P2, 위치 상쇄) | 있음 | **없음** | `out/dw_logprob_dw_P0.jsonl`, `out/dw_logprob_dw_cb{X,Y}_P2.jsonl` |
| 레포 벤치 3종 | **없음** | **없음** | (오늘 만든다) |

> **주의:** 기존 외부 점수는 전부 `claude-sonnet-5` 다. 오늘 새로 도는 것은 `claude-opus-5` 다(§2-a).
> **두 모델을 같은 칸에 넣지 않는다.** 표마다 모델 ID·호출일을 적는다.

---

## §2 Phase 0-b — 외부 모델 규약

### §2-a 모델 ID (API 로 확인, 2026-08-17)

`GET https://api.anthropic.com/v1/models` 응답 상위 = **`claude-opus-5`** (Claude Opus 5, created 2026-07-24).
오늘 새로 도는 외부 arm 은 전부 이 ID 를 쓴다. **표마다 `claude-opus-5` + 호출일 + 프롬프트 해시를 적는다.**

### §2-b PARITY 프롬프트 (기본 arm)

- 사용자 프롬프트 = `rebuild/build_external_bench.py` 의 `PROMPT_TMPL` **바이트 동일**
  (= `scripts/api_rebuild.py:174` 의 것과 같은 문자열).
- 시스템 프롬프트 = `rebuild/compare_claude_external.py` 의 `SYSTEM` **바이트 동일**.
- 코드 절단 **12,000자** (우리 `_MAX_CODE` 와 동일).
- 파서 = `rebuild/bench_common.py:parse` **그대로** (수정 금지).
- `max_tokens` = 400 (기존 외부 실행과 동일).
- **`thinking: {"type":"disabled"}`** — 우리 모델이 단일 패스 greedy 라서 조건을 맞춘다.

### §2-c 맞출 수 없는 조건 — **그대로 적는다**

**`temperature=0` 을 외부 모델에 적용할 수 없다.** Claude 5 계열은 `temperature`/`top_p`/`top_k`
를 받지 않고 400 을 돌려준다. 따라서 **temp 0 은 우리 쪽에만 적용된다.**
이 비대칭은 표 각주에 적고, "동일 조건"이라고 쓰지 않는다.

### §2-d STRONG 프롬프트 (외부에 유리한 조건)

시니어 AppSec CoT 를 허용하고(=`thinking` 기본값, adaptive), 시스템 프롬프트에
"단계적으로 추론한 뒤 **마지막에** 아래 4줄 서식으로만 결론을 낼 것"을 넣는다.
사용자 프롬프트(`PROMPT_TMPL`)는 **PARITY 와 바이트 동일**하게 유지한다 — 바뀌는 것은 시스템 프롬프트뿐.
`max_tokens` = 4,000 (사고 토큰이 서식을 자르지 않게).

> **STRONG 을 넣는 이유:** 이것이 없으면 "불리한 프롬프트를 줬다"는 반박을 막을 수 없다.
> 외부에 유리한 조건을 최소 하나는 준다.

### §2-e UNPARSED 처리

- 외부 응답이 `parse_fail` 이면 **별도 집계**한다. **safe 로 세지 않는다.**
- UNPARSED 비율 > 20% 이면 **서식 강조 문구 1회만** 추가해 재시도하고, 그 사실을 적는다.
- 재시도 후에도 > 20% 이면 그 arm 은 "측정 불가"로 적는다.

---

## §3 Phase 0-c — 지표와 판정선

### §3-a 지표

- recall / FPR / precision / F1 + **자명 기준선**(균형셋 all-vuln F1 0.6667; 레포 벤치는 §6-c 참조)
- **부트스트랩 95% CI 2,000회** (`rebuild/bootstrap_ci.py` 와 같은 절차)
- **AUC 는 우리만** — 외부는 연속 점수를 얻을 수 없다(logprob 미제공). 표에 `N/A (외부 점수 미제공)` 로 적는다.
- 쌍 지표: `acc_cb`(위치 상쇄 순위 정확도) · `pos_gap` · 동점률

### §3-b 우열 판정선 (사전 등록, 사후 변경 금지)

| 판정 | 조건 |
|---|---|
| **WIN** | 우리 F1 **CI 하한** > 상대 F1 **점추정** **AND** 우리 FPR 점추정이 더 낮다 |
| **TIE** | 두 F1 의 CI 가 겹친다 |
| **LOSE** | 상대 F1 CI 하한 > 우리 F1 점추정 |
| **N/A** | 둘 다 자명 기준선 미만 |

---

## §4 Phase 0-d — 외부 호출 우선순위와 예산

**예산: Anthropic 만 ≤ $15** (GPT 키 없음). 초과 시 **뒤에서부터 자른다.**

| # | arm | 비고 |
|---|---|---|
| ① | **Phase B 레포 파일 단위 PARITY** | 최우선 |
| ② | 내부 test 1,197 PARITY | 기존 sonnet-5 와 비교 가능 |
| ③ | PR 쌍 400 P2 PARITY (양방향 cbX/cbY) | |
| ④ | CyberNative 154 + CVEfixes 157 PARITY | |
| ⑤ | Phase B STRONG | |
| ⑥ | 내부 test STRONG | |

**20건 선행 실측으로 케이스당 비용을 추산한 뒤 시작한다.** Message Batches API(50% 할인)를 쓴다.

### §4-a RunPod 예산 — **$0 (사용 불가)**

RunPod serverless 엔드포인트 `ylzf0yaerkvqli` 는 2026-08-17 21:0x KST 조회 시
`workers: {idle:0, ready:0, throttled:2}` — **가용 GPU 0**. 실제 호출은 4분 대기 후 404 로 실패했다.
→ **우리 모델 채점은 로컬 llama.cpp(Metal, M3 16GB)** 로 돌린다.
이 경로는 온프레미스 프로덕션 경로와 같고(`FINAL_ARCHITECTURE_REPORT.md` §5),
서빙-오프라인 대조가 이미 있다(`OPPOINT_RESULTS.md` §2-0b, 판정 일치율 0.95).
**RunPod 지출은 $0 이 된다.** pod 도 만들지 않는다.

---

## §5 Phase 0-e — 각주(필수)

표마다 다음을 적는다.

1. **내부 test 는 CVEfixes 시간분할**이라 외부 모델이 사전학습에서 봤을 수 있다. **유리한 쪽은 외부.**
2. **레포 벤치 3종도 공개 취약 앱**이라 외부가 봤을 가능성이 크다. **이것도 유리한 쪽은 외부.**
3. 모든 균형셋 수치는 **50:50 가정**이다. 실제 PR 유병률은 더 낮고, 낮으면 precision 은 더 떨어진다.
4. `temperature=0` 비대칭(§2-c).

---

## §6 Phase B — 멀티파일 레포 벤치 (핵심)

### §6-a 대상 (순서 고정)

1. **JS/TS** — `juice-shop` (OWASP Juice Shop)
2. **Java** — `WebGoat`
3. **Python** — `pygoat` (문서화된 취약 앱). 정답표를 못 만들면 **PHP DVWA 로 대체**하고 사유를 적는다.

### §6-b 정답표 (스캔 결과를 보기 **전에** 커밋)

경로: `rebuild/data/repo_bench/{repo}_truth.jsonl`
한 건 = `{id, cwe, category, sink_file, sink_line, source_file, source_line, cross_file(bool), confidence, evidence_url, note}`

- `confidence`: **high** = 공식 목록/문서에 파일:라인이 있음 / **med** = 문서 + 소스 대조 / **low** = 추정
- **판정은 high+med 로만 한다. low 는 별도 행으로만 싣는다.**
- 정답표를 만들 수 없는 레포는 **뺀다**(사유 기록).

**최소 조건:** 합계 **≥ 40건**, `cross_file=true` **≥ 12건**.
미달이면 **"표본 부족"** 으로 표기하고 **표만 내고 GRAPH 판정은 하지 않는다.**

### §6-c arm (사전 등록)

| arm | 정의 |
|---|---|
| **S1 ScanOps-LLM** | 파일 단위 `/analyze` 상당(로컬 llama-server, v1 어댑터, greedy). 12,000자 초과 파일은 **함수 단위 분할**(방식 기록) |
| **S2 ScanOps-Full** | S1 ∪ `code_graph`(JS/TS 멀티파일) ∪ `multi_graph`/`java_graph` ∪ **Joern v4 프로젝트 단위 CPG**. **vuln 만 추가한다. safe/unknown 은 어떤 판정도 덮지 않는다** (`ABLATION_RESULTS.md` — safe 42.5% 오판) |
| **C1 Claude-File** | 파일 단위 PARITY(§2-b). 사용자가 파일을 붙여넣는 방식과 동일 |
| **C2 Claude-File-STRONG** | 예산이 남으면 (§2-d) |

**Claude 에 레포 전체를 주는 arm 은 만들지 않는다** — 컨텍스트·비용상 제품 사용 방식이 아니다(각주로 명시).

**OOM/시간 폴백(사전 정의):** JVM `-Xmx` = 가용 RAM 의 60%, 빌드 상한 **20분/레포**.
초과 시 **부분 그래프**로 폴백 — 엔드포인트/라우터 파일 + 그 import 폐쇄(깊이 2) 묶음별 CPG.
**폴백 여부·묶음 수를 기록한다.**

### §6-d 채점

**스캔 범위 (사전 선언, 세 arm 동일):**
juice-shop = `routes/**/*.ts` + `lib/**/*.ts` + `models/**/*.ts` + `server.ts` + `app.ts`
+ `frontend/src/app/**/*.ts` (`*.spec.ts` 제외). 빌드 산출물·테스트·`node_modules` 제외.
정답표 44건 중 **범위 밖 11건**(.yml/.tf/docker-compose 8, .sol 3)은
**두 arm 모두 자동 미탐**이므로 recall 분모에서 빼고 **건수를 표에 적는다**.
→ **recall 분모 = 33건**(전부 `.ts`), 그중 **cross_file 16건**.

**매칭 단위 = 파일.**
LLM arm(S1·C1)은 **라인을 내지 않는다** — 4줄 서식에 라인 번호가 없고, 제품도
`/analyze/batch` 에서 파일 단위 판정만 낸다. 따라서 **세 arm 전부 파일 단위로 통일한다.**
그래프·Joern 은 라인을 갖고 있으므로 `sink_line ±10` 적중 여부를 **부가 정보로만** 기록한다.
→ 이 규칙은 recall 을 낙관적으로 만든다(파일 어딘가에 취약점이 있으면 맞은 것으로 센다).
**세 arm 에 똑같이 적용되며, 표 각주에 이 사실을 적는다.**

**두 가지 recall 을 둘 다 싣는다:**
1. **위치만** — 정답의 `sink_file` 을 vuln 으로 판정했는가 (주지표)
2. **위치 + 카테고리** — 위 + 카테고리 일치 (`rebuild/data/repo_bench/category_map.json`)

- 지표: recall(전체 / **cross_file 만** / single_file 만), **파일당 오탐**(정답 파일이 아닌
  파일을 vuln 으로 판정한 수), precision, 스캔 시간·비용
- **주지표 = cross_file recall.** 그래프의 존재 이유가 거기 있다.

### §6-e 판정 (사전 등록, high+med 정답만 / 레포 합산 + 레포별)

| 판정 | 조건 |
|---|---|
| **GRAPH-WIN** | S2 cross_file recall ≥ C1 cross_file recall **+ 0.20** **AND** (S2 파일당 오탐 ≤ C1 **OR** S2 precision ≥ C1) |
| **GRAPH-TIE** | 차이 < 0.20 또는 CI 겹침 |
| **GRAPH-LOSE** | S2 < C1 |

같은 표에 **S2 − S1**(그래프 순기여)을 싣는다. 이것이 "그래프가 LLM 에 무엇을 더했나"의 직접 수치다.

**발표 문구 매핑 (사전 고정, 결과 보고 바꾸지 않는다):**

- `GRAPH-WIN` → **"멀티파일 taint 주력 탐지기 + LLM 단건 주력"**
- `GRAPH-TIE` / `GRAPH-LOSE` → **"보조 탐지 + 근거 표시"**

### §6-f 실패 분석

- S2 가 놓친 cross_file 정답 **전부** 원인 분류:
  source 미인식 / sink 미인식 / 파일 간 연결 실패 / 언어 미지원 / 파싱 실패 / OOM 폴백으로 잘림
- S2 오탐 **상위 10건**을 원문과 함께

---

## §7 Phase C — `[DIFF]` 마커 이식 (로컬, $0)

- `scripts/api_rebuild.py` 의 `analyze_pr` 에서, **`SCANOPS_PR_DIFF_MARKER=1` 일 때만**
  `rebuild/pr_diff_marker.py` 로 head content 에 언어별 주석 마커를 삽입한다.
- **미설정 시 프롬프트 바이트 동일.** `/analyze`·`/analyze/batch` 는 **무변경**.

**회귀 기준(전부 통과해야 기본 on):**

1. 내부 test 50건 `/analyze` 경로 **100% 일치**
2. 플래그 off 에서 `analyze_pr` **100% 일치**
3. patch 없음 / 삭제만 있는 hunk 경계 통과
4. 데모 2건(sanitizer 추가 / 취약 도입) on·off **4응답 저장**

**문서에 적을 문장(고정):**
> `CB-PARTIAL`(동점률 0.155 > 0.10) 게이트 미통과. CI 하한 +0.065 > 0 · 단건 회귀 없음 ·
> FPR-safe 0.065 근거로 **제품 판단**으로 기본 on. **되돌림 = 플래그.**

---

## §8 Phase A — 단건 헤드투헤드 (예산·시간 잔여분)

- 러너 `rebuild/headtohead.py` — append·재개·비용 기록, 동시성 8, 백오프, **예산 90% 에서 단계 완료 후 중단**
- 표 `rebuild/h2h_tables.py`
- 대상: 내부 test / PR 쌍(P0·P2, 위치 상쇄) / CyberNative / CVEfixes, v1 vs Claude(PARITY, 되면 STRONG)

---

## §9 폴백 (사전 정의)

| 상황 | 행동 |
|---|---|
| 정답표 40건 미달 | 표만, **판정 없음** |
| Joern 프로젝트 CPG OOM·20분 초과 | 부분 그래프 폴백 + 기록 |
| 레포 clone 실패 | NodeGoat / VulnerableApp 로 대체 |
| Python 취약 앱 정답표 불가 | PHP DVWA 로 대체 + 기록 |
| 외부 예산 초과 | 우선순위 하위 생략 + **"미측정"** 표기 |
| UNPARSED > 20% | 서식 강조 1회 재시도 |
| 이식 회귀 실패 | 플래그 **기본 off** |
| Claude 파일 12,000자 초과 | S1 과 **같은 분할 규칙** 적용 |
| RunPod 가용 GPU 0 | **로컬 llama.cpp** (§4-a) |
| 그 외 | **"미완(사유)"** |

---

## §10 서술 규칙 (이 세션 전체)

- 측정한 것만. 자명 기준선·CI·언어별을 병기.
- 금지어: **"완성", "증명", "유일", "압도", "멱살"**
- 외부 모델 **ID·호출일·프롬프트 해시**를 표마다.
- 그래프 불변 규칙: **graph/Joern 의 vuln 은 결과에 추가, safe/unknown 은 어떤 판정도 덮지 않는다.**
- **LLM Critic 없음.**
- `git add -A` 금지. 브랜치 `feat/dual-engine-bench`. main 무변경.

---

## §11 사후 변경 기록

**S-1 (측정 전, 정답표 작성 직후).** §6-d 의 매칭 단위를 "라인 ±10 / 같은 함수"에서
**"파일 단위"** 로 바꿨다. 이유: 우리 LLM 도 Claude 도 **라인 번호를 출력하지 않는다**
(4줄 서식에 없고, 제품 `/analyze/batch` 도 파일 단위 판정만 낸다). 라인 기준을 유지하면
LLM arm 두 개가 구조적으로 0이 되어 비교가 성립하지 않는다.
**세 arm 에 동일하게 적용**하고, recall 이 낙관적이 된다는 사실을 표 각주에 적는다.
**어떤 스캔도 돌리기 전에 바꿨다** (커밋 순서로 확인 가능).

**S-2 (측정 전).** §6-d 에 recall 을 두 가지(위치만 / 위치+카테고리)로 나눠 싣기로 했다.
이유: 정답표 카테고리는 juice-shop 챌린지 분류(예: "Broken Anti Automation")이고
우리·Claude 는 CWE 를 낸다. 카테고리 일치만 요구하면 **둘 다** 부당하게 낮아진다.
