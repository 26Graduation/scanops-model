# ScanOps 인계 프롬프트 — 다음 라운드

아래 전체를 새 대화 첫 메시지로 붙여넣는다. 작업 디렉터리: `/Users/kimsehan/Desktop/scanops/scanops-model`

> **이 문서 rev.2 (2026-08-22 재작성).** rev.1 은 `GRAPH_SPEC_RESULTS_R4.md` 의 §1(juice-shop
> 검정력)만 읽고 §5~§9(CVEfixes 파일럿·원인 규명·다음 라운드 권고)를 빠뜨린 채 작성됐고,
> **R4 가 이미 실패로 끝낸 실험(CVEfixes 레포 확대)을 다시 하라고 지시했다.** 그 오류를 바로잡은 판이다.
> rev.1 을 봤다면 §3-3(레포 수 확대) 지시는 **폐기**다.

---

너는 ScanOps(부산대 졸업과제 겸 B2B 보안 스캐너)의 모델·분석 엔지니어다.

**작업 시작 전에 이 순서로 읽어라.**
1. `CLAUDE.md` — 절대 규칙(추정 금지·사전등록·한 번에 한 변수·벤치 과적합 금지·측정 조건 병기·
   파일 삭제 금지·커버리지 축소 시 로그)
2. `rebuild/out/GRAPH_SPEC_RESULTS_R4.md` — **§1 만 읽지 말고 §5·§6·§8·§9 까지 전부 읽어라.**
   이번 라운드 지시는 그 §9 권고를 그대로 따른 것이다.
3. `GRAPH_RUN_SPEC.md` — 사전등록 사양. §12-3 지표 정의, §15-4 제약

이상하거나 결정이 필요한 지점이 나오면 **혼자 정하지 말고 근거와 함께 물어봐라.**

---

## 0. 이번 라운드 (R4 §9 권고 그대로)

> **V1 localization (L1) 을 별도 ablation 으로 구현하고, localization 정확도를 먼저 평가한다.**

R4 가 명시한 제약:
- L1 은 **별도 ablation** 이다. **R1 arm 자체를 변경하지 않는다.**
- 학습·평가·서빙의 4줄 템플릿을 건드리지 않는 **별도 2차 호출**로 구현한다.
- provenance 에 쓰기 **전에** localization 정확도를 먼저 평가한다
  (파일 적중 / 라인 strict / 라인 loose / CWE 일치 + **실패 4종 분리**).

---

## 1. 왜 L1 인가 — R4 §9 의 근거 3개

1. **§12-7 ④ / §15-5 C3 가 R2·R3·R4 세 라운드 연속 미달인데 원인이 그래프가 아니다.**
   v1 이 라인을 못 내서 provenance 가 파일 단위이고, v1 이 파일의 **115/257 = 44.8%** 를 찍고 있어
   그래프 적중이 구조적으로 항상 overlap 된다. **L1 없이는 이 조건을 영원히 답할 수 없다.**
2. **그래프(A) 쪽은 juice-shop 회수 상한이 0 이다**(R4 STEP 2). 룰을 더 써도 T층에서 올릴 게 없다.
3. **V2 재학습(C)은 시기가 아니다.** 외부 line-level 벤치가 18 정답 라인뿐이고 채점 정의도 미해결(F_C).

---

## 2. 하지 말 것 — 이미 측정으로 닫힌 길

### 2-1. CVEfixes 레포 수를 늘려 같은 파이프라인을 재측정 ❌

R4 STEP 7·8 이 이미 3개 레포로 했고 **구조적으로 0** 이 나왔다.

| 레포 | 정답 라인 | exact | 경보 |
|---|---:|---:|---:|
| fittr-flickr | 6 | 0 | 0 |
| maps-js-icoads | 4 | 0 | 0 |
| jquery-ui | 3 | 0 | 55 (전부 헛것) |

원인을 `probe_locations.sc` 로 CPG 를 직접 프로브해 규명했다(§6-2, 추론 아님):

- **F_A 구조적**: 정답 라인 **9/11 (81.8%)** 에 CALL 노드가 없다. `<operator>.assignment` /
  `assignmentPlus` / `addition` / 리터럴이라 **taint sink 로 표현될 수 없다.**
  → **룰을 더 써서 해결되는 문제가 아니다. sink 표현력 문제다.**
- **F_B 스펙 전이 실패**: `spec_G2_juice-shop.tsv` 는 Express/Angular 전용이라 jQuery `.html()` 룰이 없다.
  `jquery.ui.dialog.js:604` 는 CALL 도 있고 **flow=6** 인데 경보 0.
  → `GRAPH_RUN_SPEC.md` §5 는 원래 **"레포마다 LLM 이 스펙 생성"** 인데 그 파일럿은 juice-shop
  스펙을 그대로 전이했다. **설계대로 안 한 실험이다.**
- **F_C 표적 정의 불일치**: CVEfixes 정답 = "수정으로 사라진 줄", 예측 = "sink 호출 줄".
  R4 원문: *"완벽한 taint 분석기라도 31행을 보고하지 않는다"*.
  → 고치려면 채점을 `정답 라인 ±10 에 sink 가 있는가` → **`정답 라인이 보고된 경로(path) 안에 있는가`**
  로 바꿔야 하는데, 이는 **§12-3 지표 정의 변경 = 사전등록 사안**이다.

**표본을 100배로 늘려도 F_A·F_C 는 그대로다.** 검정력 문제가 아니다.

### 2-2. LLM 을 탐지기로 재학습 ❌ — 4번 실패, 원인 규명됨

2026-08-21~22 에 GPU **$43.6** 을 쓴 결과다.

| | 학습셋 | 결과 |
|---|---|---|
| v2 (파일 4k→16k) | 2,453건, vuln 라벨 56% 가 `NVD-CWE-noinfo` | AUC **0.5089**, argmax 100% safe |
| v3 (파일 16k, 데이터 3.7배·라벨 100% 정상) | 9,049건 | AUC **0.5098**, vuln 예측 8.6%, **학습 데이터에서도 NONE 출력** |

v3 는 eval loss 0.4021→0.3064 로 566스텝 단조 개선했는데 AUC 는 안 움직였다.
**loss 는 5줄 형식·CWE 이름·REASON 문구를 외운 것이지 판별을 배운 게 아니다.**

배제한 가설(전부 확인): 서빙 버그 아님(파드 PEFT·로컬 GGUF 동일), 어댑터 미적용 아님
(`/lora-adapters` 확인), 형식 붕괴 아님, 라벨 불균형 아님(46/54), 컨텍스트 부족 아님
(4k→16k 가시율 68→90% 인데 결과 동일).

**더 근본적으로 — v1 의 0.905 는 홈그라운드 점수다:**

| 벤치 | AUC | 길이만 쓴 기준선 | 쌍 순위 정확도 | 취약/안전 길이비 |
|---|---:|---:|---:|---|
| CVEfixes test | **0.9052** | 0.6470 | **0.9068** | 273 / 667 (2.4배) |
| PrimeVul (외부) | **0.5618** | 0.5177 | **0.4931** | 1597 / 1674 (1.05배) |
| CleanVul (외부) | **0.6165** | 0.5195 | **0.5558** | 897 / 990 (1.1배) |

출처: `rebuild/out/length_baseline_v1.json`, `pair_discrimination_v1.json`, `v1_logprob_*.jsonl`

v1 이 배운 건 "취약한가"가 아니라 **"CVEfixes fix 커밋의 before/after 중 어느 쪽인가"** 다.
PrimeVul 을 학습에 넣어도 0.5618 → 0.5802 로 안 오른다(`v3s42_logprob_*`).

### 2-3. LLM **sanitizer Critic** ❌ — 4번 죽였다 (⚠ R3 verifier 와 혼동 금지)

`HANDOFF_PROMPT.md` §2. CTX-1 → V3 → V4(A/D/E) 전부 사전등록 게이트 미달. 외부 Claude Haiku 4.5 와
베이스 Qwen3.5-9B 까지 YES 0건. **기여 상한 5.1%.**

**죽은 것은 "이 패치가 SANITIZED 됐나 YES/NO" 를 함수 쌍 슬라이스에 묻는 것**이다.
원인: sanitizer 패치 줄이 Joern 슬라이스에 등장하는 비율 4.8%, safe 패치의 54.2% 가 sanitizer
추가가 아님(sink 교체·리팩터링), 쌍의 38% 가 슬라이스까지 동일.

**⚠ 이것과 `graph_spec_critic_r3.py`(R3 verifier)는 완전히 다른 것이다. verifier 는 살아 있고
잘 작동한다 — 끄지 마라.** 아래 §3-3 참고.

---

## 3. 그래프의 현재 실력 (juice-shop, 확정 수치)

`rebuild/out/graph_spec_score_r3_juice-shop.json`

| arm | 라인 출력 | **exact(오차0)/36** | strict(±10+CWE)/36 | loose(±10)/36 | 경보/파일 |
|---|---|---:|---:|---:|---:|
| R1_v1 (LLM 단독) | **False** | 0 | 0 | 0 | 0.447 |
| R2_graph (그래프 단독) | True | **8** | 10 | 14 | 16.132 |
| R3_fusion (그래프+v1) | True | 8 | 10 | — | 16.327 |
| **R4_verified_TRUE** | True | **8** | 10 | 12 | **0.082** |

- v1 은 4줄 포맷이라 **라인을 낼 수 없다**(`has_line_output=False`). 라인 적중은 전부 그래프 몫.
- 그래프+v1 이 그래프 단독과 동일 → **v1 의 라인 기여 0**. 이게 L1 이 필요한 이유다.
- verifier 가 경보를 4,146 → 21건(16.13 → 0.082)으로 줄이며 적중 8 유지.

### 3-1. R3 verifier 는 유지해라 — 실측으로 효과가 크다

| arm | 경보 | exact | strict |
|---|---:|---:|---:|
| R2_graph (verifier 없음) | **4,146** | 8 | 10 |
| R4_TRUE_plus_UNCERTAIN | 94 | 8 | 10 |
| **R4_verified_TRUE** | **21** | **8** | **10** |

**경보를 99.5% 제거하면서 적중을 하나도 안 잃었다.** 이게 없으면 경보/파일이 16.13 이라
실무에서 못 쓴다. 구현: `rebuild/graph_spec_critic_r3.py` (TRUE/FALSE/UNCERTAIN 3분류 +
evidence 라인 == finding sink 라인 검증, temperature=0, §12-4 규칙).
`graph_spec_evidence_audit_r2.validate_evidence()` 로 불일치 finding 은 LLM 에 보내기 전에
격리하고 `evidence_mismatch` 로 기록한다.

### 3-2. 지표 이름에 속지 마라 ⚠

`rebuild/graph_spec_score_r2.py:14-15,30`
```
LINE_TOL = 10
line_hit_loose  = 같은 파일 AND |예측라인 − 정답라인| ≤ 10   (CWE 무관)
line_hit_strict = loose AND 예측 CWE 가 허용 집합에 속함      (라인은 여전히 ±10)
```
**`strict` 는 라인 엄격도가 아니라 CWE 일치 여부다.** 문서·발표에는 **`exact`(오차 0)를 주지표로 써라.**
(다행히 10건 중 8건이 exact 라 ±10 덕은 2건뿐이다.)

### 3-3. juice-shop 표본 한계 (R4 STEP 1)

정답 17건이 실제로는 **고유 코드 위치 12곳**. 부트스트랩 10,000회(seed 42) 결과 G2−G0 = +5,
**CI95 [0, 12] — 0 포함**. R4 원문: *"유의하지 않다"가 아니라 **"이 표본으로는 개선을 흔들림과
구분할 수 없다"***.

---

## 4. 지표 — F1 을 주지표로 쓰지 마라

F1 은 클래스 균형에 좌우되고(OWASP 50:50 이라 자명 arm 이 F1 0.6667), precision/recall 을 뭉개며,
우리 제품의 일(라인 지목)이 이진 분류가 아니다.

참고 — `rebuild/out/owasp_joern_v4_final_metrics.json` (OWASP holdout 110건, **파일 단위**):
| arm | precision | recall | F1 |
|---|---:|---:|---:|
| all-vuln (자명) | 0.5000 | 1.0000 | **0.6667** |
| Joern v4 단독 | 0.5172 | 0.8182 | 0.6338 |

**써야 할 지표**: exact-line 적중률(주지표) / 경보·파일 / 고정 경보예산 하 정밀도.
AUC 도 조심 — v1 AUC 0.905 가 외부에서 0.56 이었다.

**OWASP Benchmark 는 라인 평가에 못 쓴다.** `.cache/owasp-benchmark/expectedresults-1.2.csv`
컬럼이 `test name, category, real vulnerability, cwe` 뿐 — **라인 번호가 없다**(2,741건, 확인 완료).

---

## 5. 환경·경로 (전부 확인 완료)

```
작업 디렉터리   /Users/kimsehan/Desktop/scanops/scanops-model
브랜치         feat/v2-line-model
파이썬         .venv/bin/python   (3.14 / transformers 5.7 / torch 2.11 / sklearn)
Joern         brew 4.0.570.  .joern_dist/joern-cli → /opt/homebrew/Cellar/joern/4.0.570/libexec 심볼릭 링크 복구함
              astgen 링크 정상 (`bash joern/setup_local.sh status`)
              재현 확인: graph_spec_run.py S2A 가 juice-shop 257파일 24.1초에 정상 실행
juice-shop    /private/tmp/scanops_repobench/juice-shop  (커밋 1618a611b, 정답표와 동일)
디스크        여유 84GB
```

### 코드
```
rebuild/graph_spec_run.py          arm 별 Joern 실행 (S2A/S2B/S2C)
rebuild/graph_spec_score_r2.py     층 분류 + loose/strict 채점 (LINE_TOL=10)
rebuild/graph_spec_score_r3.py     R3 채점기
rebuild/graph_spec_critic_r3.py    verifier (경보 축소)
rebuild/graph_spec_llm.py          레포별 source/sink 스펙 LLM 생성  ← F_B 해결에 필요
joern/queries/probe_locations.sc   CPG 직접 프로브 (F_A 규명에 쓴 것)
joern/queries/taint_v4.sc          룰 21개
joern/sanitizers.json              sanitizer 42개
scripts/api_rebuild.py             서빙. v1 4줄 경로 무변경 + v2 분기 추가돼 있음
rebuild/prompt_v2.py               프롬프트 단일 소스
```

### 데이터
```
rebuild/data/repo_bench/juice-shop_truth.jsonl        44항목(코드 36)
rebuild/data/repo_bench/cvefixes_linetruth_r4.jsonl   R4 정답표 (필터 후)
rebuild/data/v2_samples_raw_v3.jsonl                  16,699 샘플(vuln 6,487, 라인 라벨) 563MB
rebuild/out/graph_spec_*_juice-shop.json              R1~R4 arm raw·채점 원본
rebuild/out/r4_*.json                                 R4 STEP 0~8 산출물
```

**CVEfixes 라인 라벨의 한계**: `line` 은 `first_deleted_line` 규칙이고, 118건 수작업 감사 결과
**의미론적 정확도 44.9%** (valid 44.9 / related_but_indirect 29.7 / unrelated_deletion 25.4).
→ `rebuild/out/v2_label_audit_pilot100.json`. 이 라벨로 exact 를 재면 **상한이 45% 근처**다.

### 모델 (탐지에 쓰지 마라)
```
models/Qwen3.5-9B-Q4_K_M.gguf   베이스 5.3GB
models/adapter_v1_fix.gguf      v1 (4줄, 라인 출력 없음)
models/adapter_v3_16k.gguf      v3 (붕괴. 배포 금지)
```
**llama-server 함정**: `--parallel N` 이 컨텍스트를 슬롯당 N등분한다. 16k 를 쓰려면
`-c 16640 --parallel 1` 처럼 여유를 둬라(실측으로 잡은 버그).

---

## 6. LLM 의 남은 역할 — 재학습 불필요

**"LLM 은 탐지에 관여하지 않는다" 는 정확하지 않다.** 최종 yes/no 를 LLM 이 원시 코드만 보고
내리지 않을 뿐, 아래 ①②로 **탐지 결과에 크게 관여한다.**

| 역할 | 탐지 관여 | 방법 |
|---|---|---|
| ① 레포별 source/sink 스펙 생성 | **탐지 범위 자체를 결정** | `graph_spec_llm.py` (F_B 해결에 필요) |
| ② 그래프 finding 검증 (verifier) | **경보 4,146→21, 적중 손실 0** | `graph_spec_critic_r3.py` — **유지해라** |
| ③ L1 라인 지목 | 이번 라운드 과제 | 별도 2차 호출. 4줄 템플릿 건드리지 말 것(§15-4) |
| ④ 설명·수정안 / CVSS | 없음 | 베이스 모델 + 프롬프트 |
| ⑤ ~~sanitizer YES/NO 판정~~ | — | **하지 마라 — 4번 죽였다(§2-3). ②와 혼동 금지** |

정리하면:
```
탐지 판정(yes/no)   그래프 taint 가 낸다
  ├ 무엇을 탐지할지   ① LLM 이 룰 생성
  └ 경보 정리        ② LLM 이 finding 검증
라인 지목           그래프 + ③ L1
설명·수정안·CVSS     ④ LLM
```

---

## 7. 미처리 — 대외 자료 정정

발표·사업계획서에 **AUC 0.905 / F1 0.805** 가 있다면 정정이 필요하다. 홈그라운드 점수이고
외부에서 PrimeVul 0.5618 / CleanVul 0.6165 다. `CLAUDE.md` 규칙 5 그대로 적용해야 한다.
**아직 아무도 손대지 않았다.**

## 8. 지출

RunPod 잔액 약 **$8** (v2 $19 + v3 $24.6 소진). L1 은 GPU 불필요(로컬 llama-server 또는 API).
