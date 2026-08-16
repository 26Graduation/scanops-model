# OPPOINT — 운영점 도달가능성 사전등록 (2026-08-17)

> **이 문서는 측정 전에 작성됐다.** 결과를 본 뒤 기준을 바꾸지 않는다.
> 변경 시 §7에 남긴다. 사양서가 결과보다 먼저 커밋된다.

## §1 질문

`FINAL_ARCHITECTURE_REPORT.md` §8 정정 목록의 **#1 이 유일하게 미해결인 사업 주장**이다:

| # | 계획서 표현 | 실측 | 상태 |
|---|---|---|---|
| 1 | "오탐률 1/3 (precision ~0.70+)" | CleanVul 240건 최고 arm precision **0.5909** | **미달** |

그런데 그 0.5909 는 **argmax 한 점**에서 잰 값이다.
**임계값을 옮기면 precision 0.70 에 닿는가? 닿는다면 recall 을 얼마나 지불하는가?**
이건 아직 아무도 재지 않았다.

## §2 왜 이 질문이 지금 중요한가

오늘 세 번 독립적으로 같은 곳을 가리켰다:

| 측정 | 관찰 |
|---|---|
| `SC_INFO_RESULTS.md` | SC 의 pair_correct 5배는 **운영점 이동**이었다 |
| `DOSE_RESULTS.md` §4 | GEN-F1 진동(step600 0.406)은 적합 실패가 아니라 **판정 경계 이동**이었다 |
| `V3_RESULTS.md` 부록 A | **"판별력은 안정, 임계값은 불안정"** — F1 비교는 임계값 잡음 비교였다 |

세 번 다 "모델이 아니라 운영점"이라 답했다. 그렇다면 **운영점을 제대로 고르면 사업 목표에
닿는지**를 직접 재는 것이 순서다. **비용 $0.**

## §3 무엇을 재는가 — 대상은 **v1** 이다

**측정 대상은 v3 가 아니라 v1 어댑터다.**
`FINAL_ARCHITECTURE_REPORT.md` §6·§5-5 에 따르면 실제 배포·서빙되는 것은
`models/adapter_v1_fix.gguf` (= v1) 이고, §8 #1 은 **제품에 대한 주장**이기 때문이다.
v3 를 재면 배포되지 않은 모델에 대한 숫자가 된다.

| split | tune (τ 선정용) | report (보고용) |
|---|---|---|
| CleanVul_v2 (주) | `out/v1_logprob_cleanvul_v2_tune.jsonl` | `out/v1_logprob_cleanvul_v2_report.jsonl` (2,706) |
| PrimeVul (부) | `out/v1_logprob_primevul_tune.jsonl` | `out/v1_logprob_primevul_report.jsonl` (288) |

- gold = `meta.label`. 점수 = `score`.
- 지표는 `bench_common.score` 를 **그대로 재사용**한다(precision/recall/fpr/f1).

## §4 방법 — τ 는 tune 에서 고르고 report 에서 보고한다

**절대 report 에서 τ 를 고르지 않는다.** 그러면 체리피킹이 된다.

1. tune split 에서 score 분위로 τ 후보를 만든다.
2. **선정 규칙(사전 고정)**: `tune precision ≥ 0.70` 을 만족하는 τ 중 **recall 최대**인 것.
   - 만족하는 τ 가 tune 에 하나도 없으면 → 그 자체가 결과다(`PRECISION-UNREACHABLE-ON-TUNE`).
3. 그 τ 를 **report 에 한 번만** 적용해 precision/recall/fpr/f1 을 보고한다.
4. 참고로 report 곡선 전체도 남기되, **판정에는 쓰지 않는다**(사후 선택 방지).
5. 자명 기준선(all-vuln)을 반드시 병기한다 — 균형셋에서 precision 0.5.
6. 부트스트랩 2,000회(쌍 단위)로 report precision 의 95% CI 를 낸다.

## §5 사전 등록 게이트

| 판정 | 조건 | 뜻 |
|---|---|---|
| **PRECISION-REACHABLE** | report precision **≥ 0.70** **AND** report recall **≥ 0.10** | 사업 목표를 **운영점 선택으로 달성 가능**. 대가(recall)를 명시해 보고 |
| **PRECISION-DEGENERATE** | report precision ≥ 0.70 **AND** recall < 0.10 | 수치는 닿지만 **실용성이 없다**. 달성으로 쓰지 않는다 |
| **PRECISION-UNREACHABLE** | report precision < 0.70 | 임계값 이동으로도 못 닿는다. §8 #1 은 미달로 유지 |

> **recall 하한 0.10 을 두는 이유**: precision 0.70 을 recall 0.01 에서 달성하는 것은
> "거의 아무것도 안 잡고 잡은 것만 맞다"는 뜻이다. 이걸 목표 달성이라 부르면 지표 조작이다.
> 결과를 보기 전에 이 바닥선을 박아둔다.

## §6 이 검사가 답하지 못하는 것 (미리 적는다)

- **AUC 가 상한을 준다.** v1 의 CleanVul_v2 AUC 는 0.617(`V3_RESULTS.md` §3-2)이다.
  판별력이 그 수준이면 도달 가능한 (precision, recall) 조합은 수학적으로 제한된다.
  이 검사는 **그 제약 안에서 최선의 점을 찾는 것**이지, 제약을 푸는 게 아니다.
- CleanVul_v2 의 라벨 성격(§4-3 — "이 변경이 취약점을 고치는 변경인가")은 그대로다.
  이 검사는 벤치를 바꾸지 않는다.
- 운영점은 **데이터 분포에 의존**한다. 실제 PR 트래픽은 균형셋(50:50)이 아니다.
  실서비스 precision 은 유병률에 따라 달라진다 — 그 보정은 이 검사의 범위 밖이다.
  **이 한계는 결과에 반드시 병기한다.**

## §7 사후 변경 기록

(비어 있으면 변경 없음.)

---

## §8 사전등록 확장 — **운영점 재보정** (2026-08-17, **결과 보기 전 추가**)

> §1~§6 은 "precision 0.70 에 닿는가"만 물었고 답은 `PRECISION-UNREACHABLE` 이었다(`out/oppoint_metrics.json`).
> 이 절은 **다음 질문**을 사전등록한다: **닿지 못한다면, 배포에 쓸 최선의 운영점은 어디인가.**
> 이 절은 아래 실행 결과를 **하나도 보기 전에** 작성·커밋됐다. 비용 $0.

### §8-1 왜 지금 이것을 재는가

배포 경로(`scripts/api_rebuild.py` → `_detect`)는 **greedy 생성**이다.
greedy 는 "logP(CWE) > logP(NONE)" 과 같으므로 **τ = 0 이라는 임계값을 암묵적으로 쓰고 있다.**
그 0 이 최선이라는 근거는 어디에도 없다. **한 번도 고른 적이 없기 때문이다.**

### §8-2 대상 — 여전히 **v1** (배포 어댑터)

§3 과 동일. v4 가 `V4_TRAIN_RUN_SPEC.md` §10-2 `ADOPT` 가 되면 **같은 규칙으로 v4 에 대해 반복**한다(§8-7).

### §8-3 τ 선정 — tune 에서만. report/test 는 보지 않는다

**선정에 쓰는 split (이 둘뿐):**

| 소스 | 파일 | 성격 |
|---|---|---|
| CleanVul_v2 tune (676) | `out/v1_logprob_cleanvul_v2_tune.jsonl` | 도메인 밖 |
| 내부 val | `out/v1_logprob_val.jsonl` | 도메인 안 |

**두 소스를 합쳐서 세지 않는다.** 크기가 다르면 큰 쪽이 τ 를 지배하기 때문이다.
대신 **소스별로 지표를 따로 계산하고**, 목적함수는 **두 소스 F1 의 평균**, 제약은 **두 소스 모두**에서 만족.

이유: 배포는 트래픽에 임계값 하나를 적용한다(도메인 안/밖을 구분하지 못한다).
따라서 τ 는 두 분포에서 동시에 견뎌야 한다. 이 요구를 목적함수에 직접 넣는다.

### §8-4 후보 운영점 (사전 고정)

| OP | 정의 |
|---|---|
| **OP-0** | **τ = 0.** 현 배포(greedy)와 같은 지점. 기준선 |
| **OP-A** | 평균 F1 최대 (제약 없음) |
| **OP-B** | **두 tune 소스 모두 FPR ≤ 0.15** 제약 아래 평균 F1 최대 |
| **OP-C** | **두 tune 소스 모두 FPR ≤ 0.10** 제약 아래 평균 F1 최대 |

- 제약을 만족하는 τ 가 없으면 그 OP 는 **`INFEASIBLE`** 로 기록한다. 제약을 완화하지 않는다.
- 각 OP 는 아래 보고 split 에 **정확히 1회씩만** 적용한다. **report/test 에서 τ 를 고르지 않는다.**

### §8-5 보고 split (5종)

| 벤치 | 파일 | 성격 |
|---|---|---|
| 내부 test | `out/v1_logprob_test.jsonl` | 도메인 안 |
| CleanVul_v2 report (2,706) | `out/v1_logprob_cleanvul_v2_report.jsonl` | 도메인 밖 (주) |
| PrimeVul report (288) | `out/v1_logprob_primevul_report.jsonl` | 도메인 밖 |
| CVEfixes 157 | `out/v1_logprob_cvefixes157.jsonl` | 도메인 밖 — **GPU 채점 필요, 학습 종료 후** |
| CyberNative 154 | `out/v1_logprob_cybernative154.jsonl` | 도메인 밖, 독립 출처 — **GPU 채점 필요** |

- 뒤 2종은 `rebuild/build_legacy_bench.py` 로 rebuild 프롬프트 형식으로 재구성했고,
  `build_dataset.py` 와 **동일한 정규화 코드 해시**로 train_v3/val_v3 대비 누수를 검사했다
  (`out/legacy_bench_leak.json`). **해시 완전일치 기준 겹침 0.** 근사 중복은 이 검사가 못 잡는다 — 한계로 적는다.
- GPU 가 학습 중이라 뒤 2종 채점은 **학습 종료 후**로 미룬다. 시간이 없으면 **3종으로 보고하고 미실행을 명시**한다.

**모든 표에 자명 기준선(all-vuln: 균형셋에서 precision 0.5, recall 1.0, FPR 1.0, F1 0.667)을 병기한다.**
보고 지표: precision / recall / FPR / F1, 그리고 report split 은 **부트스트랩 2,000회 95% CI**.

### §8-6 판정 (사전 고정)

어떤 OP 가 아래 **둘 다** 만족하면 **`OP-CANDIDATE`** (배포 운영점 후보):

1. **내부 test**: recall ≥ **0.75** AND FPR ≤ **0.15**
2. **CleanVul_v2 report**: precision 이 OP-0 보다 높되, **쌍 부트스트랩 Δprecision 의 95% CI 하한 > 0**

- 둘 다 만족하는 OP 가 없으면 → **`OP-INSUFFICIENT`**: "운영점 선택으로도 사업 목표를 지키지 못한다."
  그렇게 적고 **배포를 바꾸지 않는다.**
- 여러 OP 가 만족하면 CleanVul_v2 report Δprecision CI 하한이 가장 큰 것을 고른다.
- **OP-0 가 이미 최선인 경우도 정당한 결과다.** 그때는 변경 없음으로 적는다.

### §8-7 서술 규칙 (이 세션 전체에 적용)

- **어떤 문서에서도 "오탐률 X%" 를 (벤치 · OP · 그때의 recall) 없이 쓰지 않는다.**
  FPR 과 1-precision 은 다른 수이며, 유병률 50:50 가정에서만 관련된다. 그 가정을 매번 적는다.
- `ADOPT`(v4 채택)와 `TARGET-MET`(AUC 0.75)은 다른 이름이며 혼용하지 않는다.
- v4 가 `ADOPT` 되면 §8-3~§8-6 을 v4 점수로 **그대로 반복**한다. 규칙을 바꾸지 않는다.

### §8-8 이 확장이 답하지 못하는 것

- §6 의 한계가 그대로 유효하다 — 특히 **실서비스는 50:50 이 아니다.** 유병률이 낮으면 precision 은 더 떨어진다.
- 임계값은 **판별력(AUC)을 바꾸지 않는다.** 운영점 이동은 precision 과 recall 을 맞바꿀 뿐이다.
- 내부 val 과 내부 test 는 같은 분포다. 내부 test 성능은 **낙관적**이다.
