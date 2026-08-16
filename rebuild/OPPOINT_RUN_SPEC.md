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
