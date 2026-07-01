# ScanOps V13 사전 베이스라인 — 현재 v12 7B vs Grok (정직한 측정)

측정: 2026-06-30 · 모델 `qwen2.5-coder-security-v12-7b` (배포본, Ollama ADAPTER) · num_predict=200
> 목적: **V13가 넘어야 할 기준선**을 정직하게 고정한다. v13 학습 전 현재 상태이며,
> 이 수치를 v13 재학습 후 동일 스크립트로 비교한다.

---

## 1. CVEfixes 157 (실제 2024 CVE, 10개 언어 · held-out)

| 시스템 | F1 | 재현율 | 오탐률 | 정확도 | (TP/FN/FP/TN) |
|---|---|---|---|---|---|
| v12 7B LLM 단독 | 2.5 | **1.2%** | 0.0% | 49.7% | 1/79/0/77 |
| v12 7B + 그래프 하이브리드 | 2.5 | 1.2% | 0.0% | 49.7% | 1/79/0/77 |
| **Grok-3-mini** | **40.0** | **30.0%** | 20.8% | **54.1%** | 24/56/16/61 |

- **7B는 실제 CVE에서 "무조건 안전"** — 취약 80개 중 1개만 탐지(재현율 1.2%). 메모리 기록과 일치.
- 그래프는 실제 CVE에서 거의 'unknown'(157중 safe 3·vuln 0) → 하이브리드 = LLM(무력).
- **Grok이 압도적 우위.** 실제 CVE 판별은 현재 우리 시스템의 최대 약점 → **V13 데이터 확장의 핵심 타깃.**

## 2. OWASP Benchmark 110 (zero-shot, 합성 패턴)

### 2-A. 입력 = full servlet file (`owasp_holdout_full.json`)
| 시스템 | F1 | 재현율 | 오탐률 | 정확도 | (TP/FN/FP/TN) |
|---|---|---|---|---|---|
| v12 7B LLM 단독 | 50.9 | 52.7% | 54.5% | 49.1% | 29/26/30/25 |
| v12 7B + 그래프 하이브리드 | 75.0 | 92.7% | 54.5% | 69.1% | 51/4/30/25 |
| **Grok-3-mini** | **83.5** | 96.4% | 34.5% | **80.9%** | 53/2/19/36 |

- 그래프가 LLM 놓친 취약 **22개 보강**(재현율 52.7%→92.7%)하나, **오탐 억제는 0** → FPR 54.5% 잔존.
- 원인: full 파일에선 sink·sanitizer가 멀리 떨어져 그래프의 **strong-safe veto가 안 켜짐**(weak-safe 34건 모두 veto 보류).
- **strong 가드는 의도된 설계**(weak-safe로 실제 CVE를 잘못 veto하는 것 방지 — §1의 CVEfixes 위험과 동일).

### 2-B. 진단: weak-safe veto를 켜면? (오버피팅 주의)
| 결합규칙 | F1 | 재현율 | 오탐률 | 정확도 |
|---|---|---|---|---|
| 현재(strong-only veto) | 75.0 | 92.7% | 54.5% | 69.1% |
| **any-safe veto(진단용)** | **84.3** | 92.7% | **27.3%** | **82.7%** |

- OWASP에서 그래프 safe 34건은 **34/34 전부 실제 safe** → any-safe veto면 FP 15개 억제, FN 0 → **Grok(83.5) 추월**.
- 그러나 CVEfixes에선 그래프 safe 3건 중 2건이 실제 취약 → **전역 적용은 실제 CVE에서 위험**(오버피팅).
- 정답은 "veto 가드 제거"가 아니라 **full 파일에서도 sink+sanitizer 동위치를 잡아 strong을 올바로 켜는 그래프 개선**.

### 2-C. 입력 = method 추출 (`owasp_benchmark_cases.py`, 문서화된 프로덕션 경로)
> _(method-extracted 벤치 실행 결과 — 채워질 예정. 문서 V12_RESULTS에선 하이브리드 F1 84.6로 Grok 62.9 추월.)_

---

## 3. 정직한 결론 (V13 동기)
1. **실제 CVE(CVEfixes)**: 현재 7B는 사실상 판별 불가(재현율 1.2%). Grok 완승. → **V13(CVEfixes 3,483개, 13배) 학습이 정확히 이 약점을 겨냥.**
2. **OWASP**: 그래프 하이브리드가 입력 추출 방식에 민감. method 추출 + strong-safe veto가 켜지면 Grok 추월 가능(2-B/2-C). full 파일에선 그래프 개선 필요.
3. **다음**: ① Colab에서 V13 7B 재학습 → 동일 벤치 재측정(이 표 갱신). ② 그래프의 full-file strong-safe 탐지 개선. ③ RAG(8,883) 신규-CVE 재현율 별도 검증.

## 산출 데이터
- `reports/results_v12_cvefixes_benchmark.json` (157, 4지표/케이스별)
- `reports/results_v12_owasp_holdout_bench.json` (110 full-file)
- `reports/results_v12_owasp_method_bench.json` (110 method, 생성 중)
