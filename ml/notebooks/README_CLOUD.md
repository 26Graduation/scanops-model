# 클라우드 GPU(Colab) 학습 가이드 — Mac 대신 10분 학습

Mac에서 ~3시간 걸리는 v8 학습을 Colab 무료 T4 GPU에서 **약 10분**(학습+평가 포함)에 끝냅니다.

## 1. Colab 열기
1. https://colab.research.google.com 접속 (구글 계정 로그인)
2. 파일 → 노트북 업로드 → `ml/notebooks/colab_train_eval.ipynb` 선택
3. 상단 메뉴 → **런타임 → 런타임 유형 변경 → T4 GPU** 선택 → 저장

## 2. 업로드할 로컬 파일 2개
노트북 ② 셀 실행 시 파일 선택 창이 뜨면 아래 둘을 올립니다 (둘 다 한 번에 선택):
- `data/lora_train_v8.jsonl` (학습 데이터, 837개)
- `data/owasp_holdout_eval.json` (OWASP 평가 110케이스)

## 3. 셀 순서대로 실행 (▶)
- ① 설치 (~1분)
- ② 업로드
- ③ 학습 (~5~8분, GPU)
- ④ OWASP 평가 → **여기서 F1/오탐률/CWE정확도가 바로 나옵니다.** Grok 수치도 같이 출력돼 비교 가능
- ⑤ 학습곡선 + `adapter_v8.zip` 다운로드

## 4. 결과가 좋으면 (Grok 동급/우위)
1. 받은 `adapter_v8.zip`을 로컬 `models/qwen-security-qlora-v8/`에 압축 해제
2. `python scripts/convert_to_gguf_v5.py` (스크립트 안 태그를 v8로 바꿔서) → GGUF 변환 + Ollama 등록
3. 서빙 준비 완료

## 5. 결과가 아쉬우면 — 빠르게 재실험 (10분/회)
노트북 ③ 셀 맨 윗줄에서 하이퍼파라미터만 바꿔 ③~④ 재실행:
```python
MAXLEN, R, ALPHA, EPOCHS, LR = 1024, 32, 64, 4, 1e-4
#                                    ↑R  ↑alpha ↑epoch ↑학습률
```
시도해볼 조합 (오탐률↓ / CWE정확도↑ 목표):
- **EPOCHS 4 → 6** (더 학습): CWE 정확도↑ 기대
- **R 32 → 64** (표현력↑): 복잡한 패턴 학습력↑
- **LR 1e-4 → 5e-5** (안정적 학습): 과적합 줄임
- 데이터를 더 늘리려면 로컬에서 `scripts/build_lora_train_v8.py`의 `N_OWASP_VULN/SAFE`를 키워 재생성 후 다시 업로드

## 비교 기준 (현재 Mac v7 / Grok)
| | F1 | 재현율 | 오탐률 | CWE정확 |
|---|---|---|---|---|
| ScanOps v7 (Mac) | 56.5 | 67.3% | 70.9% | 5.5% |
| **Grok-3-mini (목표)** | 62.9 | 60.0% | 30.9% | 60.0% |

→ v8에서 **오탐률을 30%대로 낮추고 CWE정확도를 올리는 것**이 핵심 목표입니다.
