# ScanOps 보안 취약점 탐지 모델 — ML 파이프라인

> 이 `ml/` 디렉토리가 **모델 학습·평가·시각화의 단일 진입점**입니다.
> 흩어져 있던 실험 스크립트(`scripts/`)와 달리, 여기 4개 파일만 읽으면
> "어떤 데이터로 / 어떤 방법으로 학습했고 / 성능이 어떤지"를 전부 파악할 수 있습니다.

---

## 0. 방법론 한눈에 (용어 정리)

이 프로젝트의 학습 방법을 정확히 적습니다 (자주 혼동되는 부분):

| 질문 | 답 |
|---|---|
| 무슨 모델? | **트랜스포머 LLM** (Qwen2.5-Coder-1.5B), 사전학습된 코드 특화 모델 |
| 무슨 학습? | **지도 파인튜닝(supervised fine-tuning)** — 입력(코드)→출력(취약점 분석) 쌍으로 학습 |
| 학습 알고리즘? | **경사하강법(AdamW) + 역전파(backpropagation)** |
| 효율화 기법? | **QLoRA** = 4bit 양자화로 베이스 동결 + LoRA 저랭크 어댑터만 학습 (전체의 0.56%) |
| 손실 함수? | 토큰 단위 **교차 엔트로피(cross-entropy)** |
| 평가 지표? | **분류 지표**: Precision / Recall / F1 / 오탐률(FPR) / 정확도 / 혼동행렬 |

**랜덤포레스트가 아닙니다.** 랜덤포레스트는 표(tabular) 데이터용 결정트리 앙상블로,
LLM 파인튜닝과는 다른 계열입니다. **RSS(잔차제곱합)도 쓰지 않습니다.** RSS는 회귀
지표이고, 취약점 탐지는 분류 문제라 F1·오탐률로 측정합니다. 학습 중 최소화하는 값은
교차 엔트로피 손실(`train_loss.json`의 loss)입니다.

---

## 1. 파일 구조

```
ml/
  config.py      # 모든 하이퍼파라미터·경로 (단일 출처). 실험 설정은 여기만 수정.
  train.py       # QLoRA 파인튜닝 — "어디서 학습하는가"의 정답
  evaluate.py    # OWASP 외부 홀드아웃으로 분류 지표 산출 (F1 등)
  visualize.py   # 학습곡선·혼동행렬·지표막대·버전추이 PNG 생성
  notebooks/
    colab_train.ipynb   # 클라우드 GPU(Colab) 학습 노트북
```

데이터·산출물:
```
data/lora_train_v7.jsonl          # 학습 데이터 (취약/안전 균형, OWASP+합성)
.cache/owasp-benchmark/           # OWASP Benchmark 외부 평가셋 (git clone)
models/qwen-security-qlora-<tag>/ # 학습된 LoRA 어댑터 + train_loss.json
reports/eval_owasp_<tag>.json     # 평가 결과 (케이스별 상세 포함)
reports/figures/*.png             # 시각화
```

---

## 2. 실행 (3단계)

### 사전 준비
```bash
source .venv/bin/activate
# OWASP 외부 평가셋 (한 번만)
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git .cache/owasp-benchmark
```

### ① 학습
```bash
# 클라우드 GPU(CUDA) — 진짜 4bit QLoRA, 약 5~10분 (권장)
python -m ml.train --tag v8 --epochs 3

# 로컬 Mac(MPS) — fp16 폴백, 약 1~2시간 (발열 throttling 있음)
python -m ml.train --tag v8 --epochs 3
```
환경(CUDA/MPS/CPU)은 자동 감지합니다. 산출물: `models/qwen-security-qlora-v8/`.

### ② GGUF 변환 + Ollama 등록 (서빙용)
```bash
python scripts/convert_to_gguf_v5.py   # 태그만 바꿔 재사용 (병합→GGUF→Q4→ollama create)
```

### ③ 평가 + 시각화
```bash
python -m ml.evaluate --model qwen2.5-coder-security-v8:latest --tag v8 --with-grok
python -m ml.visualize --tag v8 --compare-versions
```
→ `reports/eval_owasp_v8.json` + `reports/figures/*.png`

---

## 3. 평가 지표 읽는 법

OWASP 홀드아웃 110케이스(취약 55 + 안전 55) 기준:

- **Recall(재현율/탐지율)**: 실제 취약점 55개 중 몇 개를 잡았나. 높을수록 놓침 적음.
- **FPR(오탐률)**: 안전한 코드 55개 중 몇 개를 잘못 경고했나. **낮을수록** 좋음.
- **Precision(정밀도)**: "취약"이라고 한 것 중 진짜 비율.
- **F1**: precision·recall 조화평균. 탐지·오탐 균형의 단일 지표.
- **CWE-카테고리 정확도**: 단순히 "취약함"이 아니라 *어떤* 취약점(SQLi/XSS 등)인지까지 맞췄나. 실제 코드 이해도 지표.

좋은 모델 = 높은 Recall + 낮은 FPR + 높은 CWE정확도. 우리는 외부 표준
벤치마크(OWASP)에서 Grok-3-mini와 비슷하거나 더 나은 수준을 목표로 합니다.

---

## 4. 학습 데이터 설계 — 반복(v4→v7)에서 얻은 교훈

`config.py`의 `DataConfig` 주석에도 있지만 핵심만:

1. **클래스 균형**: v4는 안전 예시가 1%뿐 → 모델이 '항상 취약'으로 편향(오탐률 ~100%).
   → 안전 예시를 ~45%로 균형.
2. **분포 정합 (스타일 단축학습 차단)**: 취약=짧은 합성, 안전=긴 OWASP Java면
   모델이 '코드 길이=라벨'을 학습 → 취약/안전 모두 합성+OWASP를 섞어 같은 분포로.
3. **프롬프트 정합**: 학습 프롬프트 = 추론 프롬프트(`build_ft_user_prompt`)로 통일해야
   `VULNERABILITY: NONE`(안전 판정)이 실제 서빙에서도 작동.

데이터 재생성: `python scripts/build_lora_train_v7.py`
