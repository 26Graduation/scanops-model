"""
ScanOps 보안 취약점 탐지 모델 — 학습/평가 설정 (단일 출처)
================================================================
모든 하이퍼파라미터와 경로를 이 파일 한 곳에 모은다. 학습 코드(train.py)와
평가 코드(evaluate.py)는 전부 여기서 값을 읽으므로, 실험 설정을 바꾸려면
이 파일만 수정하면 된다.

방법론 한 줄 요약(오해 방지):
  - 이것은 **트랜스포머 LLM(Qwen2.5-Coder-1.5B)의 지도 파인튜닝(supervised
    fine-tuning)**이다. 랜덤포레스트/결정트리 같은 고전 ML이 아니다.
  - 학습 알고리즘: **경사하강법(AdamW) + 역전파(backpropagation)**.
  - 효율화 기법: **QLoRA** = 4bit 양자화(QuantizedBase) + LoRA(저랭크 어댑터).
    전체 15.5억 파라미터 중 약 870만(0.56%)만 학습한다.
  - 손실 함수: 토큰 단위 **교차 엔트로피(cross-entropy)** (회귀의 RSS가 아님).
  - 평가 지표: 보안 탐지는 분류 문제이므로 **Precision / Recall / F1 /
    오탐률(FPR) / 정확도 / 혼동행렬**로 측정한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# 레포 루트 (ml/ 의 부모)
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT / "reports"


@dataclass
class ModelConfig:
    """베이스 모델 — Railway 1GB 메모리 제약 때문에 1.5B를 선택했다."""
    base_model_id: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    max_seq_len: int = 1024
    # ChatML 포맷 (Qwen 계열). assistant 응답만 손실 계산 대상.
    chat_format: str = "qwen"


@dataclass
class LoRAConfig:
    """LoRA 저랭크 어댑터 설정 — 어텐션 q/k/v/o 투영에만 어댑터를 붙인다."""
    r: int = 32                       # 랭크 (표현력↔과적합 트레이드오프)
    alpha: int = 64                   # 스케일링 = 2 × r (관례)
    dropout: float = 0.05             # 정규화(과적합 방지): 어댑터 뉴런 5% 무작위 차단
    target_modules: tuple[str, ...] = ("q_proj", "k_proj", "v_proj", "o_proj")


@dataclass
class TrainConfig:
    """학습 루프 하이퍼파라미터."""
    epochs: int = 3
    batch_size: int = 1
    grad_accum: int = 8               # 실효 배치 = batch_size × grad_accum = 8
    learning_rate: float = 1e-4       # cosine 스케줄 감쇠
    weight_decay: float = 0.0
    warmup_ratio: float = 0.03
    eval_ratio: float = 0.1           # train/eval 분할 비율 (단순 holdout)
    seed: int = 42
    # 4bit 양자화는 CUDA(bitsandbytes)에서만 가능. MPS/CPU는 fp16/fp32 폴백.
    use_4bit_on_cuda: bool = True


@dataclass
class DataConfig:
    """학습 데이터 구성 — v4~v7 반복으로 얻은 교훈을 주석으로 남긴다.

    교훈 1 (클래스 균형): 초기 v4 데이터는 안전 예시가 1%뿐이라 모델이
        '항상 취약'으로 편향됐다(오탐률 ~100%). → 안전 예시를 ~45%로 균형.
    교훈 2 (분포 정합): 취약 예시는 짧은 합성 스니펫, 안전 예시는 긴 OWASP
        Java 서블릿이면 모델이 보안 의미가 아니라 '코드 길이/스타일=라벨'을
        학습한다(스타일 단축학습). → 취약/안전 모두 같은 분포(합성+OWASP)로 구성.
    교훈 3 (프롬프트 정합): 학습 프롬프트는 추론 프롬프트(build_ft_user_prompt)와
        100% 동일해야 한다. 그래야 'VULNERABILITY: NONE' 같은 안전 판정이
        실제 서빙에서도 작동한다.
    """
    train_file: Path = DATA_DIR / "lora_train_v7.jsonl"
    # OWASP Benchmark(외부 표준 SAST 평가셋) 홀드아웃 — 학습엔 절대 쓰지 않는다.
    owasp_repo: Path = ROOT / ".cache" / "owasp-benchmark"
    safe_ratio_target: float = 0.45


@dataclass
class Config:
    model: ModelConfig = field(default_factory=ModelConfig)
    lora: LoRAConfig = field(default_factory=LoRAConfig)
    train: TrainConfig = field(default_factory=TrainConfig)
    data: DataConfig = field(default_factory=DataConfig)
    # 산출물 태그 (예: 'v8' → models/qwen-security-qlora-v8)
    tag: str = "v8"

    @property
    def adapter_dir(self) -> Path:
        return MODELS_DIR / f"qwen-security-qlora-{self.tag}"

    @property
    def loss_log(self) -> Path:
        return self.adapter_dir / "train_loss.json"


CONFIG = Config()
