"""Railway Ollama에 v3 모델 배포.

단계:
  1. Railway Ollama에서 HF Hub 모델 pull
  2. 별칭(alias) 생성: qwen2.5-coder-security-v3:latest
  3. api_server.py MODEL_FT 업데이트
  4. git push → 자동 재배포

실행:
  python scripts/deploy_railway_v3.py
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

import requests

RAILWAY_BASE   = "https://scanops-model-production.up.railway.app"
RAILWAY_OLLAMA = "https://ollama-production-ac66.up.railway.app"
HF_MODEL       = "hf.co/SehanKim/qwen2.5-coder-security-v3-gguf:Q4_K_M"
OLLAMA_ALIAS   = "qwen2.5-coder-security-v3:latest"
API_SERVER_PY  = Path(__file__).resolve().parents[1] / "scripts" / "api_server.py"


def find_ollama_endpoint() -> str | None:
    """Railway Ollama API 접근 가능 여부 확인."""
    try:
        r = requests.get(f"{RAILWAY_OLLAMA}/api/tags", timeout=15)
        if r.status_code == 200:
            print(f"  Ollama 엔드포인트 확인: {RAILWAY_OLLAMA}")
            models = [m["name"] for m in r.json().get("models", [])]
            print(f"  현재 모델: {models}")
            return RAILWAY_OLLAMA
    except Exception as e:
        print(f"  Ollama 접근 오류: {e}")
    print("  Railway Ollama 직접 접근 불가 → HF Hub 이름을 MODEL_FT로 직접 사용")
    return None


def pull_model_on_railway(ollama_base: str) -> bool:
    """Railway Ollama에서 HF Hub 모델 pull."""
    print(f"[1/3] Railway Ollama pull: {HF_MODEL}")
    try:
        r = requests.post(
            f"{ollama_base}/api/pull",
            json={"name": HF_MODEL, "stream": False},
            timeout=600,
        )
        if r.status_code == 200:
            print(f"      pull 완료")
            return True
        print(f"      pull 실패: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        print(f"      pull 오류: {e}")
        return False


def create_alias_on_railway(ollama_base: str) -> bool:
    """Railway Ollama에서 모델 별칭 생성."""
    print(f"[2/3] 별칭 생성: {HF_MODEL} → {OLLAMA_ALIAS}")
    try:
        r = requests.post(
            f"{ollama_base}/api/copy",
            json={"source": HF_MODEL, "destination": OLLAMA_ALIAS},
            timeout=30,
        )
        if r.status_code == 200:
            print(f"      별칭 생성 완료")
            return True
        print(f"      별칭 생성 실패: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        print(f"      별칭 생성 오류: {e}")
        return False


def update_api_server(new_model: str) -> None:
    """api_server.py MODEL_FT 업데이트."""
    print(f"[3/3] api_server.py MODEL_FT → {new_model}")
    text = API_SERVER_PY.read_text()
    new_text = re.sub(
        r'MODEL_FT\s*=\s*"[^"]+"',
        f'MODEL_FT   = "{new_model}"',
        text,
    )
    API_SERVER_PY.write_text(new_text)
    print(f"      업데이트 완료")


def git_push() -> None:
    """변경사항 커밋 + push."""
    repo = Path(__file__).resolve().parents[1]
    subprocess.run(["git", "-C", str(repo), "add", "scripts/api_server.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m",
         "feat: MODEL_FT → qwen2.5-coder-security-v3 (XSS + 29 CWE, 367 samples)\n\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "push", "origin", "main"], check=True)
    print("      git push 완료 — Railway 자동 재배포 시작")


def main() -> None:
    print("=" * 60)
    print("  ScanOps v3 Railway 배포")
    print("=" * 60)

    ollama_base = find_ollama_endpoint()

    if ollama_base:
        pull_ok = pull_model_on_railway(ollama_base)
        if pull_ok:
            create_alias_on_railway(ollama_base)
    else:
        print("  Ollama 직접 접근 불가 — HF Hub pull은 Railway 내부에서 자동 처리됩니다.")
        print("  api_server.py에서 HF Hub 모델명을 직접 사용합니다.")

    model_name = OLLAMA_ALIAS if ollama_base else HF_MODEL
    update_api_server(model_name)
    git_push()

    print("\n  Railway 재배포 대기 중...")
    time.sleep(10)

    # health 체크
    for _ in range(40):
        try:
            r = requests.get(f"{RAILWAY_BASE}/health", timeout=10)
            if r.status_code == 200:
                data = r.json()
                print(f"\n  Railway 배포 완료!")
                print(f"  모델: {data.get('model')}")
                return
        except Exception:
            pass
        time.sleep(10)

    print("\n  경고: 배포 확인 타임아웃 — Railway 대시보드를 직접 확인하세요.")


if __name__ == "__main__":
    main()
