"""
ScanOps v4 Railway 배포 스크립트
=================================
단계:
  1. Railway Ollama에서 HF Hub v4 모델 pull
  2. 별칭 생성: qwen2.5-coder-security-v4:latest
  3. api_server.py MODEL_FT, version 업데이트
  4. git push → 자동 재배포

실행:
  python scripts/deploy_railway_v4.py
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

import requests

RAILWAY_BASE   = "https://scanops-model-production.up.railway.app"
RAILWAY_OLLAMA = "https://ollama-production-ac66.up.railway.app"
HF_MODEL       = "hf.co/SehanKim/qwen2.5-coder-security-v4-gguf:Q4_K_M"
OLLAMA_ALIAS   = "qwen2.5-coder-security-v4:latest"
API_SERVER_PY  = Path(__file__).resolve().parents[1] / "scripts" / "api_server.py"
NEW_VERSION    = "4.0.0"


def find_ollama_endpoint() -> str | None:
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


def update_api_server(model_name: str) -> None:
    print(f"[3/3] api_server.py 업데이트")
    text = API_SERVER_PY.read_text(encoding="utf-8")

    # MODEL_FT 업데이트
    new_text = re.sub(
        r'MODEL_FT\s*=\s*"[^"]+"',
        f'MODEL_FT   = "{model_name}"',
        text,
    )
    # version 업데이트
    new_text = re.sub(
        r'version\s*=\s*"[\d.]+"',
        f'version="{NEW_VERSION}"',
        new_text,
    )
    # health endpoint version 업데이트
    new_text = re.sub(
        r'"version":\s*"[\d.]+"',
        f'"version": "{NEW_VERSION}"',
        new_text,
    )
    API_SERVER_PY.write_text(new_text, encoding="utf-8")
    print(f"      MODEL_FT   → {model_name}")
    print(f"      version    → {NEW_VERSION}")


def git_push() -> None:
    repo = Path(__file__).resolve().parents[1]
    subprocess.run(["git", "-C", str(repo), "add",
                    "scripts/api_server.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m",
         "feat: MODEL_FT → qwen2.5-coder-security-v4 (CWE Top-25, 1000 samples, CVSS)\n\n"
         "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "push", "origin", "main"], check=True)
    print("      git push 완료 — Railway 자동 재배포 시작")


def wait_for_deploy() -> None:
    print("\n  Railway 재배포 대기 중...")
    time.sleep(15)
    for attempt in range(40):
        try:
            r = requests.get(f"{RAILWAY_BASE}/health", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("version") == NEW_VERSION:
                    print(f"\n  Railway 배포 완료!")
                    print(f"  모델:   {data.get('model')}")
                    print(f"  버전:   {data.get('version')}")
                    return
                else:
                    print(f"  대기 중... (현재 버전: {data.get('version')})")
        except Exception:
            pass
        time.sleep(10)
    print("\n  경고: 배포 확인 타임아웃 — Railway 대시보드를 직접 확인하세요.")


def main() -> None:
    print("=" * 65)
    print("  ScanOps v4 Railway 배포")
    print("=" * 65)

    ollama_base = find_ollama_endpoint()

    if ollama_base:
        pull_ok = pull_model_on_railway(ollama_base)
        if pull_ok:
            create_alias_on_railway(ollama_base)
    else:
        print("  Ollama 직접 접근 불가 — Railway 내부에서 자동 pull 처리됩니다.")

    model_name = OLLAMA_ALIAS if ollama_base else HF_MODEL
    update_api_server(model_name)

    print("\n  git push로 Railway 자동 재배포를 트리거합니다...")
    try:
        git_push()
        wait_for_deploy()
    except subprocess.CalledProcessError as e:
        print(f"\n  git push 실패: {e}")
        print("  터미널에서 직접 실행: git push origin main")

    print(f"\n  배포 URL: {RAILWAY_BASE}")
    print(f"  헬스체크: {RAILWAY_BASE}/health")


if __name__ == "__main__":
    main()
