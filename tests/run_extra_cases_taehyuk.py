#!/usr/bin/env python3
"""

포함된 사례 (2종):
  1. mixed_deep_traversal (위반): GET /files?name=subdir/../../secret.txt
     - 하위 디렉터리(subdir/)를 거친 뒤 상위 경로로 두 단계(../../) 올라가 secret.txt 접근 시도
  2. boundary_prefix_dots (경계): GET /files?name=..secret.txt
     - '..'로 시작하는 파일명이지만 상위 디렉터리 이동(../)은 아닌 경계 입력에서 오탐 여부 확인

실행 방법 (저장소 루트 기준):
  python3 tests/run_extra_taehyuk_cases.py --bin ./build-local/honeypatch_server --root ./www

출력 저장 위치:
  results/extra_taehyuk/<모드>/<사례명>/defender.log
  results/extra_taehyuk/<모드>/<사례명>/result.json
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

# 기존 run_cases.py의 서버 요청·포트·fork 카운트 헬퍼 재사용
from run_cases import (
    SECRET_MARKER,
    count_forks,
    free_port,
    request,
    wait_ready,
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODES = ["unpatched", "patched", "honeypatch"]


# ==============================================================================
# 1. 검증 사례 및 사전 기대 결과 정의 (실행 전 작성)
#    - status  : HTTP 응답 상태코드
#    - leaked  : 응답 본문에 실제 비밀(REAL_SECRET) 노출 여부
#    - forks   : 이번 요청 동안 새로 생성된 Decoy 자식 프로세스 수
#    - detected: 방어자 로그(defender.log)에 공격 탐지 흔적이 남았는지 여부
# ==============================================================================
CASES = [
    (
        "violation",
        "mixed_deep_traversal",
        "/files?name=subdir/../../secret.txt",
        "하위 경로(subdir/) 진입 후 상위 경로(../../)로 빠져나오는 경로 탐색 시도",
    ),
    (
        "boundary",
        "boundary_prefix_dots",
        "/files?name=..secret.txt",
        "'..'로 시작하지만 경로 탐색(../)은 아닌 파일명 경계 입력",
    ),
]

# 모드별 사전 기대 결과: (status, leaked, forks, detected)
EXPECT = {
    "unpatched": {
        # 보호 미적용: 복합 경로 탐색은 비밀 노출, ..secret.txt는 파일이 없으므로 404
        "mixed_deep_traversal": (200, True,  0, False),
        "boundary_prefix_dots": (404, False, 0, False),
    },
    "patched": {
        # 일반 패치: 경로 탐색은 403 차단, ..secret.txt는 오탐 없이 404
        "mixed_deep_traversal": (403, False, 0, True),
        "boundary_prefix_dots": (404, False, 0, False),
    },
    "honeypatch": {
        # 허니패치: 경로 탐색은 Decoy 분기(fork=1) 후 200 위장 응답·비밀 미노출, ..secret.txt는 404·fork=0
        "mixed_deep_traversal": (200, False, 1, True),
        "boundary_prefix_dots": (404, False, 0, False),
    },
}


# ==============================================================================
# 2. HTTP 요청 실행 및 결과 수집
# ==============================================================================
def send_and_collect(port: int, target: str, log_path: str) -> dict:
    """단일 요청을 전송하고 응답 상태·비밀 노출·fork 수·탐지 로그 여부를 반환한다."""
    forks_before = count_forks(log_path)

    log_before = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            log_before = str(f.read())
    start_idx = int(len(log_before))

    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        status, raw = request(sock, target, keep_alive=False)

    # Decoy 자식 프로세스가 로그를 기록할 시간 확보
    time.sleep(0.1)

    new_log = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            full_log = str(f.read())
            new_log = full_log[start_idx:]

    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "detected": ("attack name=" in new_log) or ("traversal" in new_log.lower()),
        "raw": raw,
    }


def expected_to_dict(mode: str, case_name: str) -> dict:
    """기대 결과 튜플을 읽기 쉬운 딕셔너리로 변환한다."""
    status, leaked, forks, detected = EXPECT[mode][case_name]
    return {
        "status": status,
        "leaked": leaked,
        "forks": forks,
        "detected": detected,
    }


def diff_expected_actual(expected: dict, actual: dict) -> list[str]:
    """기대 결과와 실제 결과가 다른 항목 목록을 반환한다."""
    diffs = []
    for key, exp_val in expected.items():
        act_val = actual.get(key)
        if act_val != exp_val:
            diffs.append(f"{key}: 기대={exp_val}, 실제={act_val}")
    return diffs


# ==============================================================================
# 3. 개별 사례 실행 및 결과 저장
# ==============================================================================
def run_one_case(args, mode: str, category: str, case_name: str, target: str, desc: str) -> dict:
    """특정 모드에서 1개 사례를 실행하고 result.json과 defender.log를 저장한다."""
    out_dir = os.path.join(args.out, mode, case_name)
    os.makedirs(out_dir, exist_ok=True)

    log_path = os.path.join(out_dir, "defender.log")
    open(log_path, "w").close()  # 이전 로그 초기화

    expected = expected_to_dict(mode, case_name)
    port = free_port()

    server = subprocess.Popen(
        [
            args.bin,
            "--mode", mode,
            "--port", str(port),
            "--root", args.root,
            "--log", log_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_ready(port):
            raise RuntimeError("서버가 시작되지 않았습니다.")

        actual = send_and_collect(port, target, log_path)
        diffs = diff_expected_actual(expected, actual)
        passed = len(diffs) == 0

        result = {
            "mode": mode,
            "category": category,
            "case": case_name,
            "description": desc,
            "target": target,
            "passed": passed,
            "expected": expected,
            "actual": actual,
            "diffs": diffs,
        }

    except Exception as e:
        result = {
            "mode": mode,
            "category": category,
            "case": case_name,
            "description": desc,
            "target": target,
            "passed": False,
            "expected": expected,
            "error": str(e),
            "diffs": [f"실행 오류: {e}"],
        }

    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    with open(os.path.join(out_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result


# ==============================================================================
# 4. 메인 진입점
# ==============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="13주차 추가 검증 사례 실행 (우태혁)")
    parser.add_argument(
        "--bin",
        default=os.path.join(ROOT_DIR, "build-local", "honeypatch_server"),
        help="서버 바이너리 경로",
    )
    parser.add_argument(
        "--root",
        default=os.path.join(ROOT_DIR, "www"),
        help="웹 루트 디렉터리 경로",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(ROOT_DIR, "results", "extra_taehyuk"),
        help="결과 저장 경로",
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        default=MODES,
        choices=MODES,
        help="실행할 모드 목록",
    )
    args = parser.parse_args()
    args.root = os.path.abspath(args.root)

    all_results = []
    for mode in args.modes:
        print(f"\n=== {mode.upper()} ===")
        for category, case_name, target, desc in CASES:
            res = run_one_case(args, mode, category, case_name, target, desc)
            all_results.append(res)

            tag = "PASS" if res["passed"] else "FAIL"
            print(f"[{tag}] ({category:<9}) {case_name:<22} -> {target}")
            for d in res.get("diffs", []):
                print(f"       차이: {d}")

    total = len(all_results)
    passed_cnt = sum(1 for r in all_results if r["passed"])
    failed_cnt = total - passed_cnt

    print("\n=== SUMMARY ===")
    print(f"Total : {total}")
    print(f"PASS  : {passed_cnt}")
    print(f"FAIL  : {failed_cnt}")

    return 0 if failed_cnt == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
