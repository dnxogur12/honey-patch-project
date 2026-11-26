#!/usr/bin/env python3
"""13주차 추가 검증 사례 (우태혁).

정상(Normal)   : normal_readme, normal_not_found
위반(Violation): backslash_traversal, mixed_deep_traversal
경계(Boundary) : boundary_prefix_dots, boundary_dup_query
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

from run_cases import (
    SECRET_MARKER,
    count_forks,
    free_port,
    request,
    wait_ready,
)

MODES = ["unpatched", "patched", "honeypatch"]


def send_request(port, target, log_path):
    """요청을 보내고 상태코드·비밀 노출·fork 수·탐지 여부를 반환한다."""
    forks_before = count_forks(log_path)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        log_before = f.read()

    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        status, raw = request(s, target, keep_alive=False)

    time.sleep(0.1)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        new_log = f.read()[len(log_before):]

    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "detected": ("attack name=" in new_log) or ("traversal" in new_log.lower()),
        "raw": raw,
    }


# ==============================================================================
# 1. 정상 사례 2종 (오탐 없이 정상 처리되는지 확인)
# ==============================================================================
NORMAL_CASES = [
    ("normal_readme", "/files?name=readme.txt"),          # 존재하는 일반 파일 조회
    ("normal_not_found", "/files?name=nonexistent.txt"),  # 없는 일반 파일 요청(404)
]

# (HTTP 상태코드, 비밀 노출 여부, Fork 횟수, 공격 탐지 여부)
NORMAL_EXPECT = {
    "unpatched": {
        "normal_readme": (200, False, 0, False),
        "normal_not_found": (404, False, 0, False),
    },
    "patched": {
        "normal_readme": (200, False, 0, False),
        "normal_not_found": (404, False, 0, False),
    },
    "honeypatch": {
        "normal_readme": (200, False, 0, False),
        "normal_not_found": (404, False, 0, False),
    },
}


# ==============================================================================
# 2. 위반 사례 2종 (변형된 경로 탐색 공격 차단/Decoy 전환 확인)
# ==============================================================================
VIOLATION_CASES = [
    ("backslash_traversal", r"/files?name=..\secret.txt"),         # 백슬래시(\) 사용
    ("mixed_deep_traversal", "/files?name=subdir/../../secret.txt"), # 하위 경로 후 상위 탈출
]

# (HTTP 상태코드, 비밀 노출 여부, Fork 횟수, 공격 탐지 여부)
VIOLATION_EXPECT = {
    "unpatched": {
        "backslash_traversal": (200, True, 0, False),
        "mixed_deep_traversal": (200, True, 0, False),
    },
    "patched": {
        "backslash_traversal": (403, False, 0, True),
        "mixed_deep_traversal": (403, False, 0, True),
    },
    "honeypatch": {
        "backslash_traversal": (200, False, 1, True),
        "mixed_deep_traversal": (200, False, 1, True),
    },
}


# ==============================================================================
# 3. 경계 사례 2종 (오탐/파싱 경계 지점 확인)
# ==============================================================================
BOUNDARY_CASES = [
    ("boundary_prefix_dots", "/files?name=..secret.txt"),               # '..'로 시작하지만 탐색 아님
    ("boundary_dup_query", "/files?name=readme.txt&name=../secret.txt"), # 중복 name 쿼리
]

# (HTTP 상태코드, 비밀 노출 여부, Fork 횟수, 공격 탐지 여부)
BOUNDARY_EXPECT = {
    "unpatched": {
        "boundary_prefix_dots": (404, False, 0, False),
        "boundary_dup_query": (200, False, 0, False),
    },
    "patched": {
        "boundary_prefix_dots": (404, False, 0, False),
        "boundary_dup_query": (200, False, 0, False),
    },
    "honeypatch": {
        "boundary_prefix_dots": (404, False, 0, False),
        "boundary_dup_query": (200, False, 0, False),
    },
}


def get_expected(mode, name):
    """사례별 기대 결과를 딕셔너리로 반환한다."""
    for table in (NORMAL_EXPECT, VIOLATION_EXPECT, BOUNDARY_EXPECT):
        if name in table[mode]:
            status, leaked, forks, detected = table[mode][name]
            return {
                "status": status,
                "leaked": leaked,
                "forks": forks,
                "detected": detected,
            }
    raise ValueError(f"Unknown case: {name}")


def evaluate_case(mode, name, actual):
    """기대 결과와 실제 결과 일치 여부를 반환한다."""
    exp = get_expected(mode, name)
    observed = {k: actual[k] for k in exp}
    return observed == exp


def run_case(mode, name, target, args):
    """단일 사례 실행 및 결과 JSON 저장."""
    result_dir = os.path.join("results_extra_taehyuk", mode, name)
    os.makedirs(result_dir, exist_ok=True)

    log_path = os.path.join(result_dir, "defender.log")
    with open(log_path, "w"):
        pass

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
        wait_ready(port)
        actual = send_request(port, target, log_path)
        passed = evaluate_case(mode, name, actual)
        result = {
            "mode": mode,
            "case": name,
            "target": target,
            "passed": passed,
            "expected": get_expected(mode, name),
            "actual": actual,
        }
    except Exception as e:
        result = {
            "mode": mode,
            "case": name,
            "target": target,
            "passed": False,
            "expected": get_expected(mode, name),
            "error": str(e),
        }
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    with open(os.path.join(result_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default="./build-local/honeypatch_server")
    parser.add_argument("--root", default="./www")
    args = parser.parse_args()

    all_cases = NORMAL_CASES + VIOLATION_CASES + BOUNDARY_CASES
    results = []

    for mode in MODES:
        print(f"\n=== {mode.upper()} ===")
        for name, target in all_cases:
            res = run_case(mode, name, target, args)
            results.append(res)
            status_str = "PASS" if res["passed"] else "FAIL"
            print(f"{status_str}  {name}")
            if "error" in res:
                print(f"  Error: {res['error']}")

    passed = sum(r["passed"] for r in results)
    failed = len(results) - passed

    print("\n=== SUMMARY ===")
    print(f"Total   : {len(results)}")
    print(f"PASS    : {passed}")
    print(f"FAIL    : {failed}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
