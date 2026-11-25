
#!/usr/bin/env python3
"""13주차 추가 검증 사례.

정상(Normal)   : path_return, dot_path
위반(Violation): repeated_attack, null_byte
경계(Boundary) : double_encoded, empty_name

"""

import argparse
import os
import socket
import subprocess
import sys
import time
import json

# 기존 검증 코드의 공통 함수 재사용
from run_cases import (
    SECRET_MARKER,
    request,
    count_forks,
    free_port,
    wait_ready,
)

MODES = ["unpatched", "patched", "honeypatch"]

# 정상 사례 2종
NORMAL_CASES = [
    ("path_return", "/files?name=../files/readme.txt"),
    ("dot_path", "/files?name=./readme.txt"),
]

# 정상 사례 기대 결과
# (HTTP 상태코드, 비밀 노출 여부, Fork 횟수)
NORMAL_EXPECT = {
    "unpatched": {
        "path_return": (200, False, 0),
        "dot_path": (200, False, 0),
    },
    "patched": {
        "path_return": (200, False, 0),
        "dot_path": (200, False, 0),
    },
    "honeypatch": {
        "path_return": (200, False, 0),
        "dot_path": (200, False, 0),
    },
}


def run_normal_case(port, target, log_path):
    """정상 요청의 응답 및 공격 오탐 여부 검증."""

    forks_before = count_forks(log_path)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        log_before = f.read()

    with socket.create_connection(
        ("127.0.0.1", port), timeout=3
    ) as s:
        status, raw = request(s, target, keep_alive=False)

    time.sleep(0.1)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        new_log = f.read()[len(log_before):]

    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "detected": "attack name=" in new_log,
        "raw": raw,
    }



# 위반 사례 1: 동일 연결에서 반복 공격
ATTACK = "/files?name=../secret.txt"
REPEAT_COUNT = 10

REPEATED_EXPECT = {
    "unpatched": (200, True, 0),
    "patched": (403, False, 0),
    "honeypatch": (200, False, 1),
}


def run_repeated_attack(port, log_path):
    """동일 TCP 연결에서 공격을 10회 반복한다."""

    forks_before = count_forks(log_path)

    statuses = []
    leaks = []
    bodies = []
    responses = []

    with socket.create_connection(
        ("127.0.0.1", port), timeout=3
    ) as s:

        for _ in range(REPEAT_COUNT):
            status, raw = request(s, ATTACK)

            statuses.append(status)
            leaks.append(SECRET_MARKER in raw)
            responses.append(raw)

            # HTTP 헤더와 응답 본문 분리
            body = raw.partition("\r\n\r\n")[2]
            bodies.append(body)

    time.sleep(0.1)

    return {
        "statuses": statuses,
        "leaks": leaks,
        "forks": count_forks(log_path) - forks_before,
        "consistent": len(set(bodies)) == 1,
        "responses": responses,
    }


# 위반 사례 2: NUL 바이트 포함 요청
NULL_BYTE_TARGET = "/files?name=readme.txt%00"

# (HTTP 상태코드, 비밀 노출, Fork 횟수, 공격 탐지)
NULL_BYTE_EXPECT = {
    "unpatched": (200, False, 0, False),
    "patched": (403, False, 0, True),
    "honeypatch": (404, False, 1, True),
}


def run_null_byte(port, log_path):
    """NUL 바이트 탐지 및 모드별 응답 검증."""

    forks_before = count_forks(log_path)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        log_before = f.read()

    with socket.create_connection(
        ("127.0.0.1", port), timeout=3
    ) as s:
        status, raw = request(
            s, NULL_BYTE_TARGET, keep_alive=False
        )

    time.sleep(0.1)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        new_log = f.read()[len(log_before):]

    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "detected": "NUL byte in file name" in new_log,
        "raw": raw,
    }



# 경계 사례 1: 이중 URL 인코딩
DOUBLE_ENCODED_TARGET = (
    "/files?name=%252e%252e%252fsecret.txt"
)

DOUBLE_ENCODED_EXPECT = {
    "unpatched": (200, True, 0),
    "patched": (403, False, 0),
    "honeypatch": (200, False, 1),
}


def run_double_encoded(port, log_path):
    """이중 URL 인코딩 입력에 대한 처리 검증."""

    forks_before = count_forks(log_path)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        log_before = f.read()

    with socket.create_connection(
        ("127.0.0.1", port), timeout=3
    ) as s:
        status, raw = request(
            s, DOUBLE_ENCODED_TARGET, keep_alive=False
        )

    time.sleep(0.1)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        new_log = f.read()[len(log_before):]

    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "detected": "double-encoded path traversal" in new_log,
        "raw": raw,
    }


# 경계 사례 2: 빈 파일명
EMPTY_NAME_TARGET = "/files?name="

EMPTY_NAME_EXPECT = {
    "unpatched": (400, False, 0, False),
    "patched": (400, False, 0, False),
    "honeypatch": (400, False, 0, False),
}


def run_empty_name(port, log_path):
    """빈 파일명 요청에 대한 처리 검증."""

    return run_normal_case(
        port, EMPTY_NAME_TARGET, log_path
    )

def evaluate_case(mode, name, actual):
    """사례별 기대 결과와 실제 결과 비교."""

    if name in ("path_return", "dot_path"):
        expected = NORMAL_EXPECT[mode][name]
        observed = (
            actual["status"],
            actual["leaked"],
            actual["forks"],
        )

        return (
            observed == expected
            and not actual["detected"]
        )

    if name == "repeated_attack":
        status, leaked, forks = REPEATED_EXPECT[mode]

        return (
            actual["statuses"] == [status] * REPEAT_COUNT
            and actual["leaks"] == [leaked] * REPEAT_COUNT
            and actual["forks"] == forks
            and actual["consistent"]
        )

    if name == "null_byte":
        observed = (
            actual["status"],
            actual["leaked"],
            actual["forks"],
            actual["detected"],
        )

        return observed == NULL_BYTE_EXPECT[mode]

    if name == "double_encoded":
        observed = (
            actual["status"],
            actual["leaked"],
            actual["forks"],
        )

        return (
            observed == DOUBLE_ENCODED_EXPECT[mode]
            and actual["detected"] == (mode != "unpatched")
        )

    if name == "empty_name":
        observed = (
            actual["status"],
            actual["leaked"],
            actual["forks"],
            actual["detected"],
        )

        return observed == EMPTY_NAME_EXPECT[mode]

    raise ValueError(f"Unknown case: {name}")

def get_expected(mode, name):
    """사례별 사전 기대 결과 반환."""

    if name in ("path_return", "dot_path"):
        status, leaked, forks = NORMAL_EXPECT[mode][name]

        return {
            "status": status,
            "leaked": leaked,
            "forks": forks,
            "detected": False,
        }

    if name == "repeated_attack":
        status, leaked, forks = REPEATED_EXPECT[mode]

        return {
            "statuses": [status] * REPEAT_COUNT,
            "leaks": [leaked] * REPEAT_COUNT,
            "forks": forks,
            "consistent": True,
        }

    if name == "null_byte":
        status, leaked, forks, detected = NULL_BYTE_EXPECT[mode]

        return {
            "status": status,
            "leaked": leaked,
            "forks": forks,
            "detected": detected,
        }

    if name == "double_encoded":
        status, leaked, forks = DOUBLE_ENCODED_EXPECT[mode]

        return {
            "status": status,
            "leaked": leaked,
            "forks": forks,
            "detected": mode != "unpatched",
        }

    if name == "empty_name":
        status, leaked, forks, detected = EMPTY_NAME_EXPECT[mode]

        return {
            "status": status,
            "leaked": leaked,
            "forks": forks,
            "detected": detected,
        }

    raise ValueError(f"Unknown case: {name}")

def run_case(mode, name, runner, args):
    """개별 사례 실행 및 결과 저장."""

    result_dir = os.path.join(
        "results_extra", mode, name
    )
    os.makedirs(result_dir, exist_ok=True)

    log_path = os.path.join(
        result_dir, "defender.log"
    )

    # 이전 실행 로그 초기화
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

        actual = runner(port, log_path)
        passed = evaluate_case(mode, name, actual)

        result = {
            "mode": mode,
            "case": name,
            "passed": passed,
            "expected": get_expected(mode, name),
            "actual": actual,
        }

    except Exception as e:
        result = {
            "mode": mode,
            "case": name,
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

    with open(
        os.path.join(result_dir, "result.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            result, f,
            ensure_ascii=False,
            indent=2,
        )

    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bin",
        default="./build-local/honeypatch_server",
    )
    parser.add_argument("--root", default="./www")
    args = parser.parse_args()

    cases = [
        (
            name,
            lambda port, log, target=target:
                run_normal_case(port, target, log)
        )
        for name, target in NORMAL_CASES
    ]

    cases.extend([
        ("repeated_attack", run_repeated_attack),
        ("null_byte", run_null_byte),
        ("double_encoded", run_double_encoded),
        ("empty_name", run_empty_name),
    ])

    results = []

    for mode in MODES:
        print(f"\n=== {mode.upper()} ===")

        for name, runner in cases:
            result = run_case(mode, name, runner, args)
            results.append(result)

            status = "PASS" if result["passed"] else "FAIL"
            print(f"{status}  {name}")

            if "error" in result:
                print(f"  Error: {result['error']}")

    passed = sum(r["passed"] for r in results)
    failed = len(results) - passed

    print("\n=== SUMMARY ===")
    print(f"Total   : {len(results)}")
    print(f"PASS    : {passed}")
    print(f"FAIL    : {failed}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())