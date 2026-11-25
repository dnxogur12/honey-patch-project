#!/usr/bin/env python3
"""13주차 추가 검증 사례 (2) — 기존 사례와 별도 파일.

  위반(Violation): symlink    www/files/ 안의 링크가 files/ 밖의 비밀 파일을 가리킴 (../ 없음)
  정상(Normal)   : keepalive  A가 Keep-Alive 연결을 유지하는 동안 B의 새 연결 GET /public

  python3 tests/run_symlink_keepalive_cases.py
결과: results/extra13/<mode>/<case>/ (defender.log, result.json). 표준 라이브러리만 사용.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from run_cases import count_forks, free_port, request, wait_ready

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODES = ["unpatched", "patched", "honeypatch"]

# ---------------- 위반: 심볼릭 링크 ----------------
LINK_NAME = "symlink_test.txt"
LINK_MARKER = "SYMLINK_SECRET"  # 테스트용 외부 비밀 표식

# (status, leaked, forks, detected) — 실행 전 작성
# honeypatch 404: 미등록 대상에 대한 Decoy 응답 규칙 (null_byte 사례와 동일)
SYMLINK_EXPECT = {
    "unpatched":  (200, True,  0, False),  # 검사 없음 → 노출 (보호 전 기준선)
    "patched":    (403, False, 0, True),
    "honeypatch": (404, False, 1, True),
}


def run_symlink(port, log_path, root):
    secret_dir = tempfile.mkdtemp()  # www/ 밖
    secret = os.path.join(secret_dir, "outside_secret.txt")
    link = os.path.join(root, "files", LINK_NAME)
    if os.path.lexists(link):
        raise RuntimeError(f"{link} already exists; not overwriting")
    try:
        with open(secret, "w") as f:
            f.write(f"{LINK_MARKER}{{symlink-test}}\n")
        os.symlink(secret, link)
        with open(log_path, errors="replace") as f:
            before = len(f.read())
        forks0 = count_forks(log_path)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            status, raw = request(s, f"/files?name={LINK_NAME}", keep_alive=False)
        time.sleep(0.1)
        with open(log_path, errors="replace") as f:
            new_log = f.read()[before:]
        return {
            "status": status,
            "leaked": LINK_MARKER in raw,
            "forks": count_forks(log_path) - forks0,
            "detected": "attack name=" in new_log,
            "raw": raw,
        }
    finally:  # 생성한 링크·파일 정리
        if os.path.islink(link):
            os.remove(link)
        shutil.rmtree(secret_dir, ignore_errors=True)


def expect_symlink(mode):
    return dict(zip(("status", "leaked", "forks", "detected"), SYMLINK_EXPECT[mode]))


def check_symlink(mode, a):
    exp = expect_symlink(mode)
    reasons = [f"{k}: expected {v}, got {a[k]}" for k, v in exp.items() if a[k] != v]
    if reasons and mode != "unpatched" and a["leaked"] and not a["detected"]:
        reasons.append(
            "근거: 탐지 로그 없음 + 외부 비밀 노출. detector.cpp는 이름 문자열만 정규화하고 "
            "실제 경로(realpath)를 확인하지 않음. README 7절 탐지 TODO에 '심볼릭 링크'가 담당 작업으로 "
            "명시됨 → 분류 후보: 구현 버그(필터 조건 누락). "
            "팀이 범위에서 제외하기로 하면 명세상 미지원.")
    return reasons


# ---------------- 정상: Keep-Alive 동시 연결 ----------------
LIMIT_SEC = 2.0   # B가 이 시간 안에 응답받아야 PASS
WAIT_SEC = 15.0   # 실제 지연 기록용 최대 대기 (서버 유휴 타임아웃 10초보다 길게)

# 모든 모드 동일: B 200, LIMIT_SEC 이내, fork 0, 탐지 0
KEEPALIVE_EXPECT = {"a_status": 200, "b_status": 200, "forks": 0, "detected": False}


def run_keepalive(port, log_path, root):
    forks0 = count_forks(log_path)
    a = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        a_status, _ = request(a, "/public", keep_alive=True)  # A: 요청 후 연결 유지
        b = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SEC)
        t0 = time.monotonic()
        try:
            b_status, _ = request(b, "/public", keep_alive=False)
        except socket.timeout:
            b_status = None
        delay = time.monotonic() - t0
        b.close()
        try:  # B 처리 후 A 연결이 아직 살아있는지 (유휴 타임아웃으로 끊겼는지)
            a_after, _ = request(a, "/public", keep_alive=False)
        except OSError:
            a_after = None
    finally:
        a.close()
    with open(log_path, errors="replace") as f:
        detected = "attack name=" in f.read()
    return {
        "a_status": a_status,
        "b_status": b_status,
        "b_delay_sec": round(delay, 3),
        "b_timed_out": b_status is None,
        "a_after_b": a_after,
        "forks": count_forks(log_path) - forks0,
        "detected": detected,
    }


def expect_keepalive(mode):
    return dict(KEEPALIVE_EXPECT, b_delay_sec=f"<= {LIMIT_SEC}")


def check_keepalive(mode, a):
    reasons = [f"{k}: expected {v}, got {a[k]}" for k, v in KEEPALIVE_EXPECT.items() if a[k] != v]
    if a["b_delay_sec"] > LIMIT_SEC:
        reasons.append(f"b_delay_sec: expected <= {LIMIT_SEC}, got {a['b_delay_sec']}"
                       + (" (timeout)" if a["b_timed_out"] else ""))
        reasons.append(
            "근거: http_server.cpp는 단일 스레드로 serve_connection()에서 A의 recv()를 "
            "idle_timeout_sec(10초)까지 기다린 뒤에야 다음 accept()로 넘어감"
            + ("; B 응답 후 A 연결은 이미 끊김" if a["a_after_b"] is None else "")
            + ". README 7절 HTTP TODO에 '(필요 시) poll/epoll로 동시 연결 처리'로 남아 있음 "
            "→ 분류 후보: 명세상 미지원(동시 연결 미구현). "
            "원논문은 실제 서버(Apache 등)를 대상으로 해 동시 연결을 처리하므로 원논문 한계는 아님.")
    return reasons


# ---------------- 공통 실행 ----------------
CASES = [
    ("symlink", run_symlink, expect_symlink, check_symlink),
    ("keepalive", run_keepalive, expect_keepalive, check_keepalive),
]


def run_one(args, mode, name, runner, expect, checker):
    out_dir = os.path.join(args.out, mode, name)
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "defender.log")
    open(log_path, "w").close()

    exp = expect(mode)  # 실행 전 기대 결과 출력
    print(f"\n[{mode}] {name}\n  expected: {exp}")

    port = free_port()
    server = subprocess.Popen(
        [args.bin, "--mode", mode, "--port", str(port), "--root", args.root, "--log", log_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(port):
            raise RuntimeError("server did not start")
        actual = runner(port, log_path, args.root)
        reasons = checker(mode, actual)
    except Exception as e:
        actual, reasons = {"error": str(e)}, [f"error: {e}"]
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    passed = not reasons
    shown = {k: v for k, v in actual.items() if k != "raw"}
    print(f"  actual  : {shown}\n  result  : {'PASS' if passed else 'FAIL'}")
    for r in reasons:
        print(f"    - {r}")

    with open(os.path.join(out_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump({"mode": mode, "case": name, "passed": passed, "expected": exp,
                   "actual": actual, "reasons": reasons}, f, ensure_ascii=False, indent=2)
    return passed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(ROOT_DIR, "build", "honeypatch_server"))
    ap.add_argument("--root", default=os.path.join(ROOT_DIR, "www"))
    ap.add_argument("--out", default=os.path.join(ROOT_DIR, "results", "extra13"))
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    args = ap.parse_args()
    args.root = os.path.abspath(args.root)

    results = [run_one(args, m, *c) for m in args.modes for c in CASES]
    print(f"\n=== SUMMARY ===\nTotal: {len(results)}  PASS: {sum(results)}  "
          f"FAIL: {len(results) - sum(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
