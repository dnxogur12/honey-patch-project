#!/usr/bin/env python3
"""13주차 추가 검증 사례 — 공격 성공 후 이미 아는 공개 파일을 경로 탈출로 다시 요청.

공격자는 /public 페이지와 readme.txt 내용을 이미 볼 수 있다. 경로 탈출이 된다고 믿으면,
웹 폴더 구조를 파악하려고 "내용을 이미 아는 파일"을 경로 탈출로 다시 열어 본다.
같은 파일이라면 정상 경로와 경로 탈출 경로의 응답이 같아야 한다 (공격자 혼자 확인 가능한 일관성).

같은 Keep-Alive 연결에서 순서대로:
  P1 attack          ../secret.txt                 공격 성공 (허니패치: 여기서 Decoy 진입)
  P2 page_normal     /public                       메인 페이지 (정상 경로) — 기준 내용
  P3 page_traversal  ../public/index.html          같은 페이지를 경로 탈출로
  P4 readme_normal   /files?name=readme.txt        공개 파일 (정상 경로) — 기준 내용
  P5 readme_detour   ../../www/files/readme.txt    같은 파일을 웹 폴더 이름까지 거쳐서

  python3 tests/run_public_file_consistency_cases.py [--bin build/honeypatch_server] [--root www]
결과: results/extra13_public/<mode>/ (defender.log, result.json). 표준 라이브러리만 사용.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

from run_cases import SECRET_MARKER, count_forks, free_port, request, wait_ready

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODES = ["unpatched", "patched", "honeypatch"]

STEPS = [
    ("P1 attack",         "/files?name=../secret.txt"),
    ("P2 page_normal",    "/public"),
    ("P3 page_traversal", "/files?name=../public/index.html"),
    ("P4 readme_normal",  "/files?name=readme.txt"),
    ("P5 readme_detour",  "/files?name=../../www/files/readme.txt"),
]
PAIRS = [("P3 page_traversal", "P2 page_normal"), ("P5 readme_detour", "P4 readme_normal")]

# ==============================================================================
# 기대 결과 (실행 전에 작성)
# ==============================================================================
# (단계별 status, 실제 비밀 노출, 세션 fork 수)
#   P3, P5는 www/ 안의 공개 파일을 가리킴 → 취약한 서버라면 200
#   P3, P5는 정규화하면 files/ 밖 → 일반 패치는 403
EXPECT = {
    "unpatched":  ([200, 200, 200, 200, 200], True,  0),
    "patched":    ([403, 200, 403, 200, 403], False, 0),
    "honeypatch": ([200, 200, 200, 200, 200], False, 1),
}
# 추가 조건: 경로 탈출 응답이 200이면 본문이 정상 경로 응답과 같아야 함
#   (unpatched, honeypatch: P3 == P2, P5 == P4)
SAME_BODY_MODES = {"unpatched", "honeypatch"}


def body_of(raw):
    return raw.partition("\r\n\r\n")[2] if raw else ""


def run_mode(args, mode):
    out_dir = os.path.join(args.out, mode)
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "defender.log")
    if os.path.exists(log_path):
        os.remove(log_path)
    port = free_port()
    proc = subprocess.Popen(
        [args.bin, "--mode", mode, "--port", str(port), "--root", args.root, "--log", log_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {}
    leaked = False
    try:
        if not wait_ready(port):
            raise RuntimeError(f"server did not start (mode={mode})")
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            for i, (name, target) in enumerate(STEPS):
                try:
                    st, raw = request(s, target, keep_alive=i < len(STEPS) - 1)
                except OSError:
                    st, raw = None, ""
                res[name] = {"status": st, "body": body_of(raw)}
                leaked = leaked or SECRET_MARKER in raw
        time.sleep(0.2)  # Decoy 로그 기록 대기
    finally:
        proc.terminate()
        proc.wait()
    return res, leaked, count_forks(log_path)


def main():
    ap = argparse.ArgumentParser()
    default_bin = os.path.join(ROOT_DIR, "build", "honeypatch_server")
    if not os.path.exists(default_bin):
        default_bin = os.path.join(ROOT_DIR, "build-local", "honeypatch_server")
    ap.add_argument("--bin", default=default_bin)
    ap.add_argument("--root", default=os.path.join(ROOT_DIR, "www"))
    ap.add_argument("--out", default=os.path.join(ROOT_DIR, "results", "extra13_public"))
    args = ap.parse_args()

    print("[기대 결과 — 실행 전 작성]  (단계별 status, 실제 비밀 노출, fork 수)")
    for mode in MODES:
        print(f"  {mode:10} {EXPECT[mode]}")
    print("  + unpatched/honeypatch: P3 본문 == P2 본문, P5 본문 == P4 본문\n")

    total = passed = 0
    for mode in MODES:
        res, leaked, forks = run_mode(args, mode)
        exp_st, exp_leak, exp_forks = EXPECT[mode]
        print(f"[{mode}]")
        for (name, target), e in zip(STEPS, exp_st):
            g = res[name]["status"]
            ok = e == g
            total += 1
            passed += ok
            print(f"  {'PASS' if ok else 'FAIL'}  {name:18} {target:40} expected {e}  actual {g}")
        if mode in SAME_BODY_MODES:
            for a, b in PAIRS:
                ok = res[a]["body"] == res[b]["body"]
                total += 1
                passed += ok
                print(f"  {'PASS' if ok else 'FAIL'}  본문 {a.split()[0]} == {b.split()[0]}"
                      f"  ({len(res[a]['body'])} vs {len(res[b]['body'])} bytes)")
        for label, e, g in (("실제 비밀 노출", exp_leak, leaked), ("세션 fork 수", exp_forks, forks)):
            ok = e == g
            total += 1
            passed += ok
            print(f"  {'PASS' if ok else 'FAIL'}  {label:18} expected {e}  actual {g}")
        print()
        with open(os.path.join(args.out, mode, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"expected": {"statuses": exp_st, "leaked": exp_leak, "forks": exp_forks},
                       "actual": {"statuses": [res[n]["status"] for n, _ in STEPS],
                                  "leaked": leaked, "forks": forks}},
                      f, ensure_ascii=False, indent=2)

    print(f"=== SUMMARY ===\nTotal: {total}  PASS: {passed}  FAIL: {total - passed}")
    print(f"results: {args.out}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
