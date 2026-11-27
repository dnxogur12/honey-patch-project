#!/usr/bin/env python3
"""13주차 추가 검증 사례 — 타이밍 채널 (원논문 6.2 한계 확인).

  T1 attack_vs_normal_timing : 허니패치 서버에서 공격 요청이 정상 요청보다 느린지(중앙값 비교)
                               → 공격 응답만 늦어지면 공격자가 시간만으로 Decoy를 눈치챌 수 있음
                                 (원논문 §7: 같은 서버에서 공격 응답이 정상 응답보다 늦어지는 것을 우려)

  python3 tests/run_timing_cases.py [--bin build/honeypatch_server] [--root www] [--rounds 10] [--n 30]
결과: results/extra13_timing/ (honeypatch/defender.log, result.json). 표준 라이브러리만 사용.

측정 방법
  - 허니패치 서버 하나에 공격·정상 요청을 번갈아 보냄 (시점 편향 최소화)
  - 요청마다 새 연결, Connection: close  → 허니패치 공격 1건 = Decoy 1개, 응답 후 Decoy 종료
  - 시간 = 요청 전송 직전 ~ 응답 전체 수신 (연결 수립 시간 제외)
  - 공격: ../secret.txt   정상: readme.txt (같은 /files 처리 경로, 비교 공정성)
  - 라운드마다 공격 중앙값과 정상 중앙값을 비교, 이를 여러 라운드 반복
  - 처음 몇 건은 워밍업으로 버림, 요청 사이 간격을 둬 Decoy가 종료·회수되게 함 (상한 16 회피)
"""
import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import time

from run_cases import SECRET_MARKER, count_forks, free_port, read_response, wait_ready

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODES = ["honeypatch"]

ATTACK = "/files?name=../secret.txt"
NORMAL = "/files?name=readme.txt"

# ==============================================================================
# 기대 결과 (실행 전에 작성)
# ==============================================================================
# 원논문 6.2/7: redaction 등으로 공격 응답이 정상 응답보다 늦어지는 타이밍 채널이 남는다고 인정.
#   - 측정 조건: 공격·정상 모두 200, 실제 비밀 노출 없음, Decoy 생성 수 = 공격 수(워밍업 포함)
#   - 판정: 라운드마다 공격 중앙값 > 정상 중앙값 이면 "느림"
#           "느림" 라운드가 전체의 90% 이상이면 → 공격 응답이 느리다 (타이밍 채널 존재, 한계 확인)
SLOW_RATIO_REQUIRED = 0.9


def timed_request(port, target):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        req = f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
        t0 = time.perf_counter()
        s.sendall(req)
        status, raw = read_response(s)
        elapsed_ms = (time.perf_counter() - t0) * 1000
    return status, raw, elapsed_ms


def main():
    ap = argparse.ArgumentParser()
    default_bin = os.path.join(ROOT_DIR, "build", "honeypatch_server")
    if not os.path.exists(default_bin):
        default_bin = os.path.join(ROOT_DIR, "build-local", "honeypatch_server")
    ap.add_argument("--bin", default=default_bin)
    ap.add_argument("--root", default=os.path.join(ROOT_DIR, "www"))
    ap.add_argument("--out", default=os.path.join(ROOT_DIR, "results", "extra13_timing"))
    ap.add_argument("--rounds", type=int, default=10, help="라운드 수")
    ap.add_argument("--n", type=int, default=30, help="라운드당 공격/정상 각각 측정 횟수")
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.02, help="요청 사이 간격(초)")
    args = ap.parse_args()

    print("[기대 결과 — 실행 전 작성]")
    print(f"  라운드 {args.rounds}회 x 공격/정상 각 {args.n}건 (허니패치 서버)")
    print("  측정 조건: 모든 응답 200, 실제 비밀 노출 없음, "
          f"Decoy 수 = {args.warmup + args.rounds * args.n}")
    print("  라운드 판정: 공격 중앙값 > 정상 중앙값 이면 '느림'")
    print(f"  최종: '느림' 라운드 >= {SLOW_RATIO_REQUIRED:.0%}  (원논문 6.2 타이밍 채널이 남는다고 예상)\n")

    servers, logs = {}, {}
    for mode in MODES:
        out_dir = os.path.join(args.out, mode)
        os.makedirs(out_dir, exist_ok=True)
        logs[mode] = os.path.join(out_dir, "defender.log")
        if os.path.exists(logs[mode]):
            os.remove(logs[mode])
        port = free_port()
        proc = subprocess.Popen(
            [args.bin, "--mode", mode, "--port", str(port), "--root", args.root, "--log", logs[mode]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        servers[mode] = (port, proc)

    statuses = {m: [] for m in MODES}
    leaked = False
    rounds = []   # 라운드별 {mode: {"attack": [...], "normal": [...]}}
    try:
        for mode in MODES:
            if not wait_ready(servers[mode][0]):
                raise RuntimeError(f"server did not start (mode={mode})")

        def one_pass(record):
            nonlocal leaked
            for mode in MODES:
                port = servers[mode][0]
                for kind, target in (("attack", ATTACK), ("normal", NORMAL)):
                    st, raw, ms = timed_request(port, target)
                    statuses[mode].append(st)
                    if mode == "honeypatch" and kind == "attack":
                        leaked = leaked or SECRET_MARKER in raw
                    if record is not None:
                        record[mode][kind].append(ms)
                    time.sleep(args.gap)

        for _ in range(args.warmup):
            one_pass(None)
        for r in range(args.rounds):
            rec = {m: {"attack": [], "normal": []} for m in MODES}
            for _ in range(args.n):
                one_pass(rec)
            rounds.append(rec)
        time.sleep(0.2)  # Decoy 로그 기록 대기
        forks = count_forks(logs["honeypatch"])
    finally:
        for _, proc in servers.values():
            proc.terminate()
            proc.wait()

    med = statistics.median
    print(f"{'round':>5} | {'공격':>8}{'정상':>8}{'차이':>8} | 판정   (ms)")
    slow = 0
    round_rows = []
    for i, rec in enumerate(rounds, 1):
        row = {}
        for mode in MODES:
            a, n = med(rec[mode]["attack"]), med(rec[mode]["normal"])
            row[mode] = {"attack": a, "normal": n, "diff": a - n}
        h = row["honeypatch"]
        is_slow = h["attack"] > h["normal"]
        slow += is_slow
        round_rows.append({**h, "slow": is_slow})
        print(f"{i:>5} | {h['attack']:8.3f}{h['normal']:8.3f}{h['diff']:+8.3f} | {'느림' if is_slow else '아님'}")

    overall = {}
    for mode in MODES:
        a = med([x for rec in rounds for x in rec[mode]["attack"]])
        n = med([x for rec in rounds for x in rec[mode]["normal"]])
        overall[mode] = {"attack": a, "normal": n, "diff": a - n}
    o = overall["honeypatch"]
    print(f"\n전체 중앙값  공격 {o['attack']:.3f} / 정상 {o['normal']:.3f} / 차이 {o['diff']:+.3f} ms"
          f" ({o['attack'] / o['normal']:.2f}배)\n")

    expected_forks = args.warmup + args.rounds * args.n
    checks = [
        ("기대: 응답 모두 200", all(s == 200 for s in statuses["honeypatch"]),
         f"{statuses['honeypatch'].count(200)}/{len(statuses['honeypatch'])}"),
        ("기대: 공격 응답에 실제 비밀 없음", not leaked, f"leaked={leaked}"),
        ("기대: Decoy 생성 수 = 공격 수", forks == expected_forks, f"{forks}/{expected_forks}"),
        (f"기대: '느림' 라운드 >= {SLOW_RATIO_REQUIRED:.0%}", slow >= SLOW_RATIO_REQUIRED * args.rounds,
         f"실제: {slow}/{args.rounds} 라운드 느림"),
    ]
    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({detail})")

    with open(os.path.join(args.out, "result.json"), "w", encoding="utf-8") as f:
        json.dump({"rounds": args.rounds, "n_per_round": args.n, "slow_rounds": slow,
                   "overall_median_ms": overall["honeypatch"],
                   "per_round": round_rows, "forks": forks,
                   "checks": {name: ok for name, ok, _ in checks}}, f, ensure_ascii=False, indent=2)

    passed = sum(ok for _, ok, _ in checks)
    print(f"\n=== SUMMARY ===\nTotal: {len(checks)}  PASS: {passed}  FAIL: {len(checks) - passed}")
    print(f"results: {args.out}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
