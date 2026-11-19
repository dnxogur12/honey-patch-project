#!/usr/bin/env python3
"""[fork] 동시 Decoy 수 제한 검증 (고정 사례 3종과 별도 테스트)

  python3 tests/fork_limit_test.py                 # 기본: build/honeypatch_server, 상한 16
  python3 tests/fork_limit_test.py --bin PATH --limit N

시나리오 (honeypatch 모드):
  1. 공격 연결 LIMIT개를 열어 둔 채 유지   → 모두 200 (Decoy LIMIT개 생존)
  2. 공격 연결 2개 추가                    → 403 (상한 초과, fork 없음)
  3. 그동안 새 연결의 GET /public          → 200 (Main 프로세스 정상)
  4. 공격 연결 1개를 닫고 Decoy 종료 대기  → 로그에 'ended' 기록
  5. 공격 연결 1개 추가                    → 다시 200 (빈 칸 재사용)
표준 라이브러리만 사용.
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time

ATTACK = "/files?name=../secret.txt"


def send(sock, target):
    sock.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v.strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return int(head.split(b" ")[1])


def connect(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    return s


def count(log_path, needle):
    with open(log_path, encoding="utf-8", errors="replace") as f:
        return sum(needle in line for line in f)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(root_dir, "build", "honeypatch_server"))
    ap.add_argument("--root", default=os.path.join(root_dir, "www"))
    ap.add_argument("--limit", type=int, default=16, help="hp_fork.cpp의 kMaxConcurrentDecoys")
    args = ap.parse_args()

    port = free_port()
    log_path = os.path.join(tempfile.mkdtemp(prefix="fork_limit_"), "defender.log")
    server = subprocess.Popen(
        [args.bin, "--mode", "honeypatch", "--port", str(port), "--root", args.root, "--log", log_path],
        stderr=subprocess.DEVNULL,
    )
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    held = []
    try:
        time.sleep(0.3)

        # 1. 상한까지 공격 연결 유지
        statuses = []
        for _ in range(args.limit):
            s = connect(port)
            statuses.append(send(s, ATTACK))
            held.append(s)
        check(f"공격 {args.limit}개 → 모두 200", all(st == 200 for st in statuses), f"{statuses.count(200)}/{args.limit}")

        # 2. 상한 초과
        over = []
        for _ in range(2):
            s = connect(port)
            over.append(send(s, ATTACK))
            s.close()
        check("상한 초과 공격 2개 → 403", over == [403, 403], str(over))
        check("상한 초과 시 로그 기록", count(log_path, "decoy limit reached") == 2)
        check(f"생성된 Decoy 수 = {args.limit}", count(log_path, "decoy child started") == args.limit)

        # 3. 정상 사용자 영향 없음
        s = connect(port)
        check("새 연결 GET /public → 200 (Main 정상)", send(s, "/public") == 200)
        s.close()

        # 4. 공격 연결 하나 종료 → Decoy 종료 기록
        held.pop().close()
        deadline = time.time() + 3
        while time.time() < deadline and count(log_path, "ended:") < 1:
            time.sleep(0.05)
        check("Decoy 종료 시 'ended' 로그", count(log_path, "ended:") >= 1)

        # 5. 빈 칸 재사용
        s = connect(port)
        check("빈 칸 생긴 뒤 공격 → 다시 200", send(s, ATTACK) == 200)
        held.append(s)
    finally:
        for s in held:
            s.close()
        server.terminate()
        server.wait()

    print(f"\n{sum(checks)}/{len(checks)} passed   (log: {log_path})")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
