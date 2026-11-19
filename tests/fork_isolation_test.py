#!/usr/bin/env python3
"""[fork] Decoy 격리(setrlimit · no_new_privs) 검증 (Linux 전용, /proc 사용)

  python3 tests/fork_isolation_test.py               # 기본: build/honeypatch_server
  python3 tests/fork_isolation_test.py --bin PATH

공격 연결을 하나 열어 Decoy를 띄운 뒤, 살아 있는 Decoy의 /proc/<pid>/limits·status를 읽어
hp_fork.cpp의 kDecoyLimits가 실제로 적용됐는지, 부모(Main)에는 영향이 없는지 확인한다.
표준 라이브러리만 사용.
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

ATTACK = "/files?name=../secret.txt"

# /proc/<pid>/limits 의 항목 이름 → 기대값 (hp_fork.cpp kDecoyLimits와 맞출 것)
EXPECT_LIMITS = {
    "Max cpu time": "5",
    "Max address space": str(256 * 1024 * 1024),
    "Max open files": "16",
    "Max processes": "0",
    "Max core file size": "0",
}


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


def read_limits(pid):
    """{'Max cpu time': ('5', '5'), ...}  (soft, hard)"""
    out = {}
    with open(f"/proc/{pid}/limits") as f:
        next(f)  # 헤더
        for line in f:
            m = re.match(r"(.+?)\s{2,}(\S+)\s+(\S+)", line)
            if m:
                out[m.group(1).strip()] = (m.group(2), m.group(3))
    return out


def no_new_privs(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("NoNewPrivs:"):
                return line.split()[1] == "1"
    return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(root_dir, "build", "honeypatch_server"))
    ap.add_argument("--root", default=os.path.join(root_dir, "www"))
    args = ap.parse_args()

    port = free_port()
    log_path = os.path.join(tempfile.mkdtemp(prefix="fork_isolation_"), "defender.log")
    server = subprocess.Popen(
        [args.bin, "--mode", "honeypatch", "--port", str(port), "--root", args.root, "--log", log_path],
        stderr=subprocess.DEVNULL,
    )
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    sock = None
    try:
        time.sleep(0.3)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        check("공격 → 200 (Decoy 응답)", send(sock, ATTACK) == 200)

        with open(log_path, encoding="utf-8", errors="replace") as f:
            log = f.read()
        m = re.search(r"\[pid=(\d+)\] \[FORK\] conn=\d+ decoy child started", log)
        if not m:
            check("Decoy pid 찾기", False)
            return 1
        decoy = int(m.group(1))
        check("격리 적용 로그", "decoy isolation:" in log)

        limits = read_limits(decoy)
        for name, want in EXPECT_LIMITS.items():
            got = limits.get(name)
            check(f"Decoy {name} = {want}", got == (want, want), f"soft/hard={got}")
        check("Decoy NoNewPrivs = 1", no_new_privs(decoy))

        # 부모(Main)는 그대로여야 함
        main_limits = read_limits(server.pid)
        check("Main 'Max processes'는 제한 없음", main_limits.get("Max processes", ("0",))[0] != "0",
              f"{main_limits.get('Max processes')}")
        check("Main NoNewPrivs = 0", not no_new_privs(server.pid))

        # 제한이 걸린 Decoy도 정상 요청을 계속 처리할 수 있어야 함 (파일 열기 등)
        check("제한된 Decoy가 같은 연결의 GET /public 처리 → 200", send(sock, "/public") == 200)
    finally:
        if sock:
            sock.close()
        server.terminate()
        server.wait()

    print(f"\n{sum(checks)}/{len(checks)} passed   (log: {log_path})")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
