#!/usr/bin/env python3
"""[fork] fork() 실패 처리 검증 (Linux 전용)

  python3 tests/fork_failure_test.py               # 기본: build/honeypatch_server
  python3 tests/fork_failure_test.py --bin PATH

서버 코드에 테스트용 분기를 넣지 않고, 서버 프로세스의 RLIMIT_NPROC(프로세스 생성 한도)를 0으로
낮춰 커널이 실제로 fork()를 거부(EAGAIN)하게 만든다. 이후 한도를 원래대로 돌려 복구도 확인한다.

시나리오 (honeypatch 모드):
  1. fork가 막힌 상태에서 공격      → 403 (일반 패치로 대체), 비밀 미노출, Decoy 0개
  2. 같은 연결로 GET /public       → 200 (연결이 Main에 그대로 남아 있음)
  3. 새 연결 GET /public           → 200 (서버가 죽지 않음)
  4. 실패를 상한(16)보다 많이 반복  → 모두 403, 서버 생존
  5. 한도 복구 후 공격              → 200 (Decoy 정상 생성 = 실패가 세션 표 칸을 차지하지 않음)
root로 실행하면 RLIMIT_NPROC이 무시되어 fork가 막히지 않으므로 일반 사용자로 실행할 것.
표준 라이브러리만 사용.
"""
import argparse
import os
import resource
import socket
import subprocess
import sys
import tempfile
import time

ATTACK = "/files?name=../secret.txt"
SECRET_MARKER = "REAL_SECRET"


def send(sock, target):
    """(status, body) 반환"""
    sock.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, ""
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
    return int(head.split(b" ")[1]), body.decode(errors="replace")


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=5)


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

    if os.geteuid() == 0:
        print("SKIP  root는 RLIMIT_NPROC을 무시하므로 fork 실패를 만들 수 없음. 일반 사용자로 실행할 것.")
        return 0

    orig_nproc = resource.getrlimit(resource.RLIMIT_NPROC)

    def block_fork():
        # 서버 프로세스에서만 soft 한도를 0으로. hard는 그대로 두어 나중에 바깥에서 복구할 수 있게 함
        resource.setrlimit(resource.RLIMIT_NPROC, (0, orig_nproc[1]))

    port = free_port()
    log_path = os.path.join(tempfile.mkdtemp(prefix="fork_failure_"), "defender.log")
    server = subprocess.Popen(
        [args.bin, "--mode", "honeypatch", "--port", str(port), "--root", args.root, "--log", log_path],
        stderr=subprocess.DEVNULL,
        preexec_fn=block_fork,
    )
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    try:
        time.sleep(0.3)

        # 1. fork 실패 → 403 대체
        s = connect(port)
        st, body = send(s, ATTACK)
        check("fork 막힘 + 공격 → 403", st == 403, f"status={st}")
        check("비밀 미노출", SECRET_MARKER not in body)
        check("로그에 'fork failed' 기록", count(log_path, "fork failed") == 1)
        check("Decoy 생성 0개", count(log_path, "decoy child started") == 0)

        # 2. 연결이 Main에 남아 있으므로 같은 연결로 계속 응답
        st, _ = send(s, "/public")
        check("같은 연결 GET /public → 200 (연결 유지)", st == 200, f"status={st}")
        s.close()

        # 3. 서버 생존
        s = connect(port)
        st, _ = send(s, "/public")
        check("새 연결 GET /public → 200 (서버 생존)", st == 200, f"status={st}")
        s.close()

        # 4. 상한보다 많이 실패시켜도 문제 없음
        n = args.limit + 4
        results = []
        for _ in range(n):
            s = connect(port)
            results.append(send(s, ATTACK)[0])
            s.close()
        check(f"실패 {n}회 반복 → 모두 403", all(r == 403 for r in results), f"{results.count(403)}/{n}")
        check("서버 프로세스 살아 있음", server.poll() is None)

        # 5. 한도 복구 → 다시 Decoy 생성 (실패한 시도가 세션 표 칸을 차지하지 않았는지)
        resource.prlimit(server.pid, resource.RLIMIT_NPROC, orig_nproc)
        s = connect(port)
        st, body = send(s, ATTACK)
        check("한도 복구 후 공격 → 200 (Decoy 정상)", st == 200 and SECRET_MARKER not in body, f"status={st}")
        s.close()
        check("Decoy 생성 1개", count(log_path, "decoy child started") == 1)
    finally:
        server.terminate()
        server.wait()

    print(f"\n{sum(checks)}/{len(checks)} passed   (log: {log_path})")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
