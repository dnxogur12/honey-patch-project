#!/usr/bin/env python3
"""11주차 고정 검증 사례 3종을 3개 모드(미패치/일반패치/허니패치)로 실행하고 비교표를 출력한다.

  python3 tests/run_cases.py                      # 기본: build/honeypatch_server, www/
  python3 tests/run_cases.py --modes honeypatch   # 특정 모드만

결과 저장 (results/<mode>/):
  defender.log      방어자 내부 로그 (서버 --log)
  <case>.txt        공격자(클라이언트)가 실제 받은 응답 원문
표준 라이브러리만 사용. raw socket으로 전송하므로 클라이언트 측 경로 정규화가 일어나지 않는다.
"""
import argparse
import os
import socket
import subprocess
import sys
import time

SECRET_MARKER = "REAL_SECRET"  # www/secret.txt 의 실제 비밀 표식

# 11주차 보고서 고정 사례 (변경 금지)
CASES = [
    ("normal",   "/public"),
    ("violation", "/files?name=../secret.txt"),
    ("boundary", "/files?name=..%2Fsecret.txt"),
]

# 판정 기준 (12주차: 모호한 기대 결과를 코드·출력값 기준으로 구체화)
#   status : 첫 응답 상태코드
#   leaked : 응답 본문에 REAL_SECRET 포함 여부
#   forks  : 이 사례 동안 생성된 Decoy 자식 수 (defender.log의 'decoy child started' 줄 수)
EXPECT = {
    "unpatched":  {"normal": (200, False, 0), "violation": (200, True, 0),  "boundary": (200, True, 0)},
    "patched":    {"normal": (200, False, 0), "violation": (403, False, 0), "boundary": (403, False, 0)},
    "honeypatch": {"normal": (200, False, 0), "violation": (200, False, 1), "boundary": (200, False, 1)},
}


def request(sock, target, keep_alive=True):
    conn = "keep-alive" if keep_alive else "close"
    sock.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: {conn}\r\n\r\n".encode())
    return read_response(sock)


def read_response(sock):
    """(status, raw_text) 반환. Content-Length 기반이라 Keep-Alive 연결에서도 동작."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, buf.decode(errors="replace")
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
    status = int(head.split(b" ")[1])
    return status, (head + b"\r\n\r\n" + body).decode(errors="replace")


def count_forks(log_path):
    if not os.path.exists(log_path):
        return 0
    with open(log_path, encoding="utf-8", errors="replace") as f:
        return sum("decoy child started" in line for line in f)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_ready(port, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def run_case(port, target, log_path):
    """사례 1건: 첫 요청 + 같은 연결의 Keep-Alive 후속 요청 2건(정상, 동일 공격 재시도)."""
    forks_before = count_forks(log_path)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        status, raw = request(s, target)
        follow = []
        for t in ("/public", target):  # 후속 요청: 연결 유지 + 중복 fork 여부 점검
            try:
                st, _ = request(s, t)
            except OSError:
                st = None
            follow.append(st)
    time.sleep(0.1)  # Decoy 자식의 로그 기록 대기
    # 공격 연결 처리 중에도 Main이 새 연결을 정상 처리하는지 (정상 사용자 영향 점검)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s2:
        main_ok, _ = request(s2, "/public", keep_alive=False)
    return {
        "status": status,
        "leaked": SECRET_MARKER in raw,
        "forks": count_forks(log_path) - forks_before,
        "follow": follow,
        "main_ok": main_ok,
        "raw": raw,
    }


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
    rows = []
    try:
        if not wait_ready(port):
            raise RuntimeError(f"server did not start (mode={mode})")
        for name, target in CASES:
            r = run_case(port, target, log_path)
            with open(os.path.join(out_dir, f"{name}.txt"), "w", encoding="utf-8") as f:
                f.write(f"> GET {target}\n\n{r['raw']}\n")
            exp_status, exp_leak, exp_forks = EXPECT[mode][name]
            ok = (r["status"], r["leaked"], r["forks"]) == (exp_status, exp_leak, exp_forks)
            ok = ok and r["main_ok"] == 200 and all(st is not None for st in r["follow"])
            rows.append((mode, name, r, ok))
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    return rows


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(root_dir, "build", "honeypatch_server"))
    ap.add_argument("--root", default=os.path.join(root_dir, "www"))
    ap.add_argument("--out", default=os.path.join(root_dir, "results"))
    ap.add_argument("--modes", nargs="+", default=list(EXPECT), choices=list(EXPECT))
    args = ap.parse_args()

    rows = []
    for mode in args.modes:
        rows += run_mode(args, mode)

    print(f"{'mode':<11} {'case':<10} {'status':>6} {'leaked':>7} {'forks':>6} "
          f"{'follow-up':>10} {'main':>5}  result")
    print("-" * 70)
    for mode, name, r, ok in rows:
        follow = "/".join(str(s) for s in r["follow"])
        print(f"{mode:<11} {name:<10} {r['status']!s:>6} {('YES' if r['leaked'] else 'no'):>7} "
              f"{r['forks']:>6} {follow:>10} {r['main_ok']!s:>5}  {'PASS' if ok else 'FAIL'}")
    print(f"\nresponses & defender logs saved under: {args.out}")
    return 0 if all(ok for *_, ok in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
