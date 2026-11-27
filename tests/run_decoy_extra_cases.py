#!/usr/bin/env python3
"""13주차 Decoy 추가 검증: 외부 데이터 로딩 및 항목 누락."""

from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import sys

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "build" / "honeypatch_server"
ATTACK = "/files?name=../secret.txt"

REAL_MARKER = "REAL_SECRET"
CUSTOM_MARKER = "DECOY_UNIQUE_TEST_2026"
FALLBACK_MARKER = "CNU{w3lc0me_t0_th3_s3rv3r}"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(
            f"GET {ATTACK} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", errors="replace")


def run_case(name, honey_text, expected):
    with tempfile.TemporaryDirectory(prefix="hp_decoy_") as tmp:
        root = Path(tmp)
        (root / "www" / "decoy").mkdir(parents=True)
        shutil.copy2(ROOT / "www" / "secret.txt", root / "www" / "secret.txt")
        (root / "www" / "public").mkdir(parents=True, exist_ok=True)
        (root / "www" / "decoy" / "honey_data.txt").write_text(
            honey_text, encoding="utf-8"
        )

        port = free_port()
        proc = subprocess.Popen(
            [
                str(SERVER),
                "--mode", "honeypatch",
                "--port", str(port),
                "--root", str(root / "www"),
            ],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(60):
                if proc.poll() is not None:
                    raise RuntimeError("Server exited unexpectedly")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Server startup timeout")

            raw = request(port)
            status_ok = raw.startswith("HTTP/1.1 200")
            marker_ok = expected in raw
            secret_safe = REAL_MARKER not in raw
            ok = status_ok and marker_ok and secret_safe

            print(
                f"{name}: {'PASS' if ok else 'FAIL'} "
                f"(status={status_ok}, expected={marker_ok}, "
                f"no_real_secret={secret_safe})"
            )
            if not ok:
                print(raw[:1000])
            return ok
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def main():
    if not SERVER.is_file():
        print(f"Server executable not found: {SERVER}")
        return 1

    normal_data = (
        "[secret.txt]\n"
        "# TEST SECRET - decoy honey data\n"
        f"FLAG={CUSTOM_MARKER}\n"
        "db_user=test_admin\n"
        "db_password=test_password\n"
        "[admin_token]\n"
        "test-token-123\n"
    )
    missing_entry_data = (
        "[admin_token]\n"
        "test-token-123\n"
    )

    results = [
        run_case("normal_external_honey_data", normal_data, CUSTOM_MARKER),
        run_case("boundary_missing_secret_entry", missing_entry_data, FALLBACK_MARKER),
    ]
    print(f"\nTotal: {sum(results)}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
