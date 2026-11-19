# Honey-Patch 프로토타입 (7조) — 공통 베이스라인

실패한 공격을 거부하지 않고 `fork()`로 만든 **Decoy 자식 프로세스**로 넘겨, 민감정보를 가짜 값으로 바꾼 뒤
**공격이 성공한 것처럼 응답**하는 C++ HTTP 서버입니다. (논문: *From Patches to Honey-Patches*, Araujo et al., CCS 2014)

이 저장소는 **팀원들이 병렬로 개발하기 위한 공통 코드베이스**입니다. 입력부터 응답까지의 최소 실행 흐름은 동작하며,
고도화할 부분은 각 모듈의 `TODO(모듈명)` 주석으로 남겨 두었습니다.

---

## 1. 실행 환경

| 항목 | 확인한 버전 |
|---|---|
| OS | Ubuntu 22.04 (WSL2) |
| 컴파일러 | g++ 11.4 (C++17) |
| 빌드 | CMake ≥ 3.16 |
| 테스트 | Python 3.8 이상 (표준 라이브러리만 사용) |

```bash
sudo apt install -y build-essential cmake python3 curl
```

## 2. 빌드 · 실행 · 테스트

모든 명령은 **저장소 루트**에서 실행합니다 (데이터 경로 `www/`는 상대 경로).

```bash
# 빌드
cmake -S . -B build
cmake --build build -j

# 테스트 (단위 테스트 + 고정 검증 사례 3종 × 3모드)
./build/unit_tests
python3 tests/run_cases.py          # 또는: (cd build && ctest --output-on-failure)
python3 tests/fork_limit_test.py    # [fork] 동시 Decoy 수 제한 (상한 16) 검증

# 서버 직접 실행
./build/honeypatch_server --mode honeypatch --port 8080   # unpatched | patched | honeypatch
```

다른 터미널에서 수동 확인:

```bash
curl -v 'http://127.0.0.1:8080/public'                       # 정상
curl -v 'http://127.0.0.1:8080/files?name=../secret.txt'     # 위반
curl -v 'http://127.0.0.1:8080/files?name=..%2Fsecret.txt'   # 경계
```

서버 옵션: `--mode`, `--port`, `--root DIR`(기본 `www`), `--bind ADDR`(기본 `127.0.0.1`), `--log FILE`.
방어자 로그는 stderr에 출력되고, `--log`를 주면 파일에도 저장됩니다.

## 3. 프로젝트 구조

```
CMakeLists.txt
src/
  common/types.h          ← 모듈 간 공통 데이터 타입 (팀 합의 후에만 수정)
  common/logger.{h,cpp}   ← 방어자 내부 로그 (fork-safe, write(2) 사용)
  http/http_parser.*      ← [HTTP]   요청 파싱, URL 디코딩, 응답 직렬화
  http/http_server.*      ← [HTTP]   소켓 listen/accept, Keep-Alive 연결 루프
  detect/detector.*       ← [탐지]   패치 지점 입력 검사 (경로 탐색 판정)
  hpfork/hp_fork.*        ← [fork]   Decoy 자식 분기, 부모·자식 FD 정리
  decoy/redaction.*       ← [Decoy]  민감정보 소거·가짜 값 대체
  decoy/decoy_response.*  ← [Decoy]  공격 성공 위장 응답
  app/app.*               ← [통합]   모의 취약 앱 + 패치 지점 (모듈 연결)
  main.cpp                ← 인자 파싱 → 초기화 → 서버 실행
tests/
  unit_tests.cpp          ← 모듈별 단위 테스트 (소켓·fork 없음)
  run_cases.py            ← 고정 사례 3종 × 3모드 실행, 비교표 출력
www/
  public/index.html       ← GET /public
  files/readme.txt        ← GET /files?name=readme.txt
  secret.txt              ← 테스트용 비밀 (마커: REAL_SECRET) — files/ 밖에 위치
results/                  ← run_cases.py 출력 (git 제외)
```

모듈 의존 방향 (CMake에서 라이브러리 단위로 강제):

```
common  ←  http · detect · hpfork · decoy  ←  app  ←  main
```

`http`, `detect`, `hpfork`, `decoy`는 **서로를 include하지 않습니다.** `common/types.h`의 타입으로만 연결되고,
네 모듈을 묶는 곳은 `app/app.cpp` 한 곳입니다. 그래서 담당자끼리 같은 파일을 동시에 수정할 일이 없습니다.

## 4. 데이터 흐름

```
 client ──TCP──▶ [HTTP] run_server: accept → serve_connection (Keep-Alive 루프)
                     │ recv → parse_request → HttpRequest (쿼리는 URL 디코딩 완료)
                     ▼
                 [App] App::handle ── /public ──────────────────────────▶ 200 정상 응답
                     │ /files?name=X
                     ▼
            ┌── 패치 지점 ── [탐지] inspect_file_name(X) ──┐
            │ 정상                                         │ 공격
            ▼                                               ▼
   원래 코드: www/files/X 읽기            unpatched : (검사 자체가 없음 → 비밀 노출)
                                         patched   : 403 forbidden
                                         honeypatch: [fork] fork_decoy(ctx)
                                           ├ Parent : client_fd close, handed_off=true
                                           │          → 응답 없이 accept 루프로 복귀
                                           └ Child  : listen_fd close, role=Decoy
                                                      [Decoy] redact(secrets)
                                                      [Decoy] fake_success → 200 가짜 응답
                                                      같은 소켓으로 후속 요청 계속 처리
                                                      (재탐지 시 AlreadyDecoy → 재분기 없음)
                                                      연결 종료 시 _exit(0)
```

### 모듈 인터페이스 요약

| 모듈 | 함수 | 입력 → 출력 |
|---|---|---|
| HTTP | `http::parse_request(raw, out, err)` | 요청 헤더 블록 → `HttpRequest` |
| HTTP | `http::url_decode(s, plus_as_space)` | `"..%2Fsecret.txt"` → `"../secret.txt"` |
| HTTP | `http::serialize_response(resp, keep_alive)` | `HttpResponse` → 응답 바이트열 |
| HTTP | `http::run_server(cfg, handler)` | `Handler = HttpResponse(const HttpRequest&, ConnContext&)` |
| 탐지 | `detect::inspect_file_name(name)` | 디코딩된 파일명 → `DetectResult{is_attack, reason}` |
| fork | `hpfork::init()` | 서버 시작 시 1회 (hp_init 대응) |
| fork | `hpfork::fork_decoy(ctx)` | `ConnContext&` → `Parent / Child / AlreadyDecoy / Failed` (hp_fork 대응) |
| Decoy | `decoy::redact(store)` | `SecretStore&`를 직접 수정 (소거 후 가짜 값) |
| Decoy | `decoy::fake_success(req, store)` | 공격 요청 + 소거된 저장소 → 가짜 성공 `HttpResponse` (hp_skip 대응) |

**규약**
- `ConnContext`의 `client_fd`, `listen_fd`, `role`, `handed_off`는 fork 모듈만 변경합니다.
- `DetectResult::reason`과 방어자 로그는 공격자 응답에 절대 넣지 않습니다. 응답 헤더와 본문도 모드와 관계없이 같은 형식이어야 합니다.
- 서버는 **단일 스레드**를 유지합니다. 스레드가 있는 프로세스에서 `fork()`하면 호출한 스레드만 복제되어 락과 상태가 깨질 수 있습니다.
- 로그는 `logger::write()`만 사용합니다. `printf`처럼 stdio 버퍼를 쓰면 fork 후 같은 로그가 두 번 출력됩니다.
- 시그널 핸들러 안에서는 `logger::write_signal_safe()`만 사용합니다. 이 함수 안에서 `std::string`, `malloc`, `localtime`을 쓰지 않습니다 (핸들러가 malloc 도중에 끼어들면 서버가 멈추거나 힙이 깨짐).

## 5. 검증 사례 (11주차 고정 사례 유지) 와 판정 기준

| 구분 | 입력 | 기대 결과 (11주차) | 코드·출력 기준 판정 (12주차 구체화) |
|---|---|---|---|
| 정상 | `GET /public` | 정상 콘텐츠 반환, 공격 처리용 fork() 없음 | status=200, 로그의 `decoy child started` 0건 |
| 위반 | `GET /files?name=../secret.txt` | fork()로 자식 생성, Redaction 후 기존 TCP 연결로 성공 위장 응답, 실제 비밀 미노출 | status=200, 본문에 `REAL_SECRET` 없음, fork 1건, 같은 연결의 후속 요청 2건 응답, 동일 공격 재시도 시 추가 fork 없음 |
| 경계 | `GET /files?name=..%2Fsecret.txt` | URL 디코딩 후 경로 탐색으로 판정, 위반과 동일하게 Decoy 분기 | 위반과 동일 |

추가 점검(모든 사례): 공격 연결을 처리하는 동안 **새 연결의 `GET /public`에 Main 프로세스가 200을 응답하는지**(정상 사용자 영향).

### 모드별 실행 결과 (`python3 tests/run_cases.py`, 2026-11-17 베이스라인)

```
mode        case       status  leaked  forks  follow-up  main  result
----------------------------------------------------------------------
unpatched   normal        200      no      0    200/200   200  PASS
unpatched   violation     200     YES      0    200/200   200  PASS
unpatched   boundary      200     YES      0    200/200   200  PASS
patched     normal        200      no      0    200/200   200  PASS
patched     violation     403      no      0    200/403   200  PASS
patched     boundary      403      no      0    200/403   200  PASS
honeypatch  normal        200      no      0    200/200   200  PASS
honeypatch  violation     200      no      1    200/200   200  PASS
honeypatch  boundary      200      no      1    200/200   200  PASS
```

- `leaked`: 응답에 실제 비밀 포함 여부. `forks`: 생성된 Decoy 수. `follow-up`: 같은 연결의 후속 요청(`/public`, 동일 공격 재시도) 상태코드. `main`: 새 연결 정상 처리 여부.
- 보호 적용 전(unpatched)에는 비밀이 노출되고, 일반 패치(patched)는 403으로 **거부 사실을 드러냅니다.** 허니패치는 200 가짜 응답을 보내며 실제 비밀은 0건 노출됩니다.
- 공격자가 받은 응답 원문은 `results/<mode>/<case>.txt`, 방어자 로그는 `results/<mode>/defender.log`에 저장됩니다. 로그에서 공격 이후 요청들이 자식 pid로 처리된 것을 확인할 수 있습니다.

## 6. 원논문과 다른 부분

| 항목 | 원논문 | 본 구현 | 비고 |
|---|---|---|---|
| 세션 복제 | CRIU로 프로세스 체크포인트 → LXC Decoy 컨테이너에서 복원 | 단일 호스트 `fork()` | 학부 실습 환경에 맞춘 경량화 (11주차 결정) |
| 연결 전환 | 프록시를 통한 연결 전환 | 자식이 TCP 소켓 FD를 상속해 같은 연결 유지 | 부모는 FD를 닫고 다음 연결 처리 |
| 격리 | 컨테이너 단위 격리 (파일시스템 등 분리) | **격리 없음.** 같은 사용자 권한과 파일시스템을 공유하고, `alarm()` 수명 제한만 둠 | Decoy에서 탐지를 우회하면 실제 파일을 읽을 수 있음 → 한계로 기록 |
| Redaction 범위 | 복제된 프로세스 메모리의 민감정보를 가짜 데이터로 대체 | `SecretStore`에 지정한 항목만 소거·대체 | 힙에 남은 이전 사본은 지우지 못함 |
| API | `hp_init` / `hp_fork` / `hp_skip` 라이브러리 | 개념만 대응: `hpfork::init`, `hpfork::fork_decoy`, `decoy::fake_success` | 기존 구현을 가져오지 않고 직접 작성 |
| 대상 서버·취약점 | 실제 서버 소프트웨어의 실제 취약점 패치 | 직접 작성한 소형 HTTP 서버의 모의 경로 탐색 취약점 | |
| 공격자 감시 | Decoy 안의 공격자 행위 관찰 | 방어자 로그(요청·판정·분기·소거)만 기록 | |

> 위 원논문 항목은 개념 수준의 요약입니다. 보고서에 쓸 때는 원문의 해당 절과 그림을 직접 대조해 보완해 주세요.

## 7. 담당 분배 (제안) 와 TODO

각 담당자는 자기 모듈 파일과 `tests/unit_tests.cpp`의 해당 섹션만 수정합니다.
`grep -rn "TODO(" src tests`로 전체 목록을 볼 수 있습니다.

| 담당 | 파일 | 남은 작업 |
|---|---|---|
| **A. HTTP** | `src/http/*` | Content-Length 본문 처리(POST), 중복 쿼리 파라미터 정책, 헤더 상한·잘못된 요청 경계 사례 테스트, (필요 시) 단일 스레드 유지한 채 poll/epoll로 동시 연결 처리 |
| **B. 탐지** | `src/detect/*` | base_dir 기준 정규화 판정, 이중 인코딩(`%252e%252e%252f`), 역슬래시·심볼릭 링크, 13주차 반례(오탐·미탐) 테스트 추가 |
| **C. fork** | `src/hpfork/*` | SIGCHLD 핸들러로 Decoy 종료·세션 시간 기록, Decoy 격리 강화(setrlimit·권한 하향·chroot 등), 동시 Decoy 수 제한, fork 실패 처리 검증 |
| **D. Decoy** | `src/decoy/*` | honey data 파일에서 가짜 값 로드, 원본과 같은 형식의 가짜 값 생성, 미패치 응답과 구분 불가능한지 점검(상태코드·헤더·본문), 정규화된 경로 기준 대상 매핑 |
| **통합·검증** | `src/app/*`, `tests/run_cases.py` | 12주차 보고서용 전·후 비교 결과 기록, 타 환경 재현 확인, 13주차 사례 확장, 14주차 측정 지표(분기 지연 시간 등) 추가 |

### 개발 규칙
1. `common/types.h`는 공통 계약입니다. 필드를 추가하거나 바꿀 때는 팀 합의 후 한 사람이 수정합니다.
2. 작업 후 `./build/unit_tests && python3 tests/run_cases.py`가 모두 PASS인 상태로 커밋합니다. 동작을 확인할 때마다 커밋하고 실행 로그를 남깁니다.
3. 고정 사례 3종(`tests/run_cases.py`의 `CASES`)은 바꾸지 않습니다. 새 사례는 별도로 추가합니다.
4. 기대와 다른 결과가 나오면 기대값을 고치지 말고 원인부터 분석합니다.
