// 모듈 간 공통 계약(데이터 타입). 모든 모듈이 이 파일만 공유한다.
// 필드를 바꿀 때는 팀 합의 후 수정할 것 (모든 모듈에 영향).
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace hp {

// 서버 동작 모드. 동일 입력에 대한 보호 적용 전·후 비교용 (12주차 요구사항).
enum class Mode {
    Unpatched,   // 미패치: 취약 코드 그대로 → 비밀 노출
    Patched,     // 일반 패치: 공격 탐지 시 403 거부
    HoneyPatch,  // 허니패치: 공격 탐지 시 fork() → Decoy 자식이 가짜 성공 응답
};

// ---- HTTP 모듈 → 앱 모듈 ----
struct HttpRequest {
    std::string method;   // "GET"
    std::string target;   // 원본 request-target (디코딩 전). 예: /files?name=..%2Fsecret.txt
    std::string path;     // 디코딩된 경로.                    예: /files
    std::string version;  // "HTTP/1.1"
    std::map<std::string, std::string> query;    // 디코딩된 쿼리. 예: {"name": "../secret.txt"}
    std::map<std::string, std::string> headers;  // 키는 소문자
    bool keep_alive = true;  // 버전·Connection 헤더로 HTTP 모듈이 결정
};

// ---- 앱 모듈 → HTTP 모듈 ----
struct HttpResponse {
    int status = 200;
    std::string content_type = "text/plain; charset=utf-8";
    std::string body;
};

// 현재 프로세스가 맡은 역할
enum class ProcessRole {
    Main,   // 원래 서버 프로세스 (accept 루프 담당)
    Decoy,  // fork()로 생성된 미끼 프로세스 (공격 연결 하나만 담당)
};

// TCP 연결 1개의 상태. HTTP 모듈이 생성하고, fork 모듈이 분기 시 갱신한다.
struct ConnContext {
    int client_fd = -1;
    int listen_fd = -1;
    std::uint64_t conn_id = 0;
    ProcessRole role = ProcessRole::Main;
    bool handed_off = false;  // Main 전용: 이 연결을 Decoy 자식에게 넘겼으므로 더 응답하지 않음
};

// ---- 탐지 모듈 → 앱 모듈 ----
struct DetectResult {
    bool is_attack = false;
    std::string reason;  // 방어자 로그용 판정 근거 (공격자에게 노출 금지)
};

// 서버 메모리에 상주하는 민감정보.
// fork() 시 자식에게 그대로 복제되므로 Decoy 쪽에서 Redaction 대상이 된다.
struct SecretStore {
    std::map<std::string, std::string> entries;  // 예: "secret.txt" → 파일 내용
};

}  // namespace hp
