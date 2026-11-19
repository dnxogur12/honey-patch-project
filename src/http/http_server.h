// [HTTP 모듈] TCP 소켓 서버 (listen/accept, 연결별 Keep-Alive 요청 루프)
//
// 프로세스 모델: 단일 스레드 · 반복(iterative) 서버.
//   - fork()는 공격 탐지 시에만 발생해야 하므로 연결마다 fork하지 않는다.
//   - 멀티스레드로 바꾸지 말 것: 스레드가 있는 프로세스의 fork()는 호출 스레드만 복제되어
//     락·상태가 깨질 수 있다. 동시성이 필요하면 poll/epoll 기반으로 확장한다.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "common/types.h"

namespace hp::http {

// 요청 1건을 처리하는 콜백. ctx는 fork 모듈이 분기 시 갱신할 수 있도록 non-const.
// 반환 후 ctx.handed_off == true 이면 서버는 응답을 보내지 않고 연결에서 손을 뗀다.
using Handler = std::function<HttpResponse(const HttpRequest&, ConnContext&)>;

struct ServerConfig {
    std::string bind_addr = "127.0.0.1";  // 취약 모드도 실행되므로 기본은 로컬 전용
    std::uint16_t port = 8080;
    int idle_timeout_sec = 10;  // Keep-Alive 유휴 연결 수신 타임아웃
};

// accept 루프 실행. 정상 동작 중에는 반환하지 않으며, 초기화 실패 시 1을 반환.
// Decoy 자식은 담당 연결이 끝나면 이 함수 안에서 _exit(0)으로 종료한다.
int run_server(const ServerConfig& cfg, const Handler& handler);

}  // namespace hp::http
