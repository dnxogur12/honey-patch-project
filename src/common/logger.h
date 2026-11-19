// 방어자(내부) 로그. 공격자에게 가는 HTTP 응답과 분리해서 기록한다.
// 형식: 2026-11-17 20:01:02 [pid=1234] [FORK] message
//
// fork 안전성: stdio 버퍼를 쓰지 않고 write(2)로 바로 기록하므로
// fork() 전후에 같은 로그가 중복 출력되지 않는다.
#pragma once

#include <string>

namespace hp::logger {

// path가 비어 있지 않으면 stderr와 함께 파일(append)에도 기록
void init(const std::string& path);

// tag 예: "HTTP", "APP", "DETECT", "FORK", "DECOY"
void write(const char* tag, const std::string& msg);

// 시그널 핸들러 안에서 쓰는 버전 (async-signal-safe). 출력 형식은 write()와 같다.
// std::string·malloc·localtime을 쓰지 않으므로 핸들러가 언제 끼어들어도 안전하다.
// 일반 코드에서는 write()를 쓸 것.
void write_signal_safe(const char* tag, const char* msg);

}  // namespace hp::logger
