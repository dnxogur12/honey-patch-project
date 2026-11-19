// [HTTP 모듈] 요청 파싱 · URL 디코딩 · 응답 직렬화 (소켓 I/O 없음 → 단위 테스트 가능)
#pragma once

#include <string>
#include <string_view>

#include "common/types.h"

namespace hp::http {

// raw: 요청 라인 + 헤더 + 빈 줄("\r\n\r\n")까지의 블록.
// 성공 시 out을 채우고 true, 실패 시 err에 사유를 넣고 false.
bool parse_request(const std::string& raw, HttpRequest& out, std::string* err = nullptr);

// %XX 디코딩. plus_as_space=true면 '+'를 공백으로 (쿼리 문자열용).
// 잘못된 %XX는 원문 그대로 둔다.
std::string url_decode(std::string_view s, bool plus_as_space = false);

// HttpResponse → HTTP/1.1 응답 바이트열 (Content-Length, Connection 헤더 포함)
std::string serialize_response(const HttpResponse& resp, bool keep_alive);

}  // namespace hp::http
