// [앱 모듈] 모의 취약 웹 애플리케이션 + 패치 지점 (모듈 연결 담당)
//
// 라우트:
//   GET /public            → www/public/index.html            (정상 사례)
//   GET /files?name=<파일>  → www/files/<파일>                  (경로 탐색 취약점이 있는 지점)
//
// 데이터 흐름 (HoneyPatch 모드, 공격 요청):
//   detect::inspect_file_name → hpfork::fork_decoy
//     ├ Parent: 연결을 넘기고 응답 없이 반환
//     └ Child : decoy::redact → decoy::fake_success (오류 처리 skip)
#pragma once

#include <string>

#include "common/types.h"

namespace hp::app {

class App {
public:
    // root: 데이터 디렉터리 (www/). 시작 시 민감정보를 메모리(SecretStore)에 적재한다.
    App(Mode mode, std::string root);

    // http::Handler 시그니처와 동일
    HttpResponse handle(const HttpRequest& req, ConnContext& ctx);

private:
    HttpResponse handle_files(const HttpRequest& req, ConnContext& ctx);
    HttpResponse honeypatch_branch(const HttpRequest& req, ConnContext& ctx);

    Mode mode_;
    std::string root_;
    SecretStore secrets_;
};

const char* mode_name(Mode m);

}  // namespace hp::app
