// 진입점: 인자 파싱 → 모듈 초기화 → HTTP 서버 실행
#include <cstdio>
#include <cstdlib>
#include <string>

#include "app/app.h"
#include "common/logger.h"
#include "hpfork/hp_fork.h"
#include "http/http_server.h"

namespace {

void usage(const char* prog) {
    std::fprintf(stderr,
                 "usage: %s [--mode unpatched|patched|honeypatch] [--port N] [--root DIR]\n"
                 "          [--bind ADDR] [--log FILE]\n"
                 "  defaults: --mode honeypatch --port 8080 --root www --bind 127.0.0.1\n",
                 prog);
}

bool parse_mode(const std::string& s, hp::Mode& out) {
    if (s == "unpatched") out = hp::Mode::Unpatched;
    else if (s == "patched") out = hp::Mode::Patched;
    else if (s == "honeypatch") out = hp::Mode::HoneyPatch;
    else return false;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    hp::Mode mode = hp::Mode::HoneyPatch;
    hp::http::ServerConfig cfg;
    std::string root = "www";  // 저장소 루트 기준 상대 경로
    std::string log_path;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        bool has_val = i + 1 < argc;
        if (a == "--mode" && has_val) {
            if (!parse_mode(argv[++i], mode)) { usage(argv[0]); return 2; }
        } else if (a == "--port" && has_val) {
            cfg.port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if (a == "--root" && has_val) {
            root = argv[++i];
        } else if (a == "--bind" && has_val) {
            cfg.bind_addr = argv[++i];
        } else if (a == "--log" && has_val) {
            log_path = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    hp::logger::init(log_path);
    hp::hpfork::init();
    hp::app::App app(mode, root);

    return hp::http::run_server(cfg, [&app](const hp::HttpRequest& req, hp::ConnContext& ctx) {
        return app.handle(req, ctx);
    });
}
