#include "app/app.h"

#include <fstream>
#include <optional>
#include <sstream>

#include "common/logger.h"
#include "decoy/decoy_response.h"
#include "decoy/redaction.h"
#include "detect/detector.h"
#include "hpfork/hp_fork.h"

namespace hp::app {

namespace {

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

HttpResponse make(int status, std::string body, std::string type = "text/plain; charset=utf-8") {
    HttpResponse r;
    r.status = status;
    r.body = std::move(body);
    r.content_type = std::move(type);
    return r;
}

}  // namespace

const char* mode_name(Mode m) {
    switch (m) {
        case Mode::Unpatched:  return "unpatched";
        case Mode::Patched:    return "patched";
        case Mode::HoneyPatch: return "honeypatch";
    }
    return "?";
}

App::App(Mode mode, std::string root) : mode_(mode), root_(std::move(root)) {
    // 서버가 메모리에 들고 있는 민감정보 (fork 시 자식에게 복제됨 → Redaction 대상)
    if (auto s = read_file(root_ + "/secret.txt")) secrets_.entries["secret.txt"] = *s;
    else logger::write("APP", "warning: " + root_ + "/secret.txt not found");
    secrets_.entries["admin_token"] = "adm-REAL_SECRET-0b9e7c41";  // 메모리 전용 비밀 예시
    logger::write("APP", std::string("mode=") + mode_name(mode_) + " root=" + root_);
}

HttpResponse App::handle(const HttpRequest& req, ConnContext& ctx) {
    if (req.method != "GET") return make(405, "method not allowed\n");
    if (req.path == "/") return make(200, "routes: /public, /files?name=readme.txt\n");
    if (req.path == "/public") {
        if (auto s = read_file(root_ + "/public/index.html")) return make(200, *s, "text/html; charset=utf-8");
        return make(500, "missing public page\n");
    }
    if (req.path == "/files") return handle_files(req, ctx);
    return make(404, "not found\n");
}

HttpResponse App::handle_files(const HttpRequest& req, ConnContext& ctx) {
    auto it = req.query.find("name");
    if (it == req.query.end() || it->second.empty()) return make(400, "missing name\n");
    const std::string& name = it->second;  // HTTP 모듈이 이미 URL 디코딩함

    // ===================== 패치 지점 (patch point) =====================
    // 원래 취약 코드에 추가된 입력 검사. Unpatched 모드는 이 블록이 없는 원래 코드와 같다.
    if (mode_ != Mode::Unpatched) {
        DetectResult d = detect::inspect_file_name(name);
        if (d.is_attack) {
            logger::write("DETECT", "conn=" + std::to_string(ctx.conn_id) + " attack name=\"" + name +
                                        "\" reason=" + d.reason);
            if (mode_ == Mode::Patched) return make(403, "forbidden\n");
            return honeypatch_branch(req, ctx);
        }
    }
    // ===================================================================

    // 원래(취약) 코드: name을 검증 없이 경로에 이어 붙임 → "../secret.txt"로 탈출 가능
    if (auto s = read_file(root_ + "/files/" + name)) return make(200, *s);
    return make(404, "file not found\n");
}

HttpResponse App::honeypatch_branch(const HttpRequest& req, ConnContext& ctx) {
    switch (hpfork::fork_decoy(ctx)) {
        case hpfork::ForkResult::Parent:
            return {};  // ctx.handed_off=true → HTTP 모듈이 이 응답을 보내지 않음
        case hpfork::ForkResult::Failed:
            return make(403, "forbidden\n");  // 분기 실패 시 일반 패치로 안전하게 대체
        case hpfork::ForkResult::Child:
            decoy::redact(secrets_);  // 응답 생성 전에 반드시 먼저 수행
            [[fallthrough]];
        case hpfork::ForkResult::AlreadyDecoy:
            // hp_skip 대응: 거부 처리를 건너뛰고 공격이 성공한 것처럼 응답
            return decoy::fake_success(req, secrets_);
    }
    return make(500, "unreachable\n");
}

}  // namespace hp::app
