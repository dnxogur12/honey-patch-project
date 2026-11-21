#include "http/http_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "common/logger.h"
#include "http/http_parser.h"

namespace hp::http {

namespace {

constexpr size_t kMaxHeaderBytes = 8192;
constexpr size_t kMaxBodyBytes = 64 * 1024; // 본문 크기 상한

bool send_all(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        // MSG_NOSIGNAL: 클라이언트가 먼저 끊어도 SIGPIPE로 프로세스가 죽지 않도록
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

void send_error(int fd, int status, const char* body) {
    HttpResponse r;
    r.status = status;
    r.body = body;
    send_all(fd, serialize_response(r, false));
}

// 연결 1개에 대한 Keep-Alive 요청 루프.
// Main 프로세스: 공격 탐지로 handed_off 되면 즉시 반환.
// Decoy 프로세스: fork 직후 이 함수의 같은 지점에서 이어서 실행되며, 연결이 끝날 때까지 처리.
void serve_connection(ConnContext& ctx, const Handler& handler) {
    std::string buf;  // fork() 시 자식에게도 복제됨 → 파이프라인된 후속 요청이 있으면 자식이 처리
    for (;;) {
        size_t end;
        while ((end = buf.find("\r\n\r\n")) == std::string::npos) {
            if (buf.size() > kMaxHeaderBytes) {
                send_error(ctx.client_fd, 431, "header too large\n");
                return;
            }
            char tmp[4096];
            ssize_t n = ::recv(ctx.client_fd, tmp, sizeof tmp, 0);
            if (n == 0) return;  // 클라이언트 종료
            if (n < 0) {
                if (errno == EINTR) continue;
                return;  // 유휴 타임아웃(EAGAIN) 또는 오류
            }
            buf.append(tmp, static_cast<size_t>(n));
        }
        std::string raw = buf.substr(0, end + 4);
        buf.erase(0, end + 4);

        HttpRequest req;
        std::string err;
        if (!parse_request(raw, req, &err)) {
            logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " bad request: " + err);
            send_error(ctx.client_fd, 400, "bad request\n");
            return;
        }
        // Content-Length 본문 처리: 앱은 GET 전용이라 본문을 쓰지 않지만,
        // 다음 요청과의 경계를 맞추기 위해 본문만큼 읽어서 버린다 (요청 밀반입 방지).
        if (req.headers.count("transfer-encoding")) {  // chunked 등은 지원하지 않음
            logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " bad request: transfer-encoding unsupported");
            send_error(ctx.client_fd, 400, "bad request\n");
            return;
        }
        if (auto it = req.headers.find("content-length"); it != req.headers.end()) {
            const std::string& v = it->second;
            if (v.empty() || v.size() > 9 || v.find_first_not_of("0123456789") != std::string::npos) {
                logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " bad request: invalid content-length");
                send_error(ctx.client_fd, 400, "bad request\n");
                return;
            }
            size_t body_len = std::stoul(v);
            if (body_len > kMaxBodyBytes) {
                send_error(ctx.client_fd, 413, "payload too large\n");
                return;
            }
            while (buf.size() < body_len) {  // 본문이 덜 왔으면 마저 읽음
                char tmp[4096];
                ssize_t n = ::recv(ctx.client_fd, tmp, sizeof tmp, 0);
                if (n == 0) return;
                if (n < 0) {
                    if (errno == EINTR) continue;
                    return;
                }
                buf.append(tmp, static_cast<size_t>(n));
            }
            buf.erase(0, body_len);
        }
        logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " " + req.method + " " +
                                  req.target);

        HttpResponse resp = handler(req, ctx);
        if (ctx.handed_off) return;  // Main: 연결은 Decoy 자식 소유. 응답하지 않음

        if (!send_all(ctx.client_fd, serialize_response(resp, req.keep_alive))) return;
        if (!req.keep_alive) return;
    }
}

}  // namespace

int run_server(const ServerConfig& cfg, const Handler& handler) {
    int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        logger::write("HTTP", std::string("socket: ") + std::strerror(errno));
        return 1;
    }
    int one = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg.port);
    if (::inet_pton(AF_INET, cfg.bind_addr.c_str(), &addr.sin_addr) != 1) {
        logger::write("HTTP", "invalid bind address: " + cfg.bind_addr);
        return 1;
    }
    if (::bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 || ::listen(lfd, 16) < 0) {
        logger::write("HTTP", std::string("bind/listen: ") + std::strerror(errno));
        return 1;
    }
    logger::write("HTTP", "listening on " + cfg.bind_addr + ":" + std::to_string(cfg.port));

    std::uint64_t next_conn_id = 0;
    for (;;) {
        sockaddr_in peer{};
        socklen_t len = sizeof peer;
        int cfd = ::accept(lfd, reinterpret_cast<sockaddr*>(&peer), &len);
        if (cfd < 0) {
            if (errno != EINTR) logger::write("HTTP", std::string("accept: ") + std::strerror(errno));
            continue;
        }
        timeval tv{cfg.idle_timeout_sec, 0};
        ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        ConnContext ctx;
        ctx.client_fd = cfd;
        ctx.listen_fd = lfd;
        ctx.conn_id = ++next_conn_id;
        logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " accepted from " +
                                  inet_ntoa(peer.sin_addr));

        serve_connection(ctx, handler);

        if (ctx.role == ProcessRole::Decoy) {
            // Decoy 자식: 담당하던 공격 연결이 끝났으므로 accept 루프로 돌아가지 않고 종료
            logger::write("HTTP", "conn=" + std::to_string(ctx.conn_id) + " decoy session closed");
            ::close(ctx.client_fd);
            ::_exit(0);
        }
        if (!ctx.handed_off) ::close(ctx.client_fd);  // handed_off면 fork 모듈이 이미 close
    }
}

}  // namespace hp::http
