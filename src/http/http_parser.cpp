#include "http/http_parser.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace hp::http {

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}

void parse_query(const std::string& qs, std::map<std::string, std::string>& out) {
    size_t pos = 0;
    while (pos <= qs.size()) {
        size_t amp = qs.find('&', pos);
        if (amp == std::string::npos) amp = qs.size();
        std::string pair = qs.substr(pos, amp - pos);
        if (!pair.empty()) {
            size_t eq = pair.find('=');
            std::string k = pair.substr(0, eq);
            std::string v = (eq == std::string::npos) ? "" : pair.substr(eq + 1);
            // 중복 키는 첫 값 유지. TODO(HTTP): 중복 파라미터 정책 결정 (HTTP Parameter Pollution)
            out.emplace(url_decode(k, true), url_decode(v, true));
        }
        pos = amp + 1;
    }
}

const char* reason_phrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        default:  return "Unknown";
    }
}

}  // namespace

std::string url_decode(std::string_view s, bool plus_as_space) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%' && i + 2 < s.size()) {
            int hi = hex_value(s[i + 1]), lo = hex_value(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>(hi * 16 + lo));
                i += 2;
                continue;
            }
        }
        out.push_back((plus_as_space && c == '+') ? ' ' : c);
    }
    return out;
}

bool parse_request(const std::string& raw, HttpRequest& out, std::string* err) {
    auto fail = [&](const char* why) {
        if (err) *err = why;
        return false;
    };

    std::istringstream in(raw);
    std::string line;
    if (!std::getline(in, line)) return fail("empty request");
    if (!line.empty() && line.back() == '\r') line.pop_back();

    // 요청 라인: METHOD SP TARGET SP VERSION
    std::istringstream rl(line);
    if (!(rl >> out.method >> out.target >> out.version)) return fail("malformed request line");
    if (out.version != "HTTP/1.1" && out.version != "HTTP/1.0") return fail("unsupported version");
    if (out.target.empty() || out.target[0] != '/') return fail("unsupported request-target");

    size_t q = out.target.find('?');
    out.path = url_decode(out.target.substr(0, q));
    if (q != std::string::npos) parse_query(out.target.substr(q + 1), out.query);

    // 헤더
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        size_t colon = line.find(':');
        if (colon == std::string::npos) return fail("malformed header");
        out.headers[to_lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }

    // Keep-Alive 판정: HTTP/1.1 기본 유지, HTTP/1.0 기본 종료
    std::string conn;
    if (auto it = out.headers.find("connection"); it != out.headers.end()) conn = to_lower(it->second);
    out.keep_alive = (out.version == "HTTP/1.1") ? (conn != "close") : (conn == "keep-alive");
    return true;
}

std::string serialize_response(const HttpResponse& resp, bool keep_alive) {
    std::string s = "HTTP/1.1 " + std::to_string(resp.status) + " " + reason_phrase(resp.status) +
                    "\r\n";
    s += "Server: hp-server\r\n";
    s += "Content-Type: " + resp.content_type + "\r\n";
    s += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    s += keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    s += "\r\n";
    s += resp.body;
    return s;
}

}  // namespace hp::http
