// 모듈별 단위 테스트 (소켓·fork 없이 순수 함수만 검사)
// 각 담당자는 자기 모듈 섹션에 사례를 추가한다. 실행: ./build/unit_tests
#include <cstdio>
#include <string>

#include "decoy/decoy_response.h"
#include "decoy/redaction.h"
#include "detect/detector.h"
#include "http/http_parser.h"

static int g_fail = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                     \
        }                                                                 \
    } while (0)

using namespace hp;

// ---------------- HTTP 모듈 ----------------
static void test_http() {
    CHECK(http::url_decode("..%2Fsecret.txt") == "../secret.txt");
    CHECK(http::url_decode("%2e%2E%2f") == "../");
    CHECK(http::url_decode("a+b", true) == "a b");
    CHECK(http::url_decode("bad%zz%") == "bad%zz%");  // 잘못된 %XX는 그대로

    HttpRequest r;
    CHECK(http::parse_request("GET /files?name=..%2Fsecret.txt HTTP/1.1\r\nHost: x\r\n\r\n", r));
    CHECK(r.path == "/files");
    CHECK(r.query["name"] == "../secret.txt");
    CHECK(r.keep_alive);

    HttpRequest r2;
    CHECK(http::parse_request("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", r2));
    CHECK(!r2.keep_alive);

    HttpRequest r3;
    CHECK(!http::parse_request("garbage\r\n\r\n", r3));
    // TODO(HTTP): 헤더 상한, 중복 파라미터, HTTP/1.0 keep-alive 사례 추가
}

// ---------------- 탐지 모듈 ----------------
static void test_detect() {
    // 11주차 고정 사례 (디코딩 후 값 기준)
    CHECK(!detect::inspect_file_name("readme.txt").is_attack);    // 정상
    CHECK(detect::inspect_file_name("../secret.txt").is_attack);  // 위반 / 경계(디코딩 후)
    // 추가 경계
    CHECK(!detect::inspect_file_name("..report.txt").is_attack);  // '..'로 시작하는 정상 파일명
    CHECK(detect::inspect_file_name("a/../../secret.txt").is_attack);
    CHECK(detect::inspect_file_name("/etc/passwd").is_attack);
    CHECK(detect::inspect_file_name("..").is_attack);
    // TODO(탐지): 이중 인코딩, 역슬래시 등 반례 추가
}

// ---------------- Decoy 모듈 ----------------
static void test_decoy() {
    SecretStore s;
    s.entries["secret.txt"] = "FLAG=REAL_SECRET{x}\n";
    s.entries["admin_token"] = "adm-REAL_SECRET";
    decoy::redact(s);
    for (auto& [k, v] : s.entries) {
        CHECK(v.find("REAL_SECRET") == std::string::npos);
        CHECK(!v.empty());  // 소거만 하지 않고 가짜 값으로 대체되어야 함
    }

    HttpRequest req;
    req.query["name"] = "../secret.txt";
    HttpResponse resp = decoy::fake_success(req, s);
    CHECK(resp.status == 200);
    CHECK(resp.body == s.entries["secret.txt"]);
}

int main() {
    test_http();
    test_detect();
    test_decoy();
    if (g_fail == 0) std::printf("unit tests: all passed\n");
    return g_fail == 0 ? 0 : 1;
}
