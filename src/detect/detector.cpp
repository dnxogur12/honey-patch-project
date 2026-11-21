#include "detect/detector.h"

#include <vector>

namespace hp::detect {

// 판정 기준 (정규화 기준):
//   1) files/ 에서 출발해 '.'·'..'을 풀었을 때 files/ 밖으로 나가면 공격   ← "../secret.txt"
//      ("../files/readme.txt"처럼 files/ 안으로 돌아오면 정상, "..report.txt"도 정상)
//   2) '/' 또는 '\' 로 시작하는 절대 경로면 공격
//   3) NUL 바이트 포함 시 공격
//   4) 한 번 더 디코딩했을 때 1~3에 걸리면 공격 (이중 인코딩 %252e%252e%252f)
//      파일 시스템은 %2F를 '/'로 읽지 않아 실제 탈출은 아니지만, 우회 시도로 보고 기만 대상으로 분류
//   '\'는 '/'와 같은 구분자로 취급한다 (Linux에서는 일반 문자지만 우회 시도로 보수적으로 판정).

namespace {

// 1~3 규칙. 시작 위치 www/files/ 는 app.cpp 의 root_ + "/files/" 와 일치해야 한다.
// 입력 이름 하나 받아서 공격 판정
DetectResult check(const std::string& name) {
    // \0 탐지
    if (name.find('\0') != std::string::npos) return {true, "NUL byte in file name"};
    // 첫 글자 /혹은 \면 공격 판정
    if (!name.empty() && (name[0] == '/' || name[0] == '\\')) return {true, "absolute path"};

    // 입력 이름 / 혹은 \ 기준으로 잘라서 files/에서 출발해 어디로 도착하는지 따라감
    std::vector<std::string> stack{"files"};  // www/ 기준 경로
    size_t start = 0;
    while (start <= name.size()) {
        size_t slash = name.find_first_of("/\\", start);
        if (slash == std::string::npos) slash = name.size();
        std::string seg = name.substr(start, slash - start);
        if (seg == "..") {
            if (stack.empty()) return {true, "path escapes data root"};
            stack.pop_back();
        } else if (!seg.empty() && seg != ".") {
            stack.push_back(seg);
        }
        start = slash + 1;
    }
    // 스택 맨 앞이 files 아니면 files/ 밖에 도착한 것 -> 공격O
    if (stack.empty() || stack.front() != "files") return {true, "path escapes base dir after normalization"};
    return {false, ""};
}

// 판정 전용 디코딩 (파일을 여는 값은 바꾸지 않음). 모듈 간 include 금지 규칙 때문에 HTTP 모듈과 따로 둔다.
std::string decode_once(const std::string& s) {
    auto hex = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
            out.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

}  // namespace

DetectResult inspect_file_name(const std::string& name) {
    DetectResult r = check(name);
    if (r.is_attack) return r;

    std::string twice = decode_once(name);  // 4) 이중 인코딩
    if (twice != name && check(twice).is_attack) return {true, "double-encoded path traversal"};
    return {false, ""};
}

}  // namespace hp::detect
