#include "detect/detector.h"

namespace hp::detect {

// 베이스라인 판정 기준 (11주차 고정 사례 3종을 만족하는 최소 구현):
//   1) 경로 세그먼트 중 정확히 ".." 인 것이 있으면 공격   ← "../secret.txt"
//      (세그먼트 단위 비교이므로 "..report.txt" 같은 정상 파일명은 오탐하지 않음)
//   2) '/' 로 시작하는 절대 경로면 공격
//   3) NUL 바이트 포함 시 공격
//
// TODO(탐지):
//   - 정규화 기준 판정: base_dir 기준으로 경로를 정규화한 결과가 base_dir 밖이면 공격
//     (현재 규칙은 문자열 패턴 기반이라 우회 가능성 있음)
//   - 이중 인코딩(%252e%252e%252f): 디코딩 후에도 '%XX'가 남는 입력 처리 방침 결정
//   - 역슬래시('..\\'), 심볼릭 링크 등 추가 경계 사례
//   - 13주차 반례 탐색 시 오탐/미탐 사례를 tests/unit_tests.cpp 에 추가
DetectResult inspect_file_name(const std::string& name) {
    if (name.find('\0') != std::string::npos) return {true, "NUL byte in file name"};
    if (!name.empty() && name[0] == '/') return {true, "absolute path"};

    size_t start = 0;
    while (start <= name.size()) {
        size_t slash = name.find('/', start);
        if (slash == std::string::npos) slash = name.size();
        if (name.compare(start, slash - start, "..") == 0) return {true, "path traversal segment '..'"};
        start = slash + 1;
    }
    return {false, ""};
}

}  // namespace hp::detect
