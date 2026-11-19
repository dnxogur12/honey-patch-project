// [탐지 모듈] 패치 지점의 입력 검사 (원논문의 "패치 조건문"에 해당)
// 소켓·fork·HTTP 파싱과 무관한 순수 함수 → 단위 테스트로 독립 개발 가능
#pragma once

#include <string>

#include "common/types.h"

namespace hp::detect {

// 입력: URL 디코딩이 끝난 /files 의 name 파라미터 값 (예: "../secret.txt")
// 출력: 경로 탐색 공격 여부와 판정 근거
DetectResult inspect_file_name(const std::string& decoded_name);

}  // namespace hp::detect
