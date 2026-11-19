// [Decoy 모듈] 민감정보 소거·가짜 데이터 대체 (Redaction)
//
// fork()된 자식은 부모 메모리를 그대로 복제하므로, Decoy 자식은 응답을 만들기 전에
// SecretStore의 실제 비밀을 지우고 그럴듯한 가짜 값(honey data)으로 바꿔야 한다.
#pragma once

#include "common/types.h"

namespace hp::decoy {

// Decoy 자식에서 fork 직후 1회 호출. 모든 항목의 원본 바이트를 0으로 덮어쓴 뒤 가짜 값으로 대체.
void redact(SecretStore& store);

}  // namespace hp::decoy
