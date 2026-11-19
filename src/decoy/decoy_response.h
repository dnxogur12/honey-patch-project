// [Decoy 모듈] 공격 성공 위장 응답 (원논문 hp_skip 개념 대응)
//
// Decoy 자식은 패치의 거부(403) 처리를 건너뛰고, 취약 코드가 실행된 것처럼 응답한다.
// 단, 응답 내용은 Redaction이 끝난 SecretStore(가짜 값)에서만 가져온다.
#pragma once

#include "common/types.h"

namespace hp::decoy {

// req: 공격으로 판정된 요청, redacted: redact()가 끝난 저장소
HttpResponse fake_success(const HttpRequest& req, const SecretStore& redacted);

}  // namespace hp::decoy
