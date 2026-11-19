#include "decoy/decoy_response.h"

#include "common/logger.h"

namespace hp::decoy {

HttpResponse fake_success(const HttpRequest& req, const SecretStore& redacted) {
    std::string name;
    if (auto it = req.query.find("name"); it != req.query.end()) name = it->second;

    // 경로의 마지막 구성요소로 요청 대상 추정: "../secret.txt" → "secret.txt"
    // TODO(Decoy): 정규화된 대상 경로 기준으로 매핑 (예: "../../www/secret.txt")
    size_t slash = name.find_last_of('/');
    std::string base = (slash == std::string::npos) ? name : name.substr(slash + 1);

    HttpResponse r;
    if (auto it = redacted.entries.find(base); it != redacted.entries.end()) {
        r.body = it->second;  // 가짜 값
    } else {
        // 미등록 대상은 미패치 서버가 '없는 파일'에 내는 응답을 흉내낸다.
        // TODO(Decoy): 미패치 서버 응답과 상태코드·헤더·본문이 구분 불가능한지 통합 시 점검
        r.status = 404;
        r.body = "file not found\n";
    }
    logger::write("DECOY", "fake response status=" + std::to_string(r.status) + " target=" + name);
    return r;
}

}  // namespace hp::decoy
