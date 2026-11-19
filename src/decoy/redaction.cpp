#include "decoy/redaction.h"

#include "common/logger.h"

namespace hp::decoy {

namespace {

// 컴파일러 최적화로 제거되지 않도록 volatile 포인터로 0 덮어쓰기
void secure_wipe(std::string& s) {
    volatile char* p = s.data();
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
    s.shrink_to_fit();
}

// 항목별 가짜 값. 공격자가 '성공했다'고 믿을 만큼 실제 형식과 비슷해야 한다.
// TODO(Decoy): 하드코딩 대신 www/decoy/ 등의 honey data 파일에서 로드
// TODO(Decoy): 원본과 같은 형식(키 이름·줄 수·길이)을 유지하는 가짜 값 생성
std::string fake_value_for(const std::string& key) {
    if (key == "secret.txt")
        return "# internal config\n"
               "FLAG=CNU{w3lc0me_t0_th3_s3rv3r}\n"
               "db_user=admin\n"
               "db_password=Spring2026!\n";
    if (key == "admin_token") return "adm-6f1d2c9e8b7a4d3c";
    return "";
}

}  // namespace

void redact(SecretStore& store) {
    for (auto& [key, value] : store.entries) {
        secure_wipe(value);
        value = fake_value_for(key);
    }
    logger::write("DECOY", "redacted " + std::to_string(store.entries.size()) + " secret entries");
    // 한계(TODO): std::string 이전 버퍼·파일 읽기 중간 버퍼 등 힙에 남은 사본은 지우지 못한다.
    //            원논문은 프로세스 메모리 전체를 대상으로 하므로 차이로 기록할 것.
}

}  // namespace hp::decoy
