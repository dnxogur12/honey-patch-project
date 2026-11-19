// [fork 모듈] 공격 세션을 Decoy 자식 프로세스로 분기 (원논문 hp_init / hp_fork 개념 대응)
//
// 원논문: CRIU로 프로세스를 체크포인트해 LXC Decoy 컨테이너에서 복원, 프록시가 연결을 전환.
// 본 구현: 단일 호스트 fork(). 자식이 TCP 소켓 FD를 상속받아 같은 연결을 계속 처리한다.
#pragma once

#include "common/types.h"

namespace hp::hpfork {

enum class ForkResult {
    Parent,        // Main 프로세스: 연결을 넘김(client_fd 닫힘, ctx.handed_off=true)
    Child,         // 새로 생성된 Decoy 프로세스 (listen_fd 닫힘, ctx.role=Decoy)
    AlreadyDecoy,  // 이미 Decoy인 연결: 재분기하지 않음 (Keep-Alive 후속 요청 중복 fork 방지)
    Failed,        // fork() 실패: 호출자는 일반 패치(403)로 대체 처리
};

// 서버 시작 시 1회 호출 (hp_init 대응). 종료된 Decoy 자식의 좀비 회수 설정 등.
void init();

// 패치 지점에서 공격 탐지 시 호출 (hp_fork 대응).
// fork() 직후 부모·자식이 각자 불필요한 소켓 FD를 정리한다.
ForkResult fork_decoy(ConnContext& ctx);

}  // namespace hp::hpfork
