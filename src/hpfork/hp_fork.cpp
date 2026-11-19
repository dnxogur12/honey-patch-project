#include "hpfork/hp_fork.h"

#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>

#include "common/logger.h"

namespace hp::hpfork {

namespace {
constexpr unsigned kDecoyMaxLifetimeSec = 120;  // Decoy 자식 최대 수명 (SIGALRM 기본 동작 = 종료)
}

void init() {
    // 종료된 Decoy 자식을 커널이 자동 회수 (좀비 방지)
    // TODO(fork): 자식 종료 사유·세션 시간을 기록하려면 SIGCHLD 핸들러 + waitpid(WNOHANG)로 교체
    std::signal(SIGCHLD, SIG_IGN);
}

ForkResult fork_decoy(ConnContext& ctx) {
    const std::string conn = "conn=" + std::to_string(ctx.conn_id);

    if (ctx.role == ProcessRole::Decoy) {
        logger::write("FORK", conn + " already in decoy, no re-fork");
        return ForkResult::AlreadyDecoy;
    }

    std::fflush(nullptr);  // stdio 버퍼가 자식에 복제되어 중복 출력되는 것 방지
    pid_t pid = ::fork();
    if (pid < 0) {
        logger::write("FORK", conn + " fork failed: " + std::strerror(errno));
        return ForkResult::Failed;
    }

    if (pid == 0) {
        // ---- 자식 (Decoy) ----
        // 새 연결을 받지 않으므로 listen 소켓은 닫는다. client_fd는 상속받아 계속 사용.
        ::close(ctx.listen_fd);
        ctx.listen_fd = -1;
        ctx.role = ProcessRole::Decoy;
        ::alarm(kDecoyMaxLifetimeSec);
        // TODO(fork): Decoy 격리 강화 (setrlimit, 권한 하향, chroot/네임스페이스 등)
        logger::write("FORK", conn + " decoy child started");
        return ForkResult::Child;
    }

    // ---- 부모 (Main) ----
    // 공격 연결은 자식 소유가 되었으므로 부모 쪽 FD를 닫는다.
    // (부모가 계속 열고 있으면 자식이 종료해도 TCP 연결이 닫히지 않음)
    ::close(ctx.client_fd);
    ctx.client_fd = -1;
    ctx.handed_off = true;
    logger::write("FORK", conn + " handed off to decoy pid=" + std::to_string(pid));
    return ForkResult::Parent;
}

}  // namespace hp::hpfork
