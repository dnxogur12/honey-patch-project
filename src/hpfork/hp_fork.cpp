#include "hpfork/hp_fork.h"

#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "common/logger.h"

namespace hp::hpfork {

namespace {
constexpr unsigned kDecoyMaxLifetimeSec = 120;  // Decoy 자식 최대 수명 (SIGALRM 기본 동작 = 종료)
constexpr int kMaxTrackedDecoys = 64;           // 동시에 추적하는 Decoy 세션 수

// ---------------------------------------------------------------------------
// 살아 있는 Decoy 세션 표 (부모 프로세스 전용)
//
// SIGCHLD 핸들러가 이 표를 읽고 지우므로 std::map 대신 고정 배열을 쓴다.
// (map은 내부에서 malloc을 호출 → 핸들러가 끼어들면 malloc끼리 부딪혀 멈추거나 힙이 깨짐)
// 일반 코드는 SIGCHLD를 막아 둔 상태에서만 표를 수정하므로 핸들러와 겹치지 않는다.
// ---------------------------------------------------------------------------
struct DecoySlot {
    pid_t pid = 0;  // 0 = 빈 칸
    std::uint64_t conn_id = 0;
    timespec start{};  // fork 직전 시각 (CLOCK_MONOTONIC)
};
DecoySlot g_slots[kMaxTrackedDecoys];

// 핸들러에서 로그 메시지를 만들기 위한 고정 버퍼 (std::string 대신)
struct MsgBuf {
    char data[256];
    size_t len = 0;

    void str(const char* s) {
        while (*s && len < sizeof data - 1) data[len++] = *s++;
    }
    void num(unsigned long long v, int width = 0) {
        char tmp[24];
        int n = 0;
        do {
            tmp[n++] = static_cast<char>('0' + v % 10);
            v /= 10;
        } while (v > 0 && n < 24);
        while (n < width && n < 24) tmp[n++] = '0';
        while (n > 0 && len < sizeof data - 1) data[len++] = tmp[--n];
    }
    const char* c_str() {
        data[len] = '\0';
        return data;
    }
};

long long elapsed_ms(const timespec& from, const timespec& to) {
    return (to.tv_sec - from.tv_sec) * 1000LL + (to.tv_nsec - from.tv_nsec) / 1000000LL;
}

// ---------------------------------------------------------------------------
// SIGCHLD 핸들러: Decoy 자식이 끝날 때마다 커널이 부모에게서 이 함수를 실행한다.
// 여기서는 async-signal-safe 함수만 쓴다 (waitpid, clock_gettime, write 계열).
// ---------------------------------------------------------------------------
void on_sigchld(int) {
    const int saved_errno = errno;  // 핸들러가 끼어든 코드의 errno를 망가뜨리지 않도록 보관

    int status = 0;
    pid_t pid;
    // 자식 여러 개가 거의 동시에 끝나면 SIGCHLD가 1번으로 합쳐질 수 있다
    // → 끝난 자식이 더 없을 때까지 반복해서 모두 회수 (좀비 방지)
    while ((pid = ::waitpid(-1, &status, WNOHANG)) > 0) {
        timespec now{};
        ::clock_gettime(CLOCK_MONOTONIC, &now);

        DecoySlot* slot = nullptr;
        for (auto& s : g_slots) {
            if (s.pid == pid) {
                slot = &s;
                break;
            }
        }

        MsgBuf m;
        if (slot) {
            m.str("conn=");
            m.num(slot->conn_id);
            m.str(" ");
        }
        m.str("decoy pid=");
        m.num(static_cast<unsigned long long>(pid));
        m.str(" ended: ");

        if (WIFEXITED(status)) {
            m.str("exit code=");
            m.num(static_cast<unsigned long long>(WEXITSTATUS(status)));
        } else if (WIFSIGNALED(status)) {
            const int sig = WTERMSIG(status);
            m.str("killed by signal=");
            m.num(static_cast<unsigned long long>(sig));
            if (sig == SIGALRM) m.str(" (lifetime limit)");
        }

        if (slot) {
            const long long ms = elapsed_ms(slot->start, now);
            m.str(" duration=");
            m.num(static_cast<unsigned long long>(ms / 1000));
            m.str(".");
            m.num(static_cast<unsigned long long>(ms % 1000), 3);
            m.str("s");
            slot->pid = 0;  // 칸 비우기
        } else {
            m.str(" duration=unknown");
        }

        logger::write_signal_safe("FORK", m.c_str());
    }

    errno = saved_errno;
}

// 빈 칸에 세션 등록. SIGCHLD가 막힌 상태에서만 호출할 것. 표가 꽉 찼으면 false.
bool track_decoy(pid_t pid, std::uint64_t conn_id, const timespec& start) {
    for (auto& s : g_slots) {
        if (s.pid == 0) {
            s.pid = pid;
            s.conn_id = conn_id;
            s.start = start;
            return true;
        }
    }
    return false;
}
}  // namespace

void init() {
    struct sigaction sa {};
    sa.sa_handler = on_sigchld;
    sigemptyset(&sa.sa_mask);
    // SA_RESTART  : 핸들러가 끝나면 중단된 accept() 등을 자동으로 다시 실행
    // SA_NOCLDSTOP: 자식이 일시정지(SIGSTOP)할 때는 알리지 않고, 종료할 때만 알림
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (::sigaction(SIGCHLD, &sa, nullptr) < 0) {
        // 등록 실패 시 최소한 좀비만은 막도록 이전 방식(커널 자동 회수)으로 대체
        logger::write("FORK", std::string("sigaction(SIGCHLD) failed: ") + std::strerror(errno) +
                                  ", fallback to SIG_IGN");
        ::signal(SIGCHLD, SIG_IGN);
    }
}

ForkResult fork_decoy(ConnContext& ctx) {
    const std::string conn = "conn=" + std::to_string(ctx.conn_id);

    if (ctx.role == ProcessRole::Decoy) {
        logger::write("FORK", conn + " already in decoy, no re-fork");
        return ForkResult::AlreadyDecoy;
    }

    // fork ~ 세션 표 등록까지 SIGCHLD를 잠깐 막는다.
    // 막지 않으면 자식이 즉시 끝났을 때, 부모가 표에 등록하기도 전에 핸들러가 실행되어
    // 해당 pid를 찾지 못한다. 막아 둔 동안 온 신호는 버려지지 않고 풀 때 처리된다.
    sigset_t chld_only, old_mask;
    sigemptyset(&chld_only);
    sigaddset(&chld_only, SIGCHLD);
    ::sigprocmask(SIG_BLOCK, &chld_only, &old_mask);

    timespec start{};
    ::clock_gettime(CLOCK_MONOTONIC, &start);

    std::fflush(nullptr);  // stdio 버퍼가 자식에 복제되어 중복 출력되는 것 방지
    pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        logger::write("FORK", conn + " fork failed: " + std::strerror(err));
        return ForkResult::Failed;
    }

    if (pid == 0) {
        // ---- 자식 (Decoy) ----
        // 신호 차단 상태도 fork 때 복사되므로 원래대로 되돌린다.
        ::sigprocmask(SIG_SETMASK, &old_mask, nullptr);
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
    const bool tracked = track_decoy(pid, ctx.conn_id, start);

    // 공격 연결은 자식 소유가 되었으므로 부모 쪽 FD를 닫는다.
    // (부모가 계속 열고 있으면 자식이 종료해도 TCP 연결이 닫히지 않음)
    ::close(ctx.client_fd);
    ctx.client_fd = -1;
    ctx.handed_off = true;
    logger::write("FORK", conn + " handed off to decoy pid=" + std::to_string(pid));
    if (!tracked) logger::write("FORK", conn + " warning: session table full, duration not tracked");

    // 여기서 차단을 푼다. 그사이 자식이 이미 끝났다면 지금 핸들러가 실행된다.
    ::sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    return ForkResult::Parent;
}

}  // namespace hp::hpfork
