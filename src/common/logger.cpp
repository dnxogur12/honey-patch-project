#include "common/logger.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <ctime>

namespace hp::logger {

namespace {
int g_file_fd = -1;
long g_utc_offset_sec = 0;  // write_signal_safe용 로컬 시간대 오프셋 (init에서 미리 계산)

void write_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::write(fd, s.data() + off, s.size() - off);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

// ---- write_signal_safe 전용 도우미: 미리 잡아 둔 char 버퍼에만 쓴다 (malloc 없음) ----
struct RawLine {
    char data[512];
    size_t len = 0;

    void str(const char* s) {
        while (*s && len < sizeof data - 1) data[len++] = *s++;
    }
    // width > 0 이면 앞을 0으로 채움 (예: 5 → "05")
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
};

void raw_write_all(int fd, const char* p, size_t n) {
    while (n > 0) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        p += w;
        n -= static_cast<size_t>(w);
    }
}

// localtime_r은 내부 락을 쓰므로 핸들러에서 못 쓴다 → 날짜를 직접 계산
// (1970-01-01 기준 일수 → 연·월·일, Howard Hinnant의 civil_from_days 알고리즘)
void put_timestamp(RawLine& out) {
    timespec ts{};
    ::clock_gettime(CLOCK_REALTIME, &ts);
    long long t = static_cast<long long>(ts.tv_sec) + g_utc_offset_sec;
    long long days = t / 86400;
    long long secs = t % 86400;

    long long z = days + 719468;
    long long era = z / 146097;
    long long doe = z - era * 146097;
    long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    long long mp = (5 * doy + 2) / 153;
    long long d = doy - (153 * mp + 2) / 5 + 1;
    long long m = mp < 10 ? mp + 3 : mp - 9;
    long long y = yoe + era * 400 + (m <= 2 ? 1 : 0);

    out.num(y, 4);
    out.str("-");
    out.num(m, 2);
    out.str("-");
    out.num(d, 2);
    out.str(" ");
    out.num(secs / 3600, 2);
    out.str(":");
    out.num(secs / 60 % 60, 2);
    out.str(":");
    out.num(secs % 60, 2);
}
}  // namespace

void init(const std::string& path) {
    // write_signal_safe가 쓸 시간대 오프셋을 미리 계산 (핸들러에서는 localtime 호출 불가)
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    g_utc_offset_sec = tm.tm_gmtoff;

    if (path.empty()) return;
    g_file_fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (g_file_fd < 0) std::perror("logger: open");
}

void write(const char* tag, const std::string& msg) {
    char ts[32];
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    std::strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);

    std::string line = std::string(ts) + " [pid=" + std::to_string(::getpid()) + "] [" + tag +
                       "] " + msg + "\n";
    write_all(STDERR_FILENO, line);
    if (g_file_fd >= 0) write_all(g_file_fd, line);  // O_APPEND: 부모·자식이 같이 써도 줄 단위 보존
}

void write_signal_safe(const char* tag, const char* msg) {
    RawLine line;
    put_timestamp(line);
    line.str(" [pid=");
    line.num(static_cast<unsigned long long>(::getpid()));
    line.str("] [");
    line.str(tag);
    line.str("] ");
    line.str(msg);
    line.str("\n");
    raw_write_all(STDERR_FILENO, line.data, line.len);
    if (g_file_fd >= 0) raw_write_all(g_file_fd, line.data, line.len);
}

}  // namespace hp::logger
