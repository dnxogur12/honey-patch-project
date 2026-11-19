#include "common/logger.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <ctime>

namespace hp::logger {

namespace {
int g_file_fd = -1;

void write_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::write(fd, s.data() + off, s.size() - off);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}
}  // namespace

void init(const std::string& path) {
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

}  // namespace hp::logger
