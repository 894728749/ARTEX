#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += (size_t)w; n -= (size_t)w;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "nonzero") == 0) return 23;
    if (argc > 1 && strcmp(argv[1], "segv") == 0) raise(SIGSEGV);
    if (argc > 1 && strcmp(argv[1], "sleep") == 0) {
        for (;;) pause();
    }
    unsigned char buf[4096];
    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n <= 0) break;
        if (write_all(STDOUT_FILENO, buf, (size_t)n) != 0) return 24;
    }
    return 0;
}
