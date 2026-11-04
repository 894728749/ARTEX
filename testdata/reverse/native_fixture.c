#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, visibility("default"))) int artex_transform(int value) {
    return value * 3 + 7;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 100; ++i) {
        printf("ARTEX_FIXTURE %d\n", artex_transform(3));
        usleep(100000);
    }
    return 0;
}
