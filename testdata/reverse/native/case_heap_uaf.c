/* Synthetic local-only ASan fixture. Input byte '!' triggers a heap UAF. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int trigger = getchar();
    if (trigger != '!') return 0;
    puts("ASAN_UAF_TRIGGER"); fflush(stdout);
    volatile int *value = (int *)malloc(sizeof(*value));
    if (!value) return 2;
    *value = 7;
    free((void *)value);
    return *value; /* Deliberate heap-use-after-free for ASan. */
}
