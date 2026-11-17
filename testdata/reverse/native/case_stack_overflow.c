/* Synthetic local-only ASan fixture. Input byte '!' triggers a stack overwrite. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char input[32] = {0};
    size_t n = fread(input, 1, sizeof(input), stdin);
    if (n == 0 || input[0] != '!') return 0;
    puts("ASAN_STACK_TRIGGER"); fflush(stdout);
    char small[8] = {0};
    volatile size_t controlled = n;
    memcpy(small, input, controlled); /* Deliberate stack-buffer-overflow for ASan. */
    return small[0] == '!';
}
