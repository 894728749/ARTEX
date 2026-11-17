/* Synthetic local impact fixture: exact input IMPACT prints one harmless marker. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char input[16] = {0};
    size_t n = fread(input, 1, sizeof(input), stdin);
    if (n == 6 && memcmp(input, "IMPACT", 6) == 0) {
        puts("LOCAL_IMPACT_MARKER");
        return 0;
    }
    puts("NORMAL_INPUT");
    return 0;
}
