/* Synthetic coverage fixture only. This is not a vulnerability in a product. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned char input[4096] = {0};
    FILE *f = stdin;
    if (argc > 1) { f = fopen(argv[1], "rb"); if (!f) return 2; }
    size_t n = fread(input, 1, sizeof(input), f);
    if (f != stdin) fclose(f);
    if (n > 0 && input[0] == 'Z') {
        if (n > 1 && input[1] == 'Z') abort();
        puts("PREFIX");
    } else { puts("NORMAL"); }
    return 0;
}
