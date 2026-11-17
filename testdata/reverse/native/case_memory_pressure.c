/* Exceeds the runner 512 MiB RAM + default 512 MiB swap budget. */
#include <stdlib.h>
#include <string.h>

int main(void) {
    const size_t bytes = 1280u * 1024u * 1024u;
    volatile unsigned char *p = (volatile unsigned char *)malloc(bytes);
    if (!p) return 10;
    for (size_t i = 0; i < bytes; i += 4096) p[i] = (unsigned char)i;
    return 0;
}
