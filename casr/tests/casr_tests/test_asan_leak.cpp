#include <stdlib.h>

void* p;

int
main()
{
    p = malloc(7);
    p = NULL;  // The memory is leaked here.
    // free(p);
    return 0;
}
