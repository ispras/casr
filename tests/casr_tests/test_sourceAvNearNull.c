#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])
{
    uintptr_t* magic = 0;
    uintptr_t* num = NULL;
    magic = (uintptr_t)*num;
    return 0;
}
