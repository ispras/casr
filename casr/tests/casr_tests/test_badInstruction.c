

/* test.c  for ReturnAv*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])

{
    asm(".byte 0x0f, 0x0b");
    return 0;
}
