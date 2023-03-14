#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])
{
    uintptr_t* magic = 0;
    struct Test
    {
        char buff[64];
        uintptr_t* num;
    } test;

    if (argc < 2)
    {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }

    strcpy(test.buff, argv[1]);
    magic = (uintptr_t)*test.num;
    return 0;
}
