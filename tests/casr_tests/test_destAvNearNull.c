#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])
{
    uintptr_t* num = NULL;
    char buff[100];

    if (argc < 2)
    {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }

    strcpy(buff, argv[1]);
    *num = (uintptr_t)buff[3];
    return 0;
}
