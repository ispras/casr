#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
copyTolocal(char* ptr)
{
    char buff[100];
    strcpy(buff, ptr);
}

int
main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }

    copyTolocal(argv[1]);
    return 0;
}
