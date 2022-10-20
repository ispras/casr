#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }

    if (argv[1][0] == 'A')
    {
        abort();
    }
    return 0;
}
