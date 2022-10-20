

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])
{

    /*if no argument*/

    if (argc < 2)
    {

        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }

    char* buff = malloc(100);
    char* buff2 = malloc(100);
    strcpy(buff, argv[1]);
    free(buff);
    free(buff2);
    return 0;
}
