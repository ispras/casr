

/* test.c  for ReturnAv*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])

{

    char buff[100];

    /*if no argument*/

    if (argc < 2)

    {

        printf("Syntax: %s <input string>\n", argv[0]);

        exit(0);
    }

    strcpy(buff, argv[1]);

    return 0;
}
