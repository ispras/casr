#include <math.h>
#include <stdio.h>
#include <stdlib.h>

void
func1(){};

void
func2(){};

int
main(int argc, char* argv[])
{
    int (*p[2])();
    p[0] = func1;
    char buff[100];
    /*if no argument*/
    int a = atoi(argv[1]);
    p[a]();
    return 0;
}
