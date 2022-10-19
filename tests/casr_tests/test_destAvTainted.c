#include <math.h>
#include <stdio.h>
#include <stdlib.h>

unsigned long long c = 42;
unsigned long long b = 0xcafecafedeadbeaf;

int
main(int argc, char* argv[])
{
    unsigned long long* p[2];
    p[0] = &c;
    p[1] = &b;
    int a = atoi(argv[1]);
    *p[a] = a + b;
    return 0;
}
