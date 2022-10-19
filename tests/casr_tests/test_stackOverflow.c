#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
f()
{
    f();
}

int
main(int argc, char* argv[])
{
    f();
    return 0;
}
