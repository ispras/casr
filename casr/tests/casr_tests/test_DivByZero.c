#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int
main(void)
{
    srand(time(NULL));
    int x = 0;
    while (x = rand() % 2)
    {
    }
    printf("%d\n", 1 / x);
    return 0;
}
