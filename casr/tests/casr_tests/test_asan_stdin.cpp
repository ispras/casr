#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
    int n;
    scanf("%d", &n);
    if (n == 1)
    {
        n = 1 / (n - 1);
    }
    int* p = (int*)malloc(sizeof(*p) * n);
    for (int i = 0; i < n; ++i)
    {
        p[i] = 1;
    }
    if (n < 5)
    {
        p[4] = 1;
    }
    free(p);
    return 0;
}
