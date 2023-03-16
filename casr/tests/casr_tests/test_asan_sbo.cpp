#include <iostream>

int
main(int argc, char** argv)
{
    int a[3];
    for (int i = 0; i < 4; ++i)
    {
        a[i] = 1;
    }
    return a[2];
}
