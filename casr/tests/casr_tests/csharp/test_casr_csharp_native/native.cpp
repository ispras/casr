#include <iostream>

extern "C" void seg(int len)
{
    int a[10];
    a[len] = -1;
}
