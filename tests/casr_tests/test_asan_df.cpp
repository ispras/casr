#include <iostream>

int
main(int argc, char** argv)
{
    int* a = (int*)malloc(sizeof(int));
    free(a);
    free(a);
    return 0;
}
