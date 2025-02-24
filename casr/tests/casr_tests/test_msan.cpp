#include <stdio.h>

void set_val(bool &b, const int val) {
    if (val > 1) {
        b = false;
    }
}

int main(const int argc, const char *[]) {
    bool b;
    set_val(b, argc);
    if (b) {
        printf("value set\n");
    }
}