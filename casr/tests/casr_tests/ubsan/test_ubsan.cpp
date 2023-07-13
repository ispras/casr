#include <stdint.h>

int main() {
    (void)(uint16_t(0xffff) * uint16_t(0x8001));
    int x = 1;
    x / 0;
    return 0;
}
