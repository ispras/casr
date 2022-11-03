#include <iostream>

class A {
public:
    int a;
    int b;
};

int main(int argc, char** argv) {
    switch (argc) {
        case 1:
            return reinterpret_cast<A*>(0)->b;
        case 2:
            reinterpret_cast<A*>(0)->b = 1;
        case 3:
            return reinterpret_cast<A*>(0xffff)->b;
        default:
            reinterpret_cast<A*>(0xffff)->b = 1;
    }
    return 0;
}
