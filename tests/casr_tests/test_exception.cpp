#include <stdexcept>

void myfunc() { throw std::runtime_error("ExceptionMessage"); }

int main() { myfunc(); }
