#include "Test2.h"

JNIEXPORT jint JNICALL Java_Test2_heapbufferoverflow(JNIEnv *, jobject) {
    int a[5];
    a[5] = 1;
    return a[5];
}
