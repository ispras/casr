#include <napi.h>
#include <stdio.h>

void foo(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    uint8_t buf[] = {1, 2, 3};
    Napi::Buffer<uint8_t> arr = Napi::Buffer<uint8_t>::New(env, &buf[0], 3);
    arr[5u] = 1;
    printf("Number: %u\n", arr[5u]);
    // throw Napi::String::New(env, "error in native lib");
}

Napi::Object init(Napi::Env env, Napi::Object exports)
{
    exports.Set(Napi::String::New(env, "foo"), Napi::Function::New(env, foo));
    return exports;
};

NODE_API_MODULE(native, init);
