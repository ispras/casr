{
    "targets": [
        {
            "cflags": [ "-fexceptions -fsanitize=address,fuzzer-no-link -O0 -g -fPIC -I/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/ -lclang_rt.fuzzer-x86_64" ],
            "cflags_cc": [ "-fexceptions -fsanitize=address,fuzzer-no-link -O0 -g -fPIC -I/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/ -lclang_rt.fuzzer-x86_64" ],
            "include_dirs" : ["<!@(node -p \"require('node-addon-api').include\")"],
            "target_name": "native",
            "sources": [ "native.cpp" ],
            'defines': [ 'NAPI_CPP_EXCEPTIONS' ]
        }
    ]
}
