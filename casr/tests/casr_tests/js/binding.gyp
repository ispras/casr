{
    "targets": [
        {
            "cflags": [ "-fexceptions -fsanitize=address,fuzzer-no-link -O0 -g -fPIC" ],
            "cflags_cc": [ "-fexceptions -fsanitize=address,fuzzer-no-link -O0 -g -fPIC" ],
            "include_dirs" : ["<!@(node -p \"require('node-addon-api').include\")"],
            "target_name": "native",
            "sources": [ "native.cpp" ],
            'defines': [ 'NAPI_CPP_EXCEPTIONS' ]
        }
    ]
}
