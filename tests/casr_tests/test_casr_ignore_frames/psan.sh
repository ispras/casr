#! /bin/bash

string="
=================================================================\n
==3460602==ERROR: AddressSanitizer: requested allocation size 0xffffffffd4a51000 (0xffffffffd4a52000 after adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)\n
    #0 0x561e08193e0f in abort /home/user/sanitize/size-too-big.cpp:10:25\n
    #2 0x561e08193e0f in exit /home/user/sanitize/size-too-big.cpp:11:25\n
    #3 0x561e08193e0f in bad /usr/include/c++/../../../home/user/sanitize/size-too-big.cpp:12:25\n
    #4 0x561e08193e4a in main /home/user/sanitize/size-too-big.cpp:16:5\n
    #5 0x7f0f079cb082 in __libc_start_main
    /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16\n
\n
==3460602==HINT: if you don't care about these errors you may set allocator_may_return_null=1\n
SUMMARY: AddressSanitizer: allocation-size-too-big (/home/user/sanitize/size-too-big+0xa0c08) (BuildId: 6d361148d8353e252da080b8c2a94c5a91553ab5) in __interceptor_calloc\n
==3460602==ABORTING
"
echo -e $string 1>&2
