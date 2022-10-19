all: test_safeFunc32 test_returnAv test_segFaultOnPc  test_abort test_destAv test_destAvNearNull test_sourceAv test_sourceAvNearNull test_callAv test_heapError test_canary test_callAv32 test_returnAv32 test_segFaultOnPc32 test_abort32 test_destAv32 test_destAvNearNull32 test_sourceAv32 test_sourceAvNearNull32 test_heapError32 test_canary32 test_DivByZero

test_returnAv: test_returnAv.c
	gcc -g  -O0 -fno-stack-protector test_returnAv.c -o test_returnAv
test_segFaultOnPc: test_segFaultOnPc.c
	gcc -g -O0 -fno-stack-protector test_segFaultOnPc.c -o test_segFaultOnPc
test_abort: test_abort.c
	gcc -g -O0 -D_FORTIFY_SOURCE=2 test_abort.c  -o test_abort 
test_destAv: test_destAv.c
	gcc -g -O0 test_destAv.c -o test_destAv
test_destAvNearNull:
	gcc -g test_destAvNearNull.c -o test_destAvNearNull
test_sourceAv: test_sourceAv.c
	gcc -g test_sourceAv.c -o test_sourceAv
test_sourceAvNearNull: test_sourceAvNearNull.c 
	gcc -g  test_sourceAvNearNull.c -o test_sourceAvNearNull
test_callAvTainted: test_callAv.c
	gcc  -g  -O0 test_callAv.c -o test_callAvTainted
test_callAv: test_callAv.c
	gcc  -g  -O2 test_callAv.c -o test_callAv
test_heapError: test_heapError.c
	gcc -g -O0  test_heapError.c -o test_heapError
test_canary: test_returnAv.c
	gcc -g  -O0 -fstack-protector-all test_returnAv.c -o test_canary
test_safeFunc: test_returnAv.c
	gcc -g  -O2 test_returnAv.c -o test_safeFunc
test_badInstruction: test_badInstruction.c
	gcc -O0 ./test_badInstruction.c -o  test_badInstruction
test_stackOverflow: test_stackOverflow.c
	gcc -O0 ./test_stackOverflow.c -o ./test_stackOverflow
test_destAvTainted:	test_destAvTainted.c
	gcc -O0 ./test_destAvTainted.c -o ./test_destAvTainted
test_DivByZero:
	gcc -g test_DivByZero.c -o test_DivByZero
	
test_returnAv32: test_returnAv.c
	gcc -g -m32 -O0 -fno-stack-protector  test_returnAv.c -o test_returnAv32
test_segFaultOnPc32: test_segFaultOnPc.c
	gcc -g -m32 -O0 -fno-stack-protector test_segFaultOnPc.c -o test_segFaultOnPc32
test_abort32:
	gcc -m32 -g -O0 -D_FORTIFY_SOURCE=2 test_abort.c  -o test_abort32
test_destAv32: test_destAv.c
	gcc -g -m32 -O0 test_destAv.c -o test_destAv32
test_destAvNearNull32: test_destAvNearNull.c
	gcc -g -m32 -O0 test_destAvNearNull.c -o test_destAvNearNull32
test_sourceAv32: test_sourceAv.c
	gcc -g -m32  -O0 test_sourceAv.c -o test_sourceAv32
test_sourceAvNearNull32: test_sourceAvNearNull.c
	gcc -g -m32 -O0 test_sourceAvNearNull.c -o test_sourceAvNearNull32
test_callAv32: test_callAv.c
	gcc -m32  -g  -Os test_callAv.c -o test_callAv32
test_heapError32: test_heapError.c
	gcc  -m32  -g -O0  test_heapError.c -o test_heapError32
test_canary32: test_returnAv.c
	gcc -g  -m32  -O0 -fstack-protector-all test_segFaultOnPc.c -o test_canary32
test_DivByZero32:
	gcc -g -m32 test_DivByZero.c -o test_DivByZero32
test_safeFunc32: test_returnAv.c
	gcc -g  -m32 -O2 test_returnAv.c -o test_safeFunc32
test_badInstruction32: test_badInstruction.c
	gcc -O0 -m32 ./test_badInstruction.c -o  test_badInstruction32
clean:
	rm -f test_badInstruction32 test_safeFunc32 test_stackOverflow \ 
		test_badInstruction test_safeFunc test_returnAv test_segFaultOnPc \
		test_abort test_destAv test_destAvNearNull test_sourceAv \ 
		test_sourceAvNearNull test_callAv test_callAv32  test_heapError \ 
		test_canary test_returnAv32 test_segFaultOnPc32 test_abort32 \ 
		test_destAv32 test_destAvNearNull32 test_sourceAv32  \ 
		test_sourceAvNearNull32 test_heapError32 test_canary32 \ 
		test_callAvTainted test_DivByZero test_DivByZero32
