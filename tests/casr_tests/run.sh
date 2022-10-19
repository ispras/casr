#!/bin/bash

# test returnAV
./test_returnAv $(printf 'A%.s' {1..140})

# test abort
./test_abort $(printf 'A%.s' {1..200})

# test segFaultOnPc
./test_segFaultOnPc $(printf 'A%.s' {1..126}) 

# test destAv
./test_destAv $(printf 'A%.s' {1..200}) 

# test destAvNearNull
./test_destAvNearNull $(printf 'A%.s' {1..100}) 

# test sourceAv
./test_sourceAv $(printf 'A%.s' {1..200}) 

# test sourceAvNearNull
./test_sourceAvNearNull 

# test callAv
./test_callAv -11111111

# test callAvTainted
./test_callAvTainted -11111111

# test destAvTainted
./test_destAvTainted -11111111

# test_badInstruction
./test_badInstruction

# test_stackOverflow
./test_stackOverflow

#test stack_cannary
./test_canary $(printf 'A%.s' {1..120}) 

#test safeFunc
./test_safeFunc $(printf 'A%.s' {1..120}) 

# test heapError
./test_heapError $(printf 'A%.s' {1..120})

# test DivByZero
./test_DivByZero

# test returnAV32
./test_returnAv32 $(printf 'A%.s' {1..140})

# test abort32
./test_abort32 $(printf 'A%.s' {1..120})

# test segFaultOnPc32
./test_segFaultOnPc32 $(printf 'A%.s' {1..200}) 

# test destAv32
./test_destAv32 $(printf 'A%.s' {1..200}) 

# test destAvNearNull32
./test_destAvNearNull32 $(printf 'A%.s' {1..100}) 

# test sourceAv32
./test_sourceAv32 $(printf 'A%.s' {1..200}) 

# test sourceAvNearNull32
./test_sourceAvNearNull32 

# test callAvReg32
./test_callAv32 1234324

#test stack_cannary32
./test_canary32 $(printf 'A%.s' {1..120}) 

# test heapError32
./test_heapError32 $(printf 'A%.s' {1..120})

# test DivByZero32
./test_DivByZero32

# test_badInstruction32
./test_badInstruction32

#test safeFunc
./test_safeFunc32 $(printf 'A%.s' {1..120}) 

exit $ERR
