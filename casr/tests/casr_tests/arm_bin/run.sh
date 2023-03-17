#!/bin/bash

# This file is needed for coredump generation and online testing of the Casr

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

# test callAvTainted
./test_callAvTainted -11111111

# test destAvTainted
./test_destAvTainted -11111111

# test_badInstruction
./test_badInstruction

#test stack_cannary
./test_canary $(printf 'A%.s' {1..120}) 

#test safeFunc
./test_safeFunc $(printf 'A%.s' {1..120}) 

# test heapError
./test_heapError $(printf 'A%.s' {1..120})

exit $ERR
