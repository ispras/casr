## Severity classes

In this section crash severity classes are described. Crash Classes are gathered in 3 groups: exploitable, possible exploitable, not exploitable. Some class prototypes are taken from the open source library [gdb-exploitable](https://github.com/jfoote/exploitable.git).

### EXPLOITABLE

Critical classes are most dangerous. This crash could be easily control flow hijecked by attackers to transfer control flow. List of classes:

1. **SegFaultOnPc**. The target tried to access data at an address that matches the program counter. This likely indicates that the program counter contents are tainted and can be controlled by an attacker.
2. **ReturnAv**. The target crashed on a return instruction, which likely indicates stack corruption.
3. **BranchAv**. The target crashed on a branch instruction, which may indicate that the control flow is tainted.
4. **CallAv**. The target crashed on a call instruction, which may indicate that the control flow is tainted.
5. **DestAv**. The target crashed on an access violation at an address matching the destination operand of the instruction. This likely indicates a write access violation, which means the attacker may control the write address and/or value.
6. **BranchAvTainted**. The target crashed on loading from memory (SourceAv). After taint tracking, target operand of branch instruction could be tainted. Corresponds to BranchAv class.
7. **CallAvTainted**. The target crashed on loading from memory (SourceAv). After taint tracking, target operand of branch instruction could be tainted. Corresponds to CallAv class.
8. **DestAvTainted**. TheThe target crashed on loading from memory (SourceAv). After taint tracking, target operand of branch instruction could be tainted. Corresponds to DestAv class.
9. **heap-buffer-overflow(write)**. The target writes data past the end, or before the beginning, of the intended heap buffer.
10. **global-buffer-overflow(write)**. The target writes data past the end, or before the beginning, of the intended global buffer.
11. **stack-use-after-scope(write)**. The target crashed when writing on a stack address outside the lexical scope of a variable's lifetime.
12. **stack-use-after-return(write)**. The target crashed when writing to a stack memory of a returned function.
13. **stack-buffer-overflow(write)**. The target writes data past the end, or before the beginning, of the intended stack buffer.
14. **stack-buffer-underflow(write)**. The target writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.
15. **heap-use-after-free(write)**. The target crashed when writing to memory after it has been freed.
16. **container-overflow(write)**. The target crashed when writing to memory inside the allocated heap region but outside of the current container bounds.
17. **param-overlap**. Call to function disallowing overlapping memory ranges.

### PROBABLY\_EXPLOITABLE

Possible exploitable classes are needed some extra (often manual) analysis steps to determine if control flow hijeck is possible or not. List of classes:

1. **BadInstruction**. The target tried to execute a malformed or privileged instruction. This may indicate that the control flow is tainted.
2. **SegFaultOnPcNearNull**. The target tried to access data at an address that matches the program counter. This may indicate that the program counter contents are tainted, however, it may also indicate a simple NULL deference.
3. **BranchAvNearNull**. The target crashed on a branch instruction, which may indicate that the control flow is tainted. However, there is a chance it could be a NULL dereference.
4. **CallAvNearNull**. The target crashed on a call instruction, which may indicate that the control flow is tainted. However, there is a chance it could be a NULL dereference.
5. **HeapError**. The target program is aborted due to error produced by heap allocator functions.
6. **StackGuard**. The target program is  aborted due to stack cookie overwrite.
7. **DestAvNearNull**. The target crashed on an access violation at an address matching the destination operand of the instruction. This likely indicates a write access violation, which means the attacker may control write address and/or value. However, it there is a chance it could be a NULL dereference.
8. **heap-buffer-overflow**. The target attempts to read or write data past the end, or before the beginning, of the intended heap buffer.
9. **global-buffer-overflow**. The target attempts to read or write data past the end, or before the beginning, of the intended global buffer.
10. **stack-use-after-scope**. The target crashed when using a stack address outside the lexical scope of a variable's lifetime.
11. **use-after-poison**. The target crashed on trying to use the memory that was previously poisoned.
12. **stack-use-after-return**. The target crashed when using a stack memory of a returned function.
13. **stack-buffer-overflow**. The target attempts to read or write data past the end, or before the beginning, of the intended stack buffer.
14. **stack-buffer-underflow**. The target is using buffer with an index or pointer that references a memory location prior to the beginning of the buffer.
15. **heap-use-after-free**. The target crashed when using memory after it has been freed.
16. **container-overflow**. The target crashed when using memory inside the allocated heap region but outside of the current container bounds.
17. **negative-size-param**. Negative size used when accessing memory.
18. **calloc-overflow**. Overflow in calloc parameters.
19. **readllocarray-overflow**. Overflow in realloc parameters.
20. **pvalloc-overflow**. Overflow in pvalloc parameters.
21. **overwrites-const-input**. Fuzz target overwrites its constant input.

### NOT\_EXPLOITABLE

Not exploitable classes are needed extra analysis manual analysis to determine if control flow hijeck is possible or not. Also it could be deny of service crash. Lists of classes:

1. **SourceAv**. The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation.
2. **AbortSignal**. The target is stopped on a SIGABRT. SIGABRTs are often generated by libc and compiled check-code to indicate potentially critical conditions.
3. **AccessViolation**. The target crashed due to an access violation but there is not enough additional information available to determine severity of a crash. Manual analysis is needed.
4. **SourceAvNearNull**. The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation, which may mean the application crashed on a simple NULL dereference to data structure that has no immediate effect on control of the processor.
5. **SafeFunctionCheck**. The target program is aborted  due to safe functin check guard: \_chk().
6. **FPE**. The target crashed due to arithmetic exception.
7. **StackOverflow**. The target crashed on an access violation where the faulting instruction's mnemonic and the stack pointer seem to indicate a stack overflow.
8. **double-free**. The target crashed while trying to deallocate already freed memory.
9. **bad-free**. The target crashed on attempting free on address which was not malloc()-ed.
10. **alloc-dealloc-mismatch**. Mismatch between allocation and deallocation APIs.
11. **heap-buffer-overflow(read)**. The target reads data past the end, or before the beginning, of the intended heap buffer.
12. **global-buffer-overflow(read)**. The target reads data past the end, or before the beginning, of the intended global buffer.
13. **stack-use-after-scope(read)**. The target crashed when reading from a stack address outside the lexical scope of a variable's lifetime.
14. **stack-use-after-return(read)**. The target crashed when reading from a stack memory of a returned function.
15. **stack-buffer-overflow(read)**. The target reads data past the end, or before the beginning, of the intended stack buffer.
16. **stack-buffer-underflow(read)**. The target reads from a buffer using buffer access mechanisms such as indexes or pointers that reference memory locations prior to the targeted buffer.
17. **heap-use-after-free(read)**. The target crashed when reading from memory after it has been freed.
18. **container-overflow(read)**. The target crashed when reading from memory inside the allocated heap region but outside of the current container bounds.
19. **initialization-order-fiasco**. Initializer for a global variable accesses dynamically initialized global from another translation unit, which is not yet initialized.
20. **new-delete-type-mismatch**. Deallocation size different from allocation size.
21. **bad-malloc_usable_size**. Invalid argument to `malloc_usable_size`.
22. **odr-violation**. Symbol defined in multiple translation units.
23. **memory-leaks**. The target does not sufficiently track and release allocated memory after it has been used, which slowly consumes remaining memory.
24. **invalid-allocation-alignment**. Invalid allocation alignment.
25. **invalid-aligned-alloc-alignment**. Invalid alignment requested in `aligned_alloc`.
26. **invalid-posix-memalign-alignment**. Invalid alignment requested in `posix_memalign`.
27. **allocation-size-too-big**. Requested allocation size exceeds maximum supported size.
28. **out-of-memory**. The target has exceeded the memory limit.
29. **fuzz target exited**. Fuzz target exited.
30. **timeout**. Timeout after several seconds.
