extern put_value
extern get_value
RESET_REGISTER equ 0
; I use the value 'N' to indicate that a lock is open, as no core is assigned the number 'N'.
OPEN_LOCK equ N
ALIGN_VALUE equ 0x8
; Macro aligns the stack - depending on the value of rsp, changed value of rbx is subtracted.
%macro  stack_align 1
        mov     ebx, esp
        ; Depending on the value of esp, ebx contains 0x0 or 0x8.
        and     ebx, ALIGN_VALUE
        sub     rsp, rbx
        call    %1
        add     rsp, rbx
%endmacro
section .data
; Array of locks - each thread has one lock.
align 16
locks: times N dq OPEN_LOCK
section .bss
; Array stores values that are supposed to be exchanged according to
; operation encoded by 'S'.
align 16
values: resq N
section .text
align 16
global core
; RDI - contains n, the number of a core.
; RSI - contains a pointer p to a string that encodes operations.
; The function <core> performs calculations encoded in the given string.
; RAX - value stored in this register at the end is result of all performed operations.
core:
        ; I store preserved registers to preserve their values and may 
        ; use them later as storage.
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        ; I use preserved registers as storage because other registers
        ; may be changed after calling other functions.
        ; I store stack pointer in rbp.
        mov     rbp, rsp
        ; I store encoding string in r12.
        mov     r12, rsi
        ; I store n (number of the core) in r13.
        mov     r13, rdi
        ; I store array of locks in r14.
        lea     r14, [rel locks]
        ; I store array of values that are supposed to be exchanged in r15.
        lea     r15, [rel values]
.loop:
        ; I read each byte and perform operations accordingly.
        mov     rax, RESET_REGISTER
        mov     al, BYTE [r12]      
        ; I need to check if I should continue reading.
        cmp     al, 0
        jz      .exit
        inc     r12
        ; I jump to the label in order to perform the operation encoded by
        ; the given character.
        cmp     al, 'n'
        je      .PUT_CORE
        cmp     al, 'G'
        je      .GET_VALUE
        ; Some of the given operations perform on the popped argument,
        ; so I pop it here to shorten the code. As a result, the first popped value
        ; in sections of code marked by labels below is stored in r9.
        pop     r9
        cmp     al, '-'
        je      .NEG
        cmp     al, 'D'
        je      .DUP
        cmp     al, '+'
        je      .ADD
        cmp     al, '*'
        je      .MUL
        cmp     al, 'B'
        je      .POP_MOVE
        cmp     al, 'C'
        je      .loop
        cmp     al, 'E'
        je      .SWAP
        cmp     al, 'P'
        je      .PUT_VALUE
        cmp     al, 'S'
        je      .SYNCHRONIZE
; Pushes given digit on the stack.
.NUMBER:
        ; Changes character into number.
        sub     al, '0'
        ; I push r9, because I popped it earlier and it was the most
        ; effective way to make code shorter.
        push    r9
        jmp     .push_rax
; Adds two values at the top of the stack (first value is stored in r9).
.ADD:
        add     [rsp], r9
        jmp     .loop
; Multiplies two values at the top of the stack.
.MUL:
        pop     rax
        imul    r9
.push_rax:
        push    rax
        jmp     .loop
; Negates the value at the top of the stack.
.NEG:
        neg     r9
.push_r9:
        push    r9
        jmp     .loop
; Pushes n (number of the given core) on the stack.
.PUT_CORE:
        push    r13
        jmp     .loop
; Checks if the next numer is 0, if not, moves the beginning of the stack accordingly.
.POP_MOVE:
        mov     r10, [rsp]
        cmp     r10, 0
        je      .loop
        add     r12, r9
        jmp     .loop
; Duplicates value at the top of the stack (stored in r9).
.DUP:
        push    r9
        jmp     .push_r9
; Swaps two elements at the top of the stack (stored in r9 and rax).
.SWAP:
        pop     rax
        push    r9
        jmp     .push_rax
; Calls external function <get_value> and pushes its result on the stack.
.GET_VALUE:
        ; The argument is passed to the function via the rdi register.
        mov     rdi, r13
        ; I need to align stack accordingly.
        stack_align get_value
        ; Result is stored in rax and it must be pushed on the stack.
        jmp     .push_rax
; Calls external function <put_value>.
.PUT_VALUE:
        ; The arguments are passed to the function via the rdi and rsi registers.
        mov     rsi, r9
        mov     rdi, r13
        ; I need to align stack accordingly.
        stack_align put_value
        jmp     .loop
; Synchronizes two threads and switches their values.
.SYNCHRONIZE:
        ; I store the value that is supposed to be switched in
        ; the array <values>, stored in r15.
        pop     QWORD [r15 + r13 * 8];
        ; I create a copy of r9.
        mov     r8, r9
        ; I operate on a copy to not to loose r9. Moreover,
        ; after exchange I have <OPEN_LOCK> in r8 and I can use it later.
        xchg    QWORD [r14 + r13 * 8], r8
; First lock - first thread waits for the second one.
.busy_wait:
        ; This lock waits until lock[m] = n, which means it waits until the second thread
        ; also wants to exchange.
        mov     rax, r13
        lock \
        cmpxchg QWORD [r14 + r9 * 8], r13     
        jne     .busy_wait     
        ; New value is pushed on the stack.
        push    QWORD [r15 + r9 * 8]
        ; I open the lock of the second thread - I set its lock on <OPEN_LOCK>.
        xchg    QWORD [r14 + r9 * 8], r8
        mov     r8, OPEN_LOCK
; Second lock - thread waits till its 'brother' is ready and unlocks it.
.busy_wait2:
        ; Lock waits until its lock is set to <OPEN_LOCK>.
        mov     rax, r8
        lock \
        cmpxchg QWORD [r14 + r13 * 8], r8
        jne     .busy_wait2     
        jmp     .loop
.exit:
        pop     rax
        ; Preserved registers need to be restored.
        mov     rsp, rbp
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret