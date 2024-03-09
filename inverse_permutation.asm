; Inverse Permutation
; author: Maria Wysogląd
global inverse_permutation
SET_BIT_VISITED equ 0x80000000
RESET_BIT_VISITED equ 0x7fffffff
INT_MAX equ 0x7fffffff
section .text
; RDI - contains n, the size of the analyzed data.
; RSI - contains pointer to the array.
; The function <inverse_permutation> checks if n is in range from 1 to INT_MAX + 1
; and if the given array contains numbers from 0 to n-1.
; If so, it reverses the given permutation.
; RAX - value stored in this register at the end informs if reversal occured,
; if so, it contains 1 (true), otherwise it contains 0 (false).
inverse_permutation:
        ; At the beginning, we check if first argument (n)
        ; is within the given boundaries <1; INT_MAX + 1>.
        mov     rcx, rdi
        ; In order to do it in one compare instruction, we decrement rcx.
        dec     rcx
        cmp     rcx, INT_MAX
        jae     .exit_false
.loop_check:
        ; We check if given data satisfies the given conditions.
        ; We use rcx as counter now (it starts at n-1) and
        ; we get the number from a given place in the array.
        mov     eax, DWORD [rsi+rcx*4]
        ; We reset bit in case it was set earlier.
        and     eax, RESET_BIT_VISITED
        ; We check if we are out of range.
        cmp     eax, edi
        ; In such case, we'll return false, but first,
        ; we need to reset values in the array.
        jae     .exit_fix_set
        ; Otherwise, we get element from cell at the position
        ; stored in rax.
        mov     r9d, DWORD [rsi+rax*4]
        ; We need to check if given value is within range
        ; and if the 32nd bit is set. In these cases, input
        ; is not a permutation.
        cmp     r9d, edi
        jae     .exit_fix_set
        ; If everything is correct,  we mark the number as visited
        ; We set these bits in order to mark number as read.
        ; If permutation is correct, each number should be marked 
        ; once. If there are two same numbers, they point the same 
        ; element, so this element is already set when second number 
        ; points it. Thus, such an error will be found.
        or      DWORD [rsi+rax*4], SET_BIT_VISITED
        dec     ecx
        jns     .loop_check
.reset_counter:
        ; We use ecx as a counter again, with n-1 as the starting point.
        mov     ecx, edi
        dec     ecx
.main_loop:
        ; Reversing permutation is the same with rotating by two each cycle.
        ; In order to do so, we need two variables to store previous
        ; values, so we use r10d and r9d.
        mov     r10d, DWORD [rsi+rcx*4]
        ; At the beginnging, each value has bit 32nd marked, so it is smaller
        ; than 0. If it is greater than 0, it means this value was already
        ; reversed.
        cmp     r10d, 0x0
        jge     .decrement
        and     r10d, RESET_BIT_VISITED
        mov     r9d, DWORD [rsi+r10*4]
        and     r9d, RESET_BIT_VISITED
.cycle_loop:
        mov     r8d, DWORD [rsi+r9*4]
        ; We are getting new values till we find a positive number
        ; - it means we rotated the cycle and can go to the next one.
        cmp     r8d, 0x0
        jge     .decrement
        and     r8d, RESET_BIT_VISITED
        ; We set the new value at the given position, this value doesn't 
        ; have the 32nd bit set.
        mov     DWORD [rsi+r9*4], r10d
        ; At the end, we update variables.
        mov     r10d, r9d
        mov     r9d, r8d
        jmp     .cycle_loop
.decrement:
        dec     ecx
        jns     .main_loop
.exit_true:
        ; We reset the value of the register.
        xor     eax, eax
        inc     eax
        ret
.exit_fix_set:
        ; If input is incorrect, some changes have aleady been made
        ; and they need to be undone, so we fix the table by restoring
        ; values pointed to by numbers from the 
        ; <number_with_incorrect_input + 1>th to (n-1)th cell.
        inc     ecx
.exit_fix_loop:
        ; We fix the array just as we have set it up - we change the value
        ; from given cell in order to make it point to another one.
        cmp     ecx, edi
        jae     .exit_false
        mov     eax, DWORD [rsi+rcx*4]
        and     eax, RESET_BIT_VISITED
        ; Then we reset its value and put it back to memory.
        and     DWORD [rsi+rax*4], RESET_BIT_VISITED
        inc     ecx
        jmp     .exit_fix_loop
.exit_false:
        xor     eax, eax
        ret