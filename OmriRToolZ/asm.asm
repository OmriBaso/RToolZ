.code

EXTERN  OB97_GetNumber: PROC

besomemset_stosb PROC
        push rdi
        mov     rax, rdx                        ; set byte to move
        mov     rdi, rcx                        ; set destination
        mov     rcx, r8                         ; set count
        rep     stosb                           ; store the bytes

        mov rax, rdi
        pop rdi
        ret                                     ; return
besomemset_stosb ENDP

besomemcpy_fast PROC
	 mov r10, rdi ; save the values 
	 mov r11, rsi ; save the values currently in the stack
	 mov rdi, rcx ; move the first parameter that was sent to be the destination buffer
	 mov rsi, rdx ; move the second parameter that was sent to be the source buffer
	 mov rcx, r8 ; move the third parameter that was sent to be the size of the of the source buffer
	 shr rcx, 3 ; Signed division by 8 because we are on 64 bit, so we split the size into the number of bytes we transfer, for example 76 / 8
	 rep movsq ; move qword (move in bigger chunks of memroy)
	 mov rcx, r8 ;  now move the size again, 
	 and rcx, 7 ; assign and operand on rcx to zero out the remaining bytes
	 rep movsb ; loop on them
	 mov rsi, r11 ; restore registers
	 mov rdi, r10
	 ret
besomemcpy_fast ENDP

_NtOpenProcess PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0CC57D5FBh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtOpenProcess ENDP


_NtCreateProcessEx PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0818C35B3h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtCreateProcessEx ENDP


_NtOpenProcessToken PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 04B9D348Ch        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtOpenProcessToken ENDP


_NtGetNextProcess PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0C558DCF4h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtGetNextProcess ENDP

_NtQueryInformationProcess PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0C2BCDD50h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtQueryInformationProcess ENDP


_NtQueryVirtualMemory PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 00597715Bh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtQueryVirtualMemory ENDP


_NtAdjustPrivilegesToken PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0858DD14Fh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtAdjustPrivilegesToken ENDP


_NtAllocateVirtualMemory PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0C358FDDFh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtAllocateVirtualMemory ENDP


_NtFreeVirtualMemory PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 043AD294Fh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtFreeVirtualMemory ENDP


_NtCreateFile PROC
 	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 02C9BA68Eh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtCreateFile ENDP


_NtWriteFile PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0E879BA4Eh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtWriteFile ENDP

_NtReadVirtualMemory PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 057D3575Bh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtReadVirtualMemory ENDP


_NtClose PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0CE97C93Dh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtClose ENDP


_NtCreateThreadEx  PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0dc411216h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtCreateThreadEx ENDP

_NtGetContextThread   PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0340f3ea1h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtGetContextThread  ENDP

_NtDelayExecution   PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0850d9a84h        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtDelayExecution  ENDP

_NtResumeThread   PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 07eda3c7bh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtResumeThread  ENDP

_NtSetContextThread  PROC
	push rcx          ; Save registers.
	push rdx
	push r8
	push r9
	sub rsp, 28h
	mov ecx, 0b4acfa7eh        ; Load function hash into ECX.
	call OB97_GetNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	pop r9          ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
_NtSetContextThread ENDP

end