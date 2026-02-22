; syscalls.asm - x64 syscall stubs (MASM)
; Syscall numbers are for Windows 10 20H1. Adjust as needed or use dynamic retrieval.
; syscalls.asm - x64 syscall stubs (MASM)
; Syscall numbers as per your input:
;   NtUnmapViewOfSection: 0x2A
;   NtWriteVirtualMemory: 0x3A
;   NtReadVirtualMemory: 0x3F
;   NtAllocateVirtualMemory: 0x18
;   NtProtectVirtualMemory: 0x50
;   NtResumeThread: 0x52
;   NtSetContextThread: 0x18D

.code

SysNtUnmapViewOfSection proc
    mov r10, rcx
    mov eax, 02Ah      ; NtUnmapViewOfSection
    syscall
    ret
SysNtUnmapViewOfSection endp

SysNtWriteVirtualMemory proc
    mov r10, rcx
    mov eax, 03Ah      ; NtWriteVirtualMemory
    syscall
    ret
SysNtWriteVirtualMemory endp

SysNtReadVirtualMemory proc
    mov r10, rcx
    mov eax, 03Fh      ; NtReadVirtualMemory
    syscall
    ret
SysNtReadVirtualMemory endp

SysNtAllocateVirtualMemory proc
    mov r10, rcx
    mov eax, 018h      ; NtAllocateVirtualMemory
    syscall
    ret
SysNtAllocateVirtualMemory endp

SysNtProtectVirtualMemory proc
    mov r10, rcx
    mov eax, 050h      ; NtProtectVirtualMemory
    syscall
    ret
SysNtProtectVirtualMemory endp

SysNtResumeThread proc
    mov r10, rcx
    mov eax, 052h      ; NtResumeThread
    syscall
    ret
SysNtResumeThread endp

SysNtSetContextThread proc
    mov r10, rcx
    mov eax, 18Dh      ; NtSetContextThread
    syscall
    ret
SysNtSetContextThread endp

end
