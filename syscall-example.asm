;###############################################################################
;#                                                                             #
;# Copyright (C) 2020 by Sylwester Wysocki <sw143@wp.pl>                       #
;#                                                                             #
;# Permission to use, copy, modify, and/or distribute this software for any    #
;# purpose with or without fee is hereby granted.                              #
;#                                                                             #
;# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES    #
;# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF            #
;# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR     #
;# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES      #
;# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN       #
;# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR  #
;# IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.                 #
;#                                                                             #
;###############################################################################

format pe64
entry start

; Created on: 2020-10-18
; Last modified on: 2020-10-18

; Build by:
; fasm syscall-example.asm

; ------------------------------------------------------------------------------
;                                 Constants
; ------------------------------------------------------------------------------

GENERIC_WRITE         EQU 40000000h
FILE_ATTRIBUTE_NORMAL EQU 128
FILE_CREATE           EQU 2
OBJ_CASE_INSENSITIVE  EQU 64

; Hard-coded syscall ids.
; Put values read from your OS here.
;
; WARNING! Syscall ids are not officialy documented by microsoft and
; vary from one version to another. Do *NOT* rely on hard-coded syscall
; ids in production code to get specific NtXxx() function called.
SYSCALL_ID_NtCreateFile       EQU 55h
SYSCALL_ID_NtTerminateProcess EQU 2ch

; ------------------------------------------------------------------------------
;                                Code section
; ------------------------------------------------------------------------------

section '.text' code executable readable

start:

    ; --------------------------------------------------------------------------
    ; https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
    ;
    ; ... = NtCreateFile(&hFile,
    ;                    GENERIC_WRITE,
    ;                    &objectAttributes,
    ;                    &ioStatusBlock,
    ;                    NULL,
    ;                    FILE_ATTRIBUTE_NORMAL,
    ;                    0,
    ;                    FILE_CREATE,
    ;                    0,
    ;                    NULL,
    ;                    0)

    sub      rsp, 32                ; 32-bytes shadow space before call

    ; -----------------------------------
    ; First four parameters in registers:
    ; r10, rdx, r8, r9

    lea      r10, [hFile]           ; r10 = 1st param, rcx can not be used
                                    ; with syscall api

    mov      edx, GENERIC_WRITE     ; rdx = 2nd param
    lea      r8, [objectAttributes] ; r8  = 3rd param
    lea      r9, [ioStatusBlock]    ; r9  = 4th param

    ; -------------------------------
    ; Next parameters on stack
    ; from right-to-left (C-like)

    push     0                      ; 11-th param
    push     0                      ; 10-th param
    push     0                      ; 9-th param
    push     FILE_CREATE            ; 8-th param
    push     0                      ; 7-th param
    push     FILE_ATTRIBUTE_NORMAL  ; 6-th param
    push     0                      ; 5-th param

    mov      eax, SYSCALL_ID_NtCreateFile
                                    ; rax = 55h = syscall id = NtCreateFile
    syscall                         ; call NtCreateFile(...)

    add      rsp, 32+56             ; clean shadow space and pop stack
                                    ; parameters after call

    ; ---------------------------------------
    ; NtTerminateProcess(NULL,
    ;                    NtCreateFile status)

    xor      r10, r10               ; r10 = NULL = process handle
    mov      edx, eax               ; edx = exit code
    mov      eax, 2ch               ; eax = syscall id = NtTerminateProcess()
    syscall                         ; call NtTerminateProcess(...)

    ret

; ------------------------------------------------------------------------------
;                                Data section
; ------------------------------------------------------------------------------

section '.data' data readable writeable

  hFile dq ?

  align 16
  fileNameBuffer:
    du '\??\C:\TEMP\TEST.TXT'
  fileNameBufferEnd:

  fileNameSize EQU fileNameBufferEnd - fileNameBuffer

  align 16
  fileName:
    .Length        dd fileNameSize   ; Buffer length in bytes
    .MaximumLength dd fileNameSize   ; Buffer capacity in bytes
    .Buffer        dq fileNameBuffer ; Pointer to buffer data

  align 16
  objectAttributes:
    .Length                   dq 48
    .RootDirectory            dq 0
    .ObjectName               dq fileName
    .Attributes               dq OBJ_CASE_INSENSITIVE
    .SecurityDescriptor       dq 0
    .SecurityQualityOfService dq 0

  align 16
  ioStatusBlock:
    .status  dq 0
    .pointer dq 0
