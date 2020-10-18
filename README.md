# Syscall-dump (64-bit)
Dump syscall numbers assigned to NtXxx() routines exported by NTDLL.DLL library.

# What does it do?
- Load NTDLL.DLL library,
- finds its [exports table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only),
- process each exported functions one-by-one and search for below code pattern at their entry-points:

```
functionEntryPoint:
  4c 8b d1                | mov r10, rcx
  b8 xx xx xx xx          | mov eax, <syscall id>
  f6 04 25 yy yy yy yy zz | test byte [yy yy yy yy], zz
  75 03                   | jnz +3
  0f 05                   | syscall
  c3                      | ret
```
- if pattern code matched, then read xx xx xx xx DWORD (4 bytes) value - it's a **SYSCALL ID** used on your OS.

# How does it work?
- Basic system routines are implemented in **KERNEL CODE** (non-user mode, ring 0),
- **USER CODE** (ring 4) calls them using [SYSCALL](https://www.felixcloutier.com/x86/syscall) (64-bit OS) or [INT xx](https://www.felixcloutier.com/x86/intn:into:int3:int1) (older 32-bit OS) opcodes,
- due to above, many low-level functions in user mode are a **DUMB WRAPPERS** to syscall opcode with function ID passed in RAX register.

# How can I use syscall in my code?
- To call system routine via syscall on 64-bit Windows (x86-64, AMD64) you can use below code:
```
mov r10, <first param> ; r10 = 1st param, rcx cannot be used with syscall api
...                    ; 
mov eax, <syscall id>  ; eax = routine id to be execute
syscall                ; call kernel routine
```
- for full example go to [syscall-example.asm](syscall-example.asm) file.

# Can I stop using NtXxx() wrappers in my code and replace them with direct syscalls?
- Generally **NO**, because syscall ids **VARY** from one OS version to another,
- official API given by microsoft is WINAPI delivered via **FUNCTION NAMES** exported by system DLLs,
- syscall numbers are used **INTERNALLY** - it's **NOT** an official API delivered by system vendor.
