# Direct-and-Indirect-Syscalls

- This repo contains implementations of Direct and Indirect Syscalls and Reimplementations of various process injection techniques using Indirect Syscalls
- Also Included an NTAPI implementation of vanilla process injection as the syscall examples build upon that.

## [NTAPI Injection](https://github.com/trevorsaudi/Direct-and-Indirect-Syscalls/tree/main/NTAPIInjection)

- NTAPI Injection involves injecting code that uses Native API (NTAPI) functions directly. NTAPI functions are lower-level than the standard Windows API functions

## [DirectSyscalls](https://github.com/trevorsaudi/Direct-and-Indirect-Syscalls/tree/main/DirectSyscalls)

- Direct syscalls involve making system calls directly from user mode to kernel mode without using the standard Windows API functions.

## [InDirectSyscalls](https://github.com/trevorsaudi/Direct-and-Indirect-Syscalls/tree/main/IndirectSyscalls)

- Performing InDirect Syscalls by jumping to the address where the syscall is located in ntdll, instead of executing the syscall instruction ourselves

## [Remote Mapping Injection - Indirect Syscalls](https://github.com/trevorsaudi/Direct-and-Indirect-Syscalls/tree/main/LocalMapping-Indirect)

- Here, we leverage NtCreateSection and NtMapViewSection to create memory sections and map our shellcode into it, avoids use of commmon APIS
  
