# Direct-and-Indirect-Syscalls

- This repo contains implementations of Direct and Indirect Syscalls and Reimplementations of various process injection techniques using Indirect Syscalls
- Also Included an NTAPI implementation of vanilla process injection as the syscall examples build upon that.


# Process-Injection on Windows with C/C++

- This repository contains C/C++  programs that demonstrate examples of process injection techniques on a Windows system.

## Overview

- The program uses the Windows API to inject a payload into a running process. The payload and the target process are hardcoded into the program for demonstration purposes.

- The payload is generated using `msfvenom`, intended to display a message box with the text "Hello hackers".

- The target process is `notepad.exe`, but this can be modified to any process that the user has permissions to manipulate.

## [DirectSyscalls][(https://github.com/trevorsaudi/Process-Injection-cpp/tree/main/ClassicProcessInjection](https://github.com/trevorsaudi/Direct-and-Indirect-Syscalls/tree/main/DirectSyscalls)]

- Standard classic process injection featuring common API calls like `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.

## [QueueUserAPC](https://github.com/trevorsaudi/Process-Injection-cpp/tree/main/QueueUserAPC)

- . In this method, we abuse the QueueUserAPC WINAPI to queue our shellcode into running processes. This injection eliminates the need for using CreateRemoteThread to create a thread to run the shellcode.


## [TinyAES-APCInjection](https://github.com/trevorsaudi/Process-Injection-cpp/tree/main/TinyAES-APCInjection)

- In this example we encrypt the payload using TinyAES, a small portable AES256 encryption wrapper to implement aes encryption.

