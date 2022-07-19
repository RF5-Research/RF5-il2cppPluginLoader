// main.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <Windows.h>

FARPROC GetModuleSymbolAddress(const char* module, const char* symbol)
{
    HMODULE moduleHandle = GetModuleHandleA(module);
    if (moduleHandle == NULL) {
        printf("Failed to load module `%s`\n", module);
        return NULL;
    }
    FARPROC funcPTR = GetProcAddress(moduleHandle, symbol);
    if (funcPTR == NULL)
    {
        printf("Failed to load symbol `%s` in module `%s`\n", symbol, module);
        return NULL;
    }

    return funcPTR;
}

BOOL InjectDll(HANDLE hProcess, LPCSTR lpFileName)
{
    LPVOID pAddress;
    HANDLE hThread;
    DWORD exitCode;
    auto tSize = strlen(lpFileName) + 1;
    pAddress = VirtualAllocEx(hProcess, NULL, tSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!pAddress)
    {
        printf("Failed to allocate memory in the target process\n");
        return false;
    }

    if (!WriteProcessMemory(hProcess, pAddress, lpFileName, tSize, NULL))
    {
        printf("Failed to write memory to the target proces\n");
        return false;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)&LoadLibraryA, pAddress, 0, NULL);

    if (!hThread)
    {
        printf("CreateRemoteThread failed\n");
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &exitCode);
    VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);

    if (!exitCode)
    {
        printf("Exited with error code: %d\n", GetLastError());
        return false;
    }

    return true;
}

int main()
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFOA StartupInfo;
    DWORD cb;

    cb = sizeof(STARTUPINFOA);
    ZeroMemory(&StartupInfo, cb);
    StartupInfo.cb = cb;

    const char* process = "Rune Factory 5.exe";
    if (!CreateProcessA(process, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation)) {
        printf("Failed to open `%s`", process);
        return 0;
    }
    const char* modules[] = {
        "kernel32.dll",
        "iL2cppPluginLoaderDll.dll"
    };

    for (int i = 0; i < sizeof(modules) / sizeof(const char*); i++)
    {
        if (!InjectDll(ProcessInformation.hProcess, modules[i]))
        {
            TerminateProcess(ProcessInformation.hProcess, GetLastError());
            printf("Couldn't inject `%s`\n", modules[i]);
            return 0;
        }
    }

    ResumeThread(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
}