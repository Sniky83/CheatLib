#include <iostream>
#include <windows.h>

// DLL function pointers
using GetProcessHandleByNameFn = HANDLE(__cdecl *)(const WCHAR* processName);
using ReadStringMemoryFn = CHAR*(__cdecl *)(HANDLE hProcess, LPVOID addr, SIZE_T sizeOfString);
using ExecuteShellcodeFn = BOOL(__cdecl *)(HANDLE hProcess, BYTE* shellcode, SIZE_T sizeOfShellcode);
using AllocateAndWriteMemoryFn = LPVOID(__cdecl *)(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize);
using GetRelativeAddrFn = LPVOID(__cdecl *)(LPVOID shellcodeAddr, LPVOID callAddress, SIZE_T offset);
using GetAddrWithInstructionFn = BYTE*(__cdecl *)(LPVOID addr, BYTE instruction);
using AllocateMemoryFn = LPVOID(__cdecl *)(HANDLE hProcess, SIZE_T size);
using WriteShellcodeMemoryFn = BOOL(__cdecl *)(HANDLE hProcess, LPVOID lpAddress, const BYTE* shellcode, SIZE_T size);
using StartRemoteThreadFn = BOOL(__cdecl *)(HANDLE hProcess, LPVOID shellcodeAddr);
using WriteCloseShellcodeMemoryFn = BOOL(__cdecl *)(HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T offset);

// Global function pointers
GetProcessHandleByNameFn GetProcessHandleByName = nullptr;
ReadStringMemoryFn ReadStringMemory = nullptr;
ExecuteShellcodeFn ExecuteShellcode = nullptr;
AllocateAndWriteMemoryFn AllocateAndWriteMemory = nullptr;
GetRelativeAddrFn GetRelativeAddr = nullptr;
GetAddrWithInstructionFn GetAddrWithInstruction = nullptr;
AllocateMemoryFn AllocateMemory = nullptr;
WriteShellcodeMemoryFn WriteShellcodeMemory = nullptr;
StartRemoteThreadFn StartRemoteThread = nullptr;
WriteCloseShellcodeMemoryFn WriteCloseShellcodeMemory = nullptr;

// Functions prototypes
void CallPrintConsoleGameFunc(HANDLE hProcess);
int InitAllFuncPointers(HMODULE hModule);

int main() {
    // Call the CheatLib
    HMODULE hModule = LoadLibraryA("../Release/CheatLib.dll");
    if (hModule == NULL) {
        std::cerr << "Failed to load CheatLib.dll" << std::endl;
        return 1;
    }

    // Initialize all function pointers
    int initSucces = InitAllFuncPointers(hModule);

    if(initSucces = 0) {
        FreeLibrary(hModule);
        return 1;
    }

    // Starting of the code
    HANDLE hProcess = GetProcessHandleByName(L"ac_client.exe");
    if (hProcess == NULL) {
        std::cerr << "Failed to find handle process" << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    // Call the game function to print a message on the screen
    CallPrintConsoleGameFunc(hProcess);

    CloseHandle(hProcess);
    FreeLibrary(hModule);
    return 0;
}

int InitAllFuncPointers(HMODULE hModule)
{
    // Check all DLL funcs if error
    GetProcessHandleByName = (GetProcessHandleByNameFn)GetProcAddress(hModule, "GetProcessHandleByName");
    if (GetProcessHandleByName == NULL) {
        std::cerr << "Failed to get address of GetProcessHandleByName. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    ReadStringMemory = (ReadStringMemoryFn)GetProcAddress(hModule, "ReadStringMemory");
    if (ReadStringMemory == NULL) {
        std::cerr << "Failed to get address of ReadStringMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    ExecuteShellcode = (ExecuteShellcodeFn)GetProcAddress(hModule, "ExecuteShellcode");
    if (ExecuteShellcode == NULL) {
        std::cerr << "Failed to get address of ExecuteShellcode. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    AllocateAndWriteMemory = (AllocateAndWriteMemoryFn)GetProcAddress(hModule, "AllocateAndWriteMemory");
    if (AllocateAndWriteMemory == NULL) {
        std::cerr << "Failed to get address of AllocateAndWriteMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    GetRelativeAddr = (GetRelativeAddrFn)GetProcAddress(hModule, "GetRelativeAddr");
    if (GetRelativeAddr == NULL) {
        std::cerr << "Failed to get address of GetRelativeAddr. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    GetAddrWithInstruction = (GetAddrWithInstructionFn)GetProcAddress(hModule, "GetAddrWithInstruction");
    if (GetAddrWithInstruction == NULL) {
        std::cerr << "Failed to get address of GetAddrWithInstruction. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    AllocateMemory = (AllocateMemoryFn)GetProcAddress(hModule, "AllocateMemory");
    if (AllocateMemory == NULL) {
        std::cerr << "Failed to get address of AllocateMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    WriteShellcodeMemory = (WriteShellcodeMemoryFn)GetProcAddress(hModule, "WriteShellcodeMemory");
    if (WriteShellcodeMemory == NULL) {
        std::cerr << "Failed to get address of WriteShellcodeMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    StartRemoteThread = (StartRemoteThreadFn)GetProcAddress(hModule, "StartRemoteThread");
    if (StartRemoteThread == NULL) {
        std::cerr << "Failed to get address of StartRemoteThread. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    WriteCloseShellcodeMemory = (WriteCloseShellcodeMemoryFn)GetProcAddress(hModule, "WriteCloseShellcodeMemory");
    if (WriteCloseShellcodeMemory == NULL) {
        std::cerr << "Failed to get address of WriteCloseShellcodeMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    return 1;
}

void CallPrintConsoleGameFunc(HANDLE hProcess)
{
    // Write the first param of the func into new memory loc
    const CHAR* message = "PRINT CONSOLE FUNC CALLED WITH EXTERNAL DLL !";
    LPVOID stringLocAddr = AllocateAndWriteMemory(hProcess, (BYTE*)message, strlen(message));
    // Get the address with push instruction in front
    // So it corresponds to the first param of the func which is the message to print on the screen
    BYTE* addrPushInstruction = GetAddrWithInstruction(stringLocAddr, 0x68);

    std::cout << "The message to push as param is located at : " << stringLocAddr << std::endl;

    // Print the message stored into the memory at the location we created dynamically
    // Just to proof the existence of it in memory
    CHAR* messageInMem = ReadStringMemory(hProcess, stringLocAddr, strlen(message));
    std::cout << "Message pushed : " << messageInMem << std::endl;

    // Addr of my printConsoleFunc in my game memory
    LPVOID printConsoleFunc = (LPVOID)0x004DAD50;
    // Allocate new memory to write the full shellcode
    LPVOID addrAllocShellcode = AllocateMemory(hProcess, 10);
    // Get the relative address for the printConsoleFunc
    LPVOID relativeAddr = GetRelativeAddr(addrAllocShellcode, printConsoleFunc, sizeof(addrPushInstruction) + 1);
    // Get the address with call instruction in front
    BYTE* addrCallInstruction = GetAddrWithInstruction(relativeAddr, 0xE8);

    std::cout << "The whole shellcode is located at : " << addrAllocShellcode << std::endl;
    std::cout << "Relative addr for the call instruction : " << relativeAddr << std::endl;

    // Write the push shellcode in my new allocated memory address
    // ASM
    // push message
    WriteShellcodeMemory(hProcess, addrAllocShellcode, addrPushInstruction, 5);

    // Write the call shellcode in my new allocated memory address + 5 to write after the first instruction (push message) (2nd param of the func)
    // push message -> 5 bytes
    // call printConsoleFunc -> 5 bytes
    // The last parameter corresponds to the size of the shellcode : call printConsoleFunc -> 5 bytes
    WriteShellcodeMemory(hProcess, (LPVOID)((char*)addrAllocShellcode + 0x5), addrCallInstruction, 5);

    // Close the shellcode properly in ASM to exit the remote thread after the shellcode inserted
    // Only use it if you're using a remote thread (StartRemoteThread) otherwise don't call this func
    WriteCloseShellcodeMemory(hProcess, addrAllocShellcode, 10);

    // Execute the shellcode written in the new memory region to load the printConsoleFunc
    BOOL isRemoteThreadStarted = StartRemoteThread(hProcess, addrAllocShellcode);

    if(isRemoteThreadStarted) {
        std::cout << "PrintConsoleFunc has been called !" << std::endl;
    }
    else {
        std::cerr << "Fail to start the remote threadto call the PrintConsoleFunc. Error: " << GetLastError() << std::endl;
    }
}