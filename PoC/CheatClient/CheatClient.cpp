#include <iostream>
#include <Windows.h>
#include <conio.h>

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
using WriteCloseRemoteThreadMemoryFn = BOOL(__cdecl *)(HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T offset);

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
WriteCloseRemoteThreadMemoryFn WriteCloseRemoteThreadMemory = nullptr;

// Functions prototypes
void CallPrintConsoleGameFunc(HANDLE hProcess);
LPVOID ToggleGodMode(HANDLE hProcess, BOOL isGodModEnabled);
INT InitAllFuncPointers(HMODULE hModule);

int main() {
    // Call the CheatLib
    HMODULE hModule = LoadLibraryA("../../Release/CheatLib.dll");
    if (hModule == NULL) {
        std::cerr << "Failed to load CheatLib.dll" << std::endl;
        return 1;
    }

    // Initialize all function pointers
    INT initSucces = InitAllFuncPointers(hModule);

    if(initSucces == 0) {
        FreeLibrary(hModule);
        return 1;
    }

    // Loading the process you want to attach
    // iw3sp.exe -> Call Of Duty Modern Warfare
    // ac_client.exe -> Assault Cube
    HANDLE hProcess = GetProcessHandleByName(L"ac_client.exe");
    if (hProcess == NULL) {
        std::cerr << "Failed to find handle process" << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    std::cout << "Welcome the PoC CheatClient" << std::endl << std::endl;

    // Call the game function to print a message on the screen
    // For Assault Cube
    CallPrintConsoleGameFunc(hProcess);

    // For Call Of Duty Modern Warfare
    //std::cout << std::endl << "Press [F1] to toggle GOD MODE";
    //std::cout << std::endl << "Press [F12] to exit the program" << std::endl;
    //BOOL isGodModEnabled = true;
    //LPVOID allocatedAddr = NULL;
    //while (true)
    //{
    //    if (GetAsyncKeyState(VK_F1) & 1)
    //    {
    //        if (allocatedAddr != NULL)
    //        {
    //            VirtualFreeEx(hProcess, allocatedAddr, 0, MEM_RELEASE);
    //        }

    //        if (isGodModEnabled) {
    //            std::cout << std::endl << "God mode ENABLED" << std::endl;
    //        }
    //        else
    //        {
    //            std::cout << std::endl << "God mode DISABLED" << std::endl;
    //        }

    //        allocatedAddr = ToggleGodMode(hProcess, isGodModEnabled);
    //        isGodModEnabled =! isGodModEnabled;
    //    }

    //    if (GetAsyncKeyState(VK_F12) & 1)
    //    {
    //        std::cout << std::endl << "You just exited the cheat" << std::endl;
    //        break;
    //    }

    //    Sleep(10);
    //}

    #ifdef NDEBUG
        std::cout << std::endl << "Press any key to close the program..." << std::endl;
        char res = _getch();
    #endif

    CloseHandle(hProcess);
    FreeLibrary(hModule);

    return 0;
}

/// <summary>
/// Initialize all function pointers from the DLL
/// </summary>
/// <param name="hModule"></param>
/// <returns></returns>
INT InitAllFuncPointers(HMODULE hModule)
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

    WriteCloseRemoteThreadMemory = (WriteCloseRemoteThreadMemoryFn)GetProcAddress(hModule, "WriteCloseRemoteThreadMemory");
    if (WriteCloseRemoteThreadMemory == NULL) {
        std::cerr << "Failed to get address of WriteCloseRemoteThreadMemory. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 0;
    }

    return 1;
}

/// <summary>
/// Function to call the print text in the game console in assault cube
/// </summary>
/// <param name="hProcess"></param>
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

    // Address of my PrintConsoleFunc in my game memory
    LPVOID printConsoleFunc = (LPVOID)0x004DAD50;
    // Allocate new memory to write the full shellcode
    LPVOID addrAllocShellcode = AllocateMemory(hProcess, 10);
    // Get the relative address for the printConsoleFunc
    LPVOID relativeAddr = GetRelativeAddr(addrAllocShellcode, printConsoleFunc, 5);
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
    WriteCloseRemoteThreadMemory(hProcess, addrAllocShellcode, 10);

    // Execute the shellcode written in the new memory region to load the PrintConsoleFunc
    BOOL isRemoteThreadStarted = StartRemoteThread(hProcess, addrAllocShellcode);

    if(isRemoteThreadStarted) {
        std::cout << "PrintConsoleFunc has been called !" << std::endl;
    }
    else {
        std::cerr << "Fail to start the remote thread to call the PrintConsoleFunc. Error: " << GetLastError() << std::endl;
    }

    // Free the memory region allocated after the call
    VirtualFreeEx(hProcess, addrAllocShellcode, 0, MEM_RELEASE);
}

/// <summary>
/// Function to toggle god mode for Call Of Duty Modern Warfare
/// </summary>
/// <param name="hProcess"></param>
/// <param name="isGodModEnabled"></param>
/// <returns></returns>
LPVOID ToggleGodMode(HANDLE hProcess, BOOL isGodModEnabled)
{
    LPVOID adrrTakeDmg = (LPVOID)0x4AE5FE;
    if (isGodModEnabled) {
        LPVOID hookShellcodeAllocMemAddr = AllocateMemory(hProcess, 100);
        std::cout << "Address new memory allocated : " << hookShellcodeAllocMemAddr << std::endl;
        LPVOID relativeAddrNewAlloc = GetRelativeAddr(adrrTakeDmg, hookShellcodeAllocMemAddr, 0);
        std::cout << "Relative address of memmory allocated : " << relativeAddrNewAlloc << std::endl;
        BYTE* jmpIntoHookAllocInstruction = GetAddrWithInstruction(relativeAddrNewAlloc, 0xE9);
        WriteShellcodeMemory(hProcess, adrrTakeDmg, jmpIntoHookAllocInstruction, 5);
        BYTE endProperlyEditJne[] = { 0x90, 0xEB, 0x16 };
        WriteShellcodeMemory(hProcess, (LPVOID)((char*)adrrTakeDmg + 0x5), endProperlyEditJne, sizeof(endProperlyEditJne));
        BYTE customShellcode[] = { 0x83, 0xBD, 0x28, 0x01, 0x00, 0x00, 0x00, 0x74, 0x0A, 0x90, 0x90, 0x90, 0x90, 0x89, 0x95, 0x44, 0x01, 0x00, 0x00 };
        WriteShellcodeMemory(hProcess, hookShellcodeAllocMemAddr, customShellcode, sizeof(customShellcode));
        LPVOID relativeAddrJmp = GetRelativeAddr((LPVOID)((char*)hookShellcodeAllocMemAddr + sizeof(customShellcode)), (LPVOID)((char*)adrrTakeDmg + 0x5), 0);
        std::cout << "Relative address of memory call function TakeDamages : " << relativeAddrJmp << std::endl;
        BYTE* jmpBackIntoFuncInstruction = GetAddrWithInstruction(relativeAddrJmp, 0xE9);
        WriteShellcodeMemory(hProcess, (LPVOID)((char*)hookShellcodeAllocMemAddr + sizeof(customShellcode)), jmpBackIntoFuncInstruction, 5);

        return hookShellcodeAllocMemAddr;
    }
    else 
    {
        BYTE originalShellcode[] = { 0x89, 0x95, 0x44, 0x01, 0x00, 0x00 };
        WriteShellcodeMemory(hProcess, adrrTakeDmg, originalShellcode, sizeof(originalShellcode));

        return NULL;
    }
}