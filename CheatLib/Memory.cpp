#include "pch.h"
#include "memory.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>

extern "C" {
    __declspec(dllexport) BOOL WriteCloseShellcodeMemory(HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T offset);
    __declspec(dllexport) HANDLE GetProcessHandleByName(const WCHAR* processName);
    __declspec(dllexport) CHAR* ReadStringMemory(HANDLE hProcess, LPVOID address, SIZE_T length);
    __declspec(dllexport) BOOL WriteShellcodeMemory(HANDLE hProcess, LPVOID lpAddress, const BYTE* shellcode, SIZE_T size);
    __declspec(dllexport) LPVOID AllocateAndWriteMemory(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize);
    __declspec(dllexport) LPVOID AllocateMemory(HANDLE hProcess, SIZE_T size);
    __declspec(dllexport) BOOL ExecuteShellcode(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize);
    __declspec(dllexport) LPVOID GetAddrLittleEndian(LPVOID addr);
    __declspec(dllexport) LPVOID GetRelativeAddr(LPVOID targetAddr, LPVOID callAddr, SIZE_T offset);
    __declspec(dllexport) BYTE* GetAddrWithInstruction(LPVOID addr, BYTE instruction);
    __declspec(dllexport) BOOL StartRemoteThread(HANDLE hProcess, LPVOID shellcodeAddr);

    __declspec(dllexport) INT ReadIntMemory(HANDLE hProcess, LPVOID address)
    {
        return ReadMemory<INT>(hProcess, address);
    }

    __declspec(dllexport) FLOAT ReadFloatMemory(HANDLE hProcess, LPVOID address)
    {
        return ReadMemory<FLOAT>(hProcess, address);
    }

    __declspec(dllexport) LPVOID ReadAddrMemory(HANDLE hProcess, LPVOID address)
    {
        return ReadMemory<LPVOID>(hProcess, address);
    }

    __declspec(dllexport) BOOL WriteIntMemory(HANDLE hProcess, LPVOID address, INT value)
    {
        return WriteMemory<INT>(hProcess, address, value);
    }

    __declspec(dllexport) BOOL WriteFloatMemory(HANDLE hProcess, LPVOID address, FLOAT value)
    {
        return WriteMemory<FLOAT>(hProcess, address, value);
    }
}

__declspec(dllexport) HANDLE GetProcessHandleByName(const WCHAR* processName)
{
    HANDLE hProcess = NULL;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Take a snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << std::endl;
        return NULL;
    }

    // Retrieve information about the first process
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(processName, pe32.szExeFile) == 0) {
                // Open a handle to the process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess == NULL) {
                    std::cerr << "OpenProcess failed with error: " << GetLastError() << std::endl;
                }
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        std::cerr << "Process32FirstW failed with error: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);
    return hProcess;
}

template <typename T>
__declspec(dllexport) T ReadMemory(HANDLE hProcess, LPVOID address)
{
    T value = 0;
    BOOL result = ReadProcessMemory(hProcess, address, &value, sizeof(T), NULL);

    if (!result)
    {
        // Set value to zero if the operation failed
        value = 0;
    }
    return value;
}

__declspec(dllexport) CHAR* ReadStringMemory(HANDLE hProcess, LPVOID address, SIZE_T length)
{
    // Read the specified range of bytes from memory
    std::vector<char> buffer(length + 1);
    if (!ReadProcessMemory(hProcess, address, buffer.data(), length, NULL))
    {
        return nullptr;
    }

    // Add a null terminator to the end of the string
    buffer[length] = '\0';

    // Convert the vector to a null-terminated char* string
    char* string = new char[length + 1];
    strncpy_s(string, (length + 1), buffer.data(), length);

    return string;
}


template <typename T>
__declspec(dllexport) BOOL WriteMemory(HANDLE hProcess, LPVOID address, const T& value)
{
    BOOL result = WriteProcessMemory(hProcess, address, &value, sizeof(T), NULL);

    return result;
}

__declspec(dllexport) BOOL WriteShellcodeMemory(HANDLE hProcess, LPVOID lpAddress, const BYTE* shellcode, SIZE_T size)
{
    return WriteProcessMemory(hProcess, lpAddress, shellcode, size, NULL);
}

__declspec(dllexport) BOOL ExecuteShellcode(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize)
{
    // Allocate memory in the target process for the shellcode
    LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcodeAddr == NULL)
    {
        return FALSE;
    }

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, shellcodeSize, NULL))
    {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // Create a new thread in the target process that starts execution at the beginning of the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
    if (hThread == NULL)
    {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for the thread to finish executing
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory
    VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);

    // Close the handles
    CloseHandle(hThread);

    return TRUE;
}

__declspec(dllexport) BOOL StartRemoteThread(HANDLE hProcess, LPVOID shellcodeAddr)
{
    // Create a new thread in the target process that starts execution at the beginning of the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
    if (hThread == NULL)
    {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for the thread to finish executing
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory
    VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);

    // Close the handles
    CloseHandle(hThread);

    return TRUE;
}

__declspec(dllexport) LPVOID AllocateAndWriteMemory(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize)
{
    // Allocate memory in the target process for the shellcode
    LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcodeAddr == NULL)
    {
        return NULL;
    }

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, shellcodeSize, NULL))
    {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return NULL;
    }

    // Return the address of the allocated memory
    return shellcodeAddr;
}

__declspec(dllexport) LPVOID AllocateMemory(HANDLE hProcess, SIZE_T size)
{
    LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpAddress == NULL)
    {
        return NULL;
    }
    
    return lpAddress;
}

__declspec(dllexport) BOOL WriteCloseShellcodeMemory(HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T offset)
{
    SIZE_T bytesWritten = 0;

    #ifdef _WIN64
        // 64-bit version
        BYTE callExitThread[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3 };
        DWORD64 callExitThreadAddr = (DWORD64)&ExitThread;
        memcpy(&callExitThread[2], &callExitThreadAddr, 8);
    #else
        // 32-bit version
        BYTE callExitThread[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90 };
        DWORD callExitThreadAddr = (DWORD)&ExitThread;
        DWORD relativeAddr = callExitThreadAddr - ((DWORD)shellcodeAddr + offset + 5);
        memcpy(&callExitThread[1], &relativeAddr, 4);
    #endif

    BOOL result = WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)shellcodeAddr + offset), callExitThread, sizeof(callExitThread), &bytesWritten);
    if (result == FALSE || bytesWritten != sizeof(callExitThread))
    {
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) LPVOID GetAddrLittleEndian(LPVOID addr)
{
    unsigned char* char_array = (unsigned char*)&addr;
    std::reverse(char_array, char_array + sizeof(addr));

    return *(LPVOID*)char_array;
}


__declspec(dllexport) LPVOID GetRelativeAddr(LPVOID targetAddr, LPVOID callAddr, SIZE_T offset)
{
    SIZE_T sizeOfInstructionAddr = 5;
    SIZE_T diffOffsetSizeOfInstr = (sizeOfInstructionAddr + offset);
    LPVOID diff = (LPVOID)((DWORD_PTR)callAddr - (DWORD_PTR)targetAddr - diffOffsetSizeOfInstr);

    return diff;
}

__declspec(dllexport) BYTE* GetAddrWithInstruction(LPVOID addr, BYTE instruction)
{
    // Correction de la taille de l'adresse pour la copie
    BYTE* addrWithFirstByteArray = new BYTE[sizeof(addr) + 1];

    // Premier octet est l'instruction
    addrWithFirstByteArray[0] = instruction;

    // Copie de l'adresse après l'instruction
    std::memcpy(addrWithFirstByteArray + 1, &addr, sizeof(addr));

    return addrWithFirstByteArray;
}
