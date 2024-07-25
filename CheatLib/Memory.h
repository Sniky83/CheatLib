#ifdef MEMORY_EXPORTS
#define MEMORY_API __declspec(dllexport)
#else
#define MEMORY_API __declspec(dllimport)
#endif

#include <windows.h>

#ifdef __cplusplus
    extern "C" {
#endif
MEMORY_API BOOL WriteCloseShellcodeMemory(HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T offset);
MEMORY_API BOOL StartRemoteThread(HANDLE hProcess, LPVOID shellcodeAddr);
MEMORY_API HANDLE GetProcessHandleByName(const WCHAR* processName);
MEMORY_API BOOL ExecuteShellcode(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize);
MEMORY_API LPVOID AllocateAndWriteMemory(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize);
MEMORY_API LPVOID AllocateMemory(HANDLE hProcess, SIZE_T size);
MEMORY_API INT ReadIntMemory(HANDLE hProcess, LPVOID address);
MEMORY_API FLOAT ReadFloatMemory(HANDLE hProcess, LPVOID address);
MEMORY_API CHAR* ReadStringMemory(HANDLE hProcess, LPVOID address, SIZE_T length);
MEMORY_API LPVOID ReadAddrMemory(HANDLE hProcess, LPVOID address);
MEMORY_API BOOL WriteIntMemory(HANDLE hProcess, LPVOID address, INT value);
MEMORY_API BOOL WriteFloatMemory(HANDLE hProcess, LPVOID address, FLOAT value);
MEMORY_API BOOL WriteShellcodeMemory(HANDLE hProcess, LPVOID lpAddress, const BYTE* shellcode, SIZE_T size);
MEMORY_API LPVOID GetAddrLittleEndian(LPVOID addr);
MEMORY_API LPVOID GetRelativeAddr(LPVOID targetAddr, LPVOID callAddr, SIZE_T offset);
MEMORY_API BYTE* GetAddrWithInstruction(LPVOID addr, BYTE instruction);

#ifdef __cplusplus
    }
#endif

// Template avec décoration donc les noms peuvent varier chez le client
template <typename T>
MEMORY_API T ReadMemory(HANDLE hProcess, LPVOID address);
template <typename T>
MEMORY_API BOOL WriteMemory(HANDLE hProcess, LPVOID address, const T& value);