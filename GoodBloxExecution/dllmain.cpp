#include "pch.h"
#include "MinHook.h"
#include <Windows.h>
#include <string>
#include <iostream>
#include <locale>
#include <utility>
#include <codecvt>
#include <fstream>
#include <vector>
#include <sstream>
#include <Psapi.h>
#include <WinUser.h>
#include <TlHelp32.h>
#include <WinInet.h>
#include <direct.h>
#include <random>
#include <WinInet.h>
#include <wininet.h>
#include <iostream>
#include <conio.h>
#include <fstream>
#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mtd.lib")
#endif
#define x(x) (x - 0x400000 + (DWORD)GetModuleHandleA(0))
typedef int(__cdecl* RBX_PCALL)(DWORD, int, int, int);
RBX_PCALL r_lua_pcall = (RBX_PCALL)x(0x70AD39);
typedef int(__cdecl* RBX_LOADBUFFER)(DWORD L, const char* buff, size_t size,
    const char* name);
RBX_LOADBUFFER r_lua_loadbuffer = (RBX_LOADBUFFER)x(0x70BD30);
typedef void(__cdecl* RBX_PUSHCCLOSURE)(DWORD, int (*)(DWORD L), int);
RBX_PUSHCCLOSURE r_lua_pushcclosure = (RBX_PUSHCCLOSURE)x(0x70A6D0);
typedef const char* (__cdecl* RBX_TOSTRING)(DWORD, int, size_t); // this is actuall tolstring but im a dumbass and typed tostring
RBX_TOSTRING r_lua_tolstring = (RBX_TOSTRING)x(0x70A3C0);
namespace Color {
    inline std::ostream& yellow(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 6 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& red(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 4 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& white(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 7 | FOREGROUND_BLUE);
        return s;
    }

    inline std::ostream& blue(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 1 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& green(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 2 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& purple(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 5 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& grey(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 8 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& pink(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 4 | 7 | FOREGROUND_INTENSITY);
        return s;
    }

    inline std::ostream& etc(std::ostream& s)
    {
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hStdout, 4 | 5 | FOREGROUND_INTENSITY);
        return s;
    }
}


namespace Hook {
  

    DWORD GettopAddress = x(0x709FC0);
    DWORD RobloxState = 0;
    LPVOID* HookedAddress = (LPVOID*)GettopAddress;
    typedef DWORD(__cdecl* RBX_GETTOP)(DWORD);
    RBX_GETTOP OriginalGettop = (RBX_GETTOP)GettopAddress;

    DWORD GettopHook(DWORD RbxState)
    {
        RobloxState = RbxState;//sets the roblox state bc the first arg of newthread is the state
        return (*(DWORD*)(RbxState + 8) - *(DWORD*)(RbxState + 12)) >> 4;
    }

    void Hook() {
        MH_CreateHook(HookedAddress, GettopHook, NULL);//hooks to newthread with our func
        MH_EnableHook(HookedAddress);//enables the hook
        MH_DisableHook(HookedAddress);//disables it because im epic
        MH_RemoveHook(HookedAddress);//removes the hook
    }

    void InitHook() {
        MH_Initialize();
        while(RobloxState == 0) { Hook(); }
        MH_Uninitialize();

        if (RobloxState == 0) {
            MessageBoxA(NULL, "you big fat fuck, retry", "Retard", NULL);
        }
    }
}
int r_luaL_loadstring(DWORD L, const char* s) {
   return r_lua_loadbuffer(Hook::RobloxState, s, strlen(s), "@aaa");

}
int print(DWORD L) {
    std::cout << r_lua_tolstring(L, 1, NULL) << "\n";
    return 0;
}
int warn(DWORD L) {
    std::cout << Color::yellow << r_lua_tolstring(L, 1, NULL) << "\n";
    return 0;
}

DWORD WINAPI input(PVOID lvpParameter)
{
    HANDLE hPipe;
    char buffer[0x7fff];
    DWORD dwRead;
    //pipe setup
    hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\oogabooga"),
        PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
        PIPE_WAIT,
        1,
        1024 * 16,
        1024 * 16,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);
    while (hPipe != INVALID_HANDLE_VALUE)
    {
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)
        {
            while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
            {
                //adding a endingg to the buffer cuz if i didnt it wouldnt stop reading the string
                buffer[dwRead] = '\0';
            }
            //game detections
            if (r_luaL_loadstring(Hook::RobloxState, ("local args = {...} local print = args[1] local warn = args[2]" + std::string(buffer)).c_str())) {
                std::cout << Color::red << r_lua_tolstring(Hook::RobloxState, -1, NULL) << Color::white "\n";
            }
            else {
                r_lua_pushcclosure(Hook::RobloxState, print, 0);
                r_lua_pushcclosure(Hook::RobloxState, warn, 0);

                if (r_lua_pcall(Hook::RobloxState, 2, 0, 0)) {
                    std::cout << Color::red << r_lua_tolstring(Hook::RobloxState, -1, NULL) << Color::white << "\n";
                }
            }
        }
        DisconnectNamedPipe(hPipe);
    }
}
void EntryPoint() {
    DWORD console;
    VirtualProtect((void*)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &console);
    *(DWORD32*)(&FreeConsole) = 0xC3;
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    Hook::InitHook();
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)input, NULL, NULL, NULL);
}
__forceinline void UnlinkModule(HINSTANCE Module) {
    DWORD PEB_DATA = 0;
    _asm {
        pushad;
        pushfd;
        mov eax, fs: [30h]
            mov eax, [eax + 0Ch]
            mov PEB_DATA, eax
            InLoadOrderModuleList :
        mov esi, [eax + 0Ch]
            mov edx, [eax + 10h]

            LoopInLoadOrderModuleList :
            lodsd
            mov esi, eax
            mov ecx, [eax + 18h]
            cmp ecx, Module
            jne SkipA
            mov ebx, [eax]
            mov ecx, [eax + 4]
            mov[ecx], ebx
            mov[ebx + 4], ecx
            jmp InMemoryOrderModuleList

            SkipA :
        cmp edx, esi
            jne LoopInLoadOrderModuleList

            InMemoryOrderModuleList :
        mov eax, PEB_DATA
            mov esi, [eax + 14h]
            mov edx, [eax + 18h]

            LoopInMemoryOrderModuleList :
            lodsd
            mov esi, eax
            mov ecx, [eax + 10h]
            cmp ecx, Module
            jne SkipB
            mov ebx, [eax]
            mov ecx, [eax + 4]
            mov[ecx], ebx
            mov[ebx + 4], ecx
            jmp InInitializationOrderModuleList

            SkipB :
        cmp edx, esi
            jne LoopInMemoryOrderModuleList

            InInitializationOrderModuleList :
        mov eax, PEB_DATA
            mov esi, [eax + 1Ch]
            mov edx, [eax + 20h]

            LoopInInitializationOrderModuleList :
            lodsd
            mov esi, eax
            mov ecx, [eax + 08h]
            cmp ecx, Module
            jne SkipC
            mov ebx, [eax]
            mov ecx, [eax + 4]
            mov[ecx], ebx
            mov[ebx + 4], ecx
            jmp Finished

            SkipC :
        cmp edx, esi
            jne LoopInInitializationOrderModuleList

            Finished :
        popfd;
        popad;
    }
}
unsigned int ProtectSections(HMODULE Module) {
    MODULEINFO ModuleInfo;
    GetModuleInformation(GetCurrentProcess(), Module, &ModuleInfo, sizeof(ModuleInfo));
    uintptr_t Address = (uintptr_t)(Module);
    uintptr_t TermAddress = Address + ModuleInfo.SizeOfImage;
    MEMORY_BASIC_INFORMATION MemoryInfo;


    while (Address < TermAddress) {
        VirtualQuery((void*)(Address), &MemoryInfo, sizeof(MemoryInfo));
        if (MemoryInfo.State == MEM_COMMIT && (MemoryInfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            unsigned long OldProtection;
            VirtualProtect((void*)(Address), MemoryInfo.RegionSize, PAGE_EXECUTE_READ, &OldProtection);
        }
        Address = (uintptr_t)(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize;
    }

    VirtualQuery((void*)(MemoryInfo.AllocationBase), &MemoryInfo, sizeof(MemoryInfo));
    if (MemoryInfo.State != MEM_COMMIT || !(MemoryInfo.Protect & PAGE_EXECUTE_READ))
        return 0x400;
    return MemoryInfo.RegionSize - 0x400;
}
BOOL APIENTRY DllMain(HMODULE Module, DWORD ul_reason_for_call, void* Reserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(Module);
        UnlinkModule(Module);
        unsigned long OldProtection;
        VirtualProtect(Module, 4096, PAGE_READWRITE, &OldProtection);
        ZeroMemory(Module, 4096);
        ProtectSections(Module);
        HANDLE hThread = NULL;
        HANDLE hDllMainThread = GetCurrentThread();
        if (Reserved == NULL) {

            if (!(hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)EntryPoint, NULL, NULL, NULL))) {
                CloseHandle(hDllMainThread);
                return FALSE;
            }
            CloseHandle(hThread);
        }
        
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

