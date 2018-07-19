// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <windows.h>
#include <corecrt_malloc.h>
#include <stdio.h>
#include "detours.h"
#pragma comment(lib, "detours.lib")

#include <Dbghelp.h>
#pragma comment(lib, "dbghelp.lib") 

#include <string>
#include <iosfwd>
#include <sstream>
#include <vector>
using namespace std;

HANDLE process;

typedef void * (__cdecl * PFN_MALLOC)(size_t _Size);
typedef void(__cdecl * PFN_FREE)(void* _Block);
PFN_MALLOC g_pOldMalloc100;
PFN_MALLOC g_pOldMalloc120;
PFN_MALLOC g_pOldMalloc140 = nullptr;
PFN_FREE g_pOldFree140;

static const int MAX_STACK_FRAMES = 10;
string TraceStack();

void printStack(void)
{
    unsigned int   i;
    void         * stack[100];
    unsigned short frames;
    SYMBOL_INFO  * symbol;
    HANDLE         process;

    frames = CaptureStackBackTrace(0, 100, stack, NULL);
    symbol = (SYMBOL_INFO *)g_pOldMalloc140(sizeof(SYMBOL_INFO) + 256 * sizeof(char));
    symbol->MaxNameLen = 255;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

    for (i = 0; i < frames; i++)
    {
        SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);

        printf("%i: %s - 0x%0X\n", frames - i - 1, symbol->Name, symbol->Address);
    }

    g_pOldFree140(symbol);
}

struct MemoryLeaker
{
    PVOID pAddress;
    size_t nSize;
    bool bLeaked;
    void *pStack[MAX_STACK_FRAMES];
    WORD frames;
    MemoryLeaker() :pAddress(nullptr), nSize(0), bLeaked(true), frames(0) {}
    MemoryLeaker(PVOID pAddress, size_t nSize) :pAddress(pAddress), nSize(nSize), bLeaked(true), frames(0) {}
};

MemoryLeaker g_array[100];
int g_nIndex = 0;
void* __cdecl MyMalloc100(
    _In_ _CRT_GUARDOVERFLOW size_t _Size
)
{
    //OutputDebugStringA("100100100100100100100100100100100100100100100....................................");
    return g_pOldMalloc100(_Size);
}

void* __cdecl MyMalloc120(
    _In_ _CRT_GUARDOVERFLOW size_t _Size
)
{
    //OutputDebugStringA("120120120120120120120120120120120120120120120120120....................................");
    return g_pOldMalloc120(_Size);
}

void* __cdecl MyMalloc140(
    _In_ _CRT_GUARDOVERFLOW size_t _Size
)
{
    void *pVoid = g_pOldMalloc140(_Size);
    char s[MAX_PATH] = { 0 };
    sprintf(s, "Malloc: %0x, Size: %d Bytes 140140140140140140140140140140140140140140140140140140....................................\r\n", pVoid, _Size);
    //OutputDebugStringA(s);
    //要打印调用堆栈，就不能用自动分配内存的stl对象，或自己new（malloc）空间，否则会陷入死循环
    //可以考虑在栈空间中申请内存，然后写入文件中
    MemoryLeaker *pLeaker = &g_array[g_nIndex];
    g_nIndex++;
    pLeaker->pAddress = pVoid;
    pLeaker->nSize = _Size;
    pLeaker->frames = CaptureStackBackTrace(0, MAX_STACK_FRAMES, pLeaker->pStack, NULL);
    return pVoid;
}

void __cdecl MyFree140(
    _Pre_maybenull_ _Post_invalid_ void* _Block
)
{
    for (size_t i = 0; i < size(g_array); i++)
    {
        if (g_array[i].pAddress == _Block)
        {
            g_array[i].bLeaked = false;
        }
    }
    char s[MAX_PATH] = { 0 };
    sprintf(s, "Free: %0x 140140140140140140140140140140140140140140140140140140....................................\r\n", _Block);
    //OutputDebugStringA(s);
    g_pOldFree140(_Block);
}

extern "C" _declspec(dllexport) BOOL APIENTRY SetHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //////////////////////////////////////////////////////////////////////////
    //后续还要增加对realloc，realloc，calloc，_recalloc和free的监控，来处理内存泄露，详见截图：hook.png
    //////////////////////////////////////////////////////////////////////////
    //VS2010
    g_pOldMalloc100 = (PFN_MALLOC)DetourFindFunction("msvcr100.dll", "malloc");
    DetourAttach(&(PVOID&)g_pOldMalloc100, MyMalloc100);

    //VS2013
    g_pOldMalloc120 = (PFN_MALLOC)DetourFindFunction("msvcr120.dll", "malloc");
    DetourAttach(&(PVOID&)g_pOldMalloc120, MyMalloc120);

    //VS2017
    g_pOldMalloc140 = (PFN_MALLOC)DetourFindFunction("api-ms-win-crt-heap-l1-1-0.dll", "malloc");
    DetourAttach(&(PVOID&)g_pOldMalloc140, MyMalloc140);

    g_pOldFree140 = (PFN_FREE)DetourFindFunction("api-ms-win-crt-heap-l1-1-0.dll", "free");
    DetourAttach(&(PVOID&)g_pOldFree140, MyFree140);

    LONG ret = DetourTransactionCommit();

    return ret == NO_ERROR;
}


extern "C" _declspec(dllexport) BOOL APIENTRY DropHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)g_pOldMalloc100, MyMalloc100);
    DetourDetach(&(PVOID&)g_pOldMalloc120, MyMalloc120);
    DetourDetach(&(PVOID&)g_pOldMalloc140, MyMalloc140);
    LONG ret = DetourTransactionCommit();
    return ret == NO_ERROR;
}

static HMODULE s_hDll;

HMODULE WINAPI Detoured()
{
    return s_hDll;
}


//https://blog.csdn.net/windpenguin/article/details/80382344
string TraceStack()
{
    static const int MAX_STACK_FRAMES = 5;

    void *pStack[MAX_STACK_FRAMES];

    HANDLE process = GetCurrentProcess();
    SymInitialize(process, NULL, TRUE);
    WORD frames = CaptureStackBackTrace(0, MAX_STACK_FRAMES, pStack, NULL);

    std::ostringstream oss;
    oss << "stack traceback: " << std::endl;
    for (WORD i = 0; i < frames; ++i) {
        DWORD64 address = (DWORD64)(pStack[i]);

        DWORD64 displacementSym = 0;
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD displacementLine = 0;
        IMAGEHLP_LINE64 line;
        //SymSetOptions(SYMOPT_LOAD_LINES);  
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

        if (SymFromAddr(process, address, &displacementSym, pSymbol)
            && SymGetLineFromAddr64(process, address, &displacementLine, &line)) {
            oss << "\t" << pSymbol->Name << " at " << line.FileName << ":" << line.LineNumber << "(0x" << std::hex << pSymbol->Address << std::dec << ")" << std::endl;
        }
        else {
            oss << "\terror: " << GetLastError() << std::endl;
        }
    }
    return oss.str();
}

string TraceStack(WORD frames, void *pStack[MAX_STACK_FRAMES])
{
    std::ostringstream oss;
    oss << "stack traceback: " << std::endl;
    for (WORD i = 0; i < frames; ++i) {
        DWORD64 address = (DWORD64)(pStack[i]);

        DWORD64 displacementSym = 0;
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD displacementLine = 0;
        IMAGEHLP_LINE64 line;
        //SymSetOptions(SYMOPT_LOAD_LINES);  
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        if (SymFromAddr(process, address, &displacementSym, pSymbol)
            && SymGetLineFromAddr64(process, address, &displacementLine, &line)) {
            oss << "\t" << pSymbol->Name << " at " << line.FileName << ":" << line.LineNumber << "(0x" << std::hex << pSymbol->Address << std::dec << ")" << std::endl;
        }
        else {
            oss << "\terror: " << GetLastError() << std::endl;
        }
    }
    return oss.str();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //打印堆栈前的初始化，如果放在malloc中调用的堆栈函数中，会导致嵌套调用
        process = GetCurrentProcess();
        SymInitialize(process, NULL, TRUE);
        OutputDebugStringA("start hook....................................");
        s_hDll = hModule;
        DisableThreadLibraryCalls(hModule);
        SetHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DropHook();
        OutputDebugStringA("memory leak....................................");
        for (size_t i = 0; i < size(g_array); i++)
        {
            if (g_array[i].pAddress == nullptr
                || g_array[i].bLeaked == false)
            {
                continue;
            }
            char s[1000] = { 0 };
            sprintf(s, "Memory: %0x, size: %d\r\%s\r\n", g_array[i].pAddress, g_array[i].nSize, TraceStack(g_array[i].frames, g_array[i].pStack).c_str());
            OutputDebugStringA(s);
        }
        OutputDebugStringA("end hook....................................");



        break;
    }
    return TRUE;
}

