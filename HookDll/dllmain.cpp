// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <sstream>

#include "detours.h"
#pragma comment(lib, "detours.lib")

#include <Dbghelp.h>
#pragma comment(lib, "dbghelp.lib") 

using namespace std;

typedef void * (__cdecl * PFN_MALLOC)(size_t _Size);
typedef void(__cdecl * PFN_FREE)(void* _Block);
PFN_MALLOC g_pMalloc = malloc;
PFN_FREE   g_pFree = free;

static const int MAX_STACK_FRAMES = 10;

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
int          g_nIndex = 0;
HANDLE       g_process = NULL;

void* __cdecl HookMalloc(_In_ _CRT_GUARDOVERFLOW size_t _Size)
{
    void *pVoid = g_pMalloc(_Size);

    MemoryLeaker *pLeaker = &g_array[g_nIndex++];
    pLeaker->pAddress = pVoid;
    pLeaker->nSize = _Size;
    pLeaker->frames = CaptureStackBackTrace(0, MAX_STACK_FRAMES, pLeaker->pStack, NULL);

    return pVoid;
}

void __cdecl HookFree(_Pre_maybenull_ _Post_invalid_ void* _Block)
{
    for (size_t i = 0; i < size(g_array); i++)
    {
        if (g_array[i].pAddress == _Block)
        {
            g_array[i].bLeaked = false;
            break;
        }
    }

    g_pFree(_Block);
}

extern "C" _declspec(dllexport) BOOL APIENTRY StartHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //TODO: 后续还要增加对realloc，realloc，calloc，_recalloc和free的监控，来处理内存泄露，详见截图：hook.png
    if (NO_ERROR != DetourAttach(&(PVOID&)g_pMalloc, HookMalloc))
    {

    }

    if (NO_ERROR != DetourAttach(&(PVOID&)g_pFree, HookFree))
    {

    }

    return DetourTransactionCommit() == NO_ERROR;
}

extern "C" _declspec(dllexport) BOOL APIENTRY StopHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)g_pMalloc, HookMalloc);

    return DetourTransactionCommit() == NO_ERROR;
}

string TraceStack(WORD frames, void *pStack[MAX_STACK_FRAMES])
{
    std::ostringstream os;
    os << "stack traceback: " << std::endl;
    for (WORD i = 0; i < frames; ++i)
    {
        DWORD64 address = (DWORD64)(pStack[i]);

        DWORD64 displacementSym = 0;
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD displacementLine = 0;
        IMAGEHLP_LINE64 line;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        if (SymFromAddr(g_process, address, &displacementSym, pSymbol)
            && SymGetLineFromAddr64(g_process, address, &displacementLine, &line))
        {
            os << "\t" << pSymbol->Name << " at " << line.FileName << ":" << line.LineNumber << "(0x" << std::hex << pSymbol->Address << std::dec << ")" << std::endl;
        }
        else
        {
            os << "\terror: " << GetLastError() << std::endl;
        }
    }

    return os.str();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_process = GetCurrentProcess();
        SymInitialize(g_process, NULL, TRUE);
        OutputDebugStringA("start hook....................................\n");
        DisableThreadLibraryCalls(hModule);
        StartHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        StopHook();
        OutputDebugStringA("memory leak....................................\n");
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
        OutputDebugStringA("end hook....................................\n");
        break;
    }
    return TRUE;
}