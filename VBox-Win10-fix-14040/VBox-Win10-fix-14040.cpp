/*
  VBox-Win10-fix-14040 -
  Hooks VirtualBox service and delays a registry query during host-only
  network interface creation to fix compatibility with Windows 10.
  See https://www.virtualbox.org/ticket/14040 for details.

  Copyright (c) 2015, Jiri Hruska <jirka@fud.cz>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
  IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#define UNICODE
#define _UNICODE
#include <Windows.h>
#pragma comment(lib, "shell32.lib")
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")
#include <CommCtrl.h>
#pragma comment(lib, "comctl32.lib")
#include <stdio.h>
#include <vector>
#include <set>
#include <map>

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

//---

FILE* g_log;

void log(const char* group, const char* str, ...)
{
  if (!g_log)
    return;

  SYSTEMTIME st;
  GetLocalTime(&st);
  fprintf(g_log, "%02d:%02d:%02d.%03d | %-16s | ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, group);

  va_list va;
  va_start(va, str);
  vfprintf(g_log, str, va);
  va_end(va);

  fputc('\n', g_log);
}

void openLog(const wchar_t* basename)
{
  SYSTEMTIME st;
  GetLocalTime(&st);
  wchar_t filename[MAX_PATH];
  swprintf_s(filename, L"%s.%04d%02d%02d-%02d%02d%02d-%d.log", basename, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());
  g_log = _wfopen(filename, L"w");
  log("--------", "Logging started");
}

void closeLog()
{
  log("--------", "Logging stopped");
  if (g_log)
    fclose(g_log);
  g_log = NULL;
}

void flushLog()
{
  if (g_log)
    fflush(g_log);
}

//---

struct PointerOrAddress {
  LPVOID m_value;
  PointerOrAddress(LPVOID value)    : m_value(reinterpret_cast<LPVOID>(value)) {}
  PointerOrAddress(DWORD_PTR value) : m_value(reinterpret_cast<LPVOID>(value)) {}
  operator LPVOID()    const { return reinterpret_cast<   LPVOID>(m_value); }
  operator DWORD_PTR() const { return reinterpret_cast<DWORD_PTR>(m_value); }
};

HANDLE g_hProcess;
LPVOID g_mainImageBase;
std::map<DWORD, HANDLE> g_hThread;

#define ADDR_OFS(_base, _ofs) static_cast<LPVOID>(reinterpret_cast<LPBYTE>(_base) + (_ofs))

template<typename T> bool readProcMem(PointerOrAddress lpAddress, T* data)
{
  SIZE_T nr;
  return !!ReadProcessMemory(g_hProcess, lpAddress, data, sizeof(*data), &nr) && (nr == sizeof(*data));
}

void* readProcString(PointerOrAddress lpAddress, int maxLength, bool unicode)
{
  void* buf = malloc((unicode ? 2 : 1) * (maxLength + 1));
  SIZE_T nr;
  if (!ReadProcessMemory(g_hProcess, lpAddress, buf, unicode ? maxLength * 2 : maxLength, &nr)) {
    free(buf);
    return NULL;
  }
  if (unicode)
    static_cast<WCHAR*>(buf)[nr / 2] = L'\0';
  else
    static_cast<CHAR*>(buf)[nr] = '\0';
  return buf;
}

void writeProcMem(PointerOrAddress lpBaseAddress, LPCVOID lpData, SIZE_T dwCount)
{
  WriteProcessMemory(g_hProcess, lpBaseAddress, lpData, dwCount, NULL);
}

//---

struct Breakpoint {
  PointerOrAddress addr;
  BYTE orig;
  bool reinstate;

  Breakpoint(PointerOrAddress p_addr) : addr(p_addr), orig(0xCC), reinstate(false) {}
  Breakpoint(const Breakpoint& other) : addr(other.addr), orig(other.orig), reinstate(other.reinstate) {}
  bool operator<(const Breakpoint& other) const { return static_cast<DWORD_PTR>(addr) < other.addr; }
};

std::set<Breakpoint> g_breakpoints;

void bpSet(PointerOrAddress addr)
{
  if (g_breakpoints.find(addr) != g_breakpoints.end())
    return;

  Breakpoint bp(addr);
  readProcMem(bp.addr, &bp.orig);
  g_breakpoints.insert(bp);

  if (bp.orig != 0xCC) {
    writeProcMem(bp.addr, "\xCC", 1);
    FlushInstructionCache(g_hProcess, bp.addr, 1);
  }

  log("Breakpoint", "Added at 0x%p (orig. 0x%02X)", bp.addr, bp.orig);
}

bool bpTest(PointerOrAddress addr)
{
  return (g_breakpoints.find(addr) != g_breakpoints.end());
}

void bpClear(PointerOrAddress addr)
{
  auto it = g_breakpoints.find(addr);
  if (it == g_breakpoints.end())
    return;

  writeProcMem(addr, &it->orig, 1);
  FlushInstructionCache(g_hProcess, it->addr, 1);

  log("Breakpoint", "Removed at 0x%p (orig. 0x%02X)", it->addr, it->orig);

  g_breakpoints.erase(it);
}

void bpTempClear(PointerOrAddress addr)
{
  auto it = g_breakpoints.find(addr);
  if (it == g_breakpoints.end())
    return;

  Breakpoint& bp = const_cast<Breakpoint&>(*it);

  writeProcMem(addr, &bp.orig, 1);
  FlushInstructionCache(g_hProcess, bp.addr, 1);
  bp.reinstate = true;

  log("Breakpoint", "Temporarily removed at 0x%p (orig. 0x%02X)", bp.addr, bp.orig);
}

void bpReinstate()
{
  for (auto& cbp : g_breakpoints) {
    Breakpoint& bp = const_cast<Breakpoint&>(cbp);
    if (!bp.reinstate)
      continue;

    if (bp.orig != 0xCC) {
      writeProcMem(bp.addr, "\xCC", 1);
      FlushInstructionCache(g_hProcess, bp.addr, 1);
    }
    bp.reinstate = false;

    log("Breakpoint", "Reinstated at 0x%p", bp.addr);
  }
}

void bpClearAll()
{
  for (auto& bp : g_breakpoints) {
    if (bp.reinstate)
      continue;

    writeProcMem(bp.addr, &bp.orig, 1);
    FlushInstructionCache(g_hProcess, bp.addr, 1);

    log("Breakpoint", "Removed at 0x%p (orig. 0x%02X)", bp.addr, bp.orig);
  }

  g_breakpoints.clear();
}

//---

int runDebugger(wchar_t* selfname, wchar_t* cmdline)
{
  struct Logger {
    Logger(const wchar_t* logname)
    {
      openLog(logname);
    }

    ~Logger()
    {
      closeLog();
    }
  } logger(selfname);

  WCHAR runningPath[MAX_PATH];
  wcscpy_s(runningPath, selfname);
  wcscat_s(runningPath, L".running");
  DWORD lastRunningCheck = GetTickCount();

  DWORD_PTR advapi32_RegQueryValueExW_ofs;
  {
    HMODULE hAdvapi32 = LoadLibrary(L"advapi32.dll");
    if (!hAdvapi32) {
      log("Main", "Could not load advapi32.dll");
      return -1;
    }
    void* pRegQueryValueExW = GetProcAddress(hAdvapi32, "RegQueryValueExW");
    if (!pRegQueryValueExW) {
      log("Main", "Could not resolve RegQueryValueExW");
      FreeLibrary(hAdvapi32);
      return -1;
    }
    log("VboxFix", "hAdvapi32 = %p, pRegQueryValueExW = %p", hAdvapi32, pRegQueryValueExW);
    advapi32_RegQueryValueExW_ofs = static_cast<BYTE*>(pRegQueryValueExW) - reinterpret_cast<BYTE*>(hAdvapi32);
    FreeLibrary(hAdvapi32);
  }

  log("Main", "Executing subprocess %S", cmdline);
  STARTUPINFO si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  if (!CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
                     DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                     NULL, NULL, &si, &pi)) {
    log("Main", "CreateProcess() failed (%d).", GetLastError());
    return -1;
  }
  DebugSetProcessKillOnExit(FALSE);
  CloseHandle(pi.hThread);

  DWORD dwExitCode = 0;
  bool done = false;
  while (!done) {
    DEBUG_EVENT de;
    bool hasEvent = true;
    if (!WaitForDebugEvent(&de, 1000)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT) {
        hasEvent = false;
      } else {
        log("Main", "WaitForDebugEvent() failed (%d).", GetLastError());
        break;
      }
    }

    if (GetTickCount() - lastRunningCheck > 1000) {
      if (GetFileAttributes(runningPath) == INVALID_FILE_ATTRIBUTES) {
        log("Main", "Parent's running file is missing, detaching...");
detach:
        for (auto& thread : g_hThread) {
          SuspendThread(thread.second);
          CONTEXT ctx;
          ctx.ContextFlags = CONTEXT_CONTROL;
          GetThreadContext(thread.second, &ctx);
          ctx.EFlags &= ~0x100;
          SetThreadContext(thread.second, &ctx);
        }
        bpClearAll();
        for (auto& thread : g_hThread)
          ResumeThread(thread.second);
        if (hasEvent)
          ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        DebugActiveProcessStop(pi.dwProcessId);
        g_hProcess = NULL;
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        log("Main", "Subprocess finished with exit code %d", dwExitCode);
        break;
      }
      lastRunningCheck = GetTickCount();
      flushLog();
    }

    if (!hasEvent)
      continue;

    DWORD dwContinueStatus = DBG_CONTINUE;
    switch (de.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT: {
        CREATE_PROCESS_DEBUG_INFO& cpdi = de.u.CreateProcessInfo;
        g_hProcess = cpdi.hProcess;
        g_hThread[de.dwThreadId] = cpdi.hThread;
        g_mainImageBase = cpdi.lpBaseOfImage;
        WCHAR name[MAX_PATH];
        if (!GetMappedFileName(g_hProcess, cpdi.lpBaseOfImage, name, MAX_PATH))
          wcscpy_s(name, L"<unknown>");
        log("E:CreateProcess", "ID: %u, 0x%p => %S", GetProcessId(g_hProcess), cpdi.lpBaseOfImage, name);
        CloseHandle(cpdi.hFile);
        if (wcsstr(cmdline, L"/Helper VirtualBox\\SVCHelper\\") == NULL) {
          log("VboxFix", "Not a helper execution, letting it be...");
          goto detach;
        }
        break;
      }

      case EXIT_PROCESS_DEBUG_EVENT: {
        EXIT_PROCESS_DEBUG_INFO& epdi = de.u.ExitProcess;
        log("E:ExitProcess", "Exit code: %u", epdi.dwExitCode);
        dwExitCode = epdi.dwExitCode;
        done = true;
        break;
      }

      case CREATE_THREAD_DEBUG_EVENT: {
        CREATE_THREAD_DEBUG_INFO& ctdi = de.u.CreateThread;
        log("E:CreateThread", "ID: %u", de.dwThreadId);
        g_hThread[de.dwThreadId] = ctdi.hThread;
        break;
      }

      case EXIT_THREAD_DEBUG_EVENT: {
        EXIT_THREAD_DEBUG_INFO& etdi = de.u.ExitThread;
        log("E:ExitThread", "ID: %u, Exit code: %u", de.dwThreadId, etdi.dwExitCode);
        g_hThread.erase(de.dwThreadId);
        break;
      }

      case LOAD_DLL_DEBUG_EVENT: {
        LOAD_DLL_DEBUG_INFO& lddi = de.u.LoadDll;
        WCHAR name[MAX_PATH];
        if (!GetMappedFileName(g_hProcess, lddi.lpBaseOfDll, name, MAX_PATH))
          wcscpy_s(name, L"<unknown>");
        log("E:LoadDll", "0x%p => %S", lddi.lpBaseOfDll, name);
        LPCTSTR basename = wcsrchr(name, L'\\');
        basename = basename ? basename + 1 : L"";
        if (_wcsicmp(basename, L"advapi32.dll") == 0)
          bpSet(ADDR_OFS(lddi.lpBaseOfDll, advapi32_RegQueryValueExW_ofs));
        CloseHandle(lddi.hFile);
        break;
      }

      case UNLOAD_DLL_DEBUG_EVENT: {
        UNLOAD_DLL_DEBUG_INFO& uddi = de.u.UnloadDll;
        log("E:UnloadDll", "0x%p", uddi.lpBaseOfDll);
        break;
      }

      case EXCEPTION_DEBUG_EVENT: {
        EXCEPTION_DEBUG_INFO& edi = de.u.Exception;
        EXCEPTION_RECORD& er = edi.ExceptionRecord;
        if (er.ExceptionCode == EXCEPTION_BREAKPOINT && bpTest(er.ExceptionAddress)) {
          CONTEXT ctx;
          ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
          GetThreadContext(g_hThread[de.dwThreadId], &ctx);

#ifdef _WIN64
          // RCX = hKey, RDX = lpValueName, R8 = lpReserved, R9 = lpType
          WCHAR* lpValueName = (WCHAR*)readProcString(ctx.Rdx, 34, true);
#else
          // [ESP+04h] = hKey, [ESP+08h] = lpValueName, ...
          LPVOID arg8;
          readProcMem(ctx.Esp + 8, &arg8);
          WCHAR* lpValueName = (WCHAR*)readProcString(arg8, 34, true);
#endif
          if (lpValueName && wcscmp(lpValueName, L"NetCfgInstanceId") == 0) {
            LPVOID lpReturnAddr;
#ifdef _WIN64
            readProcMem(ctx.Rsp, &lpReturnAddr);
#else
            readProcMem(ctx.Esp, &lpReturnAddr);
#endif
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQueryEx(g_hProcess, lpReturnAddr, &mbi, sizeof(mbi));
            if (mbi.AllocationBase == g_mainImageBase) {
              log("VboxFix", "RegQueryValueExW(NetCfgInstanceId) intercepted, sleeping for 3 seconds...");
              Sleep(3000);
            }
          }
          free(lpValueName);

          bpTempClear(er.ExceptionAddress);
#ifdef _WIN64
          ctx.Rip--;
#else
          ctx.Eip--;
#endif
          ctx.EFlags |= 0x100;
          SetThreadContext(g_hThread[de.dwThreadId], &ctx);
        } else if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
          bpReinstate();
        } else {
          log("E:Exception", "0x%08X at 0x%p (%s chance)", er.ExceptionCode, er.ExceptionAddress,
            edi.dwFirstChance ? "first" : "last");
          if (!edi.dwFirstChance)
            TerminateProcess(g_hProcess, er.ExceptionCode);
          dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }
        break;
      }

      case OUTPUT_DEBUG_STRING_EVENT: {
        OUTPUT_DEBUG_STRING_INFO& odsi = de.u.DebugString;
        void* str = readProcString(odsi.lpDebugStringData, odsi.nDebugStringLength, !!odsi.fUnicode);
        if (odsi.fUnicode)
          log("E:DebugString", "%S", str);
        else
          log("E:DebugString", "%s", str);
        free(str);
        break;
      }

      case RIP_EVENT: {
        RIP_INFO& ri = de.u.RipInfo;
        log("E:RIP", "Error: %u, Type: 0x%04X", ri.dwError, ri.dwType);
        break;
      }
    }

    if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus)) {
      log("Main", "ContinueDebugEvent() failed (%d).", GetLastError());
      break;
    }
  }

  CloseHandle(pi.hProcess);
  return dwExitCode;
}

//---

bool setDebuggerFor(const WCHAR* image, const WCHAR* debugger)
{
  HKEY hKey;
  WCHAR path[MAX_PATH];
  wcscpy_s(path, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\");
  wcscat_s(path, image);
  DWORD err = RegCreateKeyEx(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
  if (err != ERROR_SUCCESS)
    return false;

  err = RegSetValueEx(hKey, L"Debugger", 0, REG_SZ, reinterpret_cast<const BYTE*>(debugger), static_cast<DWORD>(2 * (wcslen(debugger) + 1)));
  if (err != ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return false;
  }

  RegCloseKey(hKey);
  return true;
}

bool clearDebuggerFor(const WCHAR* image)
{
  HKEY hKey;
  WCHAR path[MAX_PATH];
  wcscpy_s(path, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\");
  const WCHAR* root = path + wcslen(path);
  wcscat_s(path, image);

  DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &hKey);
  if (err == ERROR_SUCCESS) {
    RegDeleteValue(hKey, L"Debugger");
    RegCloseKey(hKey);
  }

  for (;;) {
    WCHAR* ptr = wcsrchr(path, L'\\');
    *ptr = L'\0';

    DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE, &hKey);
    if (err == ERROR_SUCCESS) {
      err = RegDeleteKeyEx(hKey, ptr + 1, 0, 0);
      RegCloseKey(hKey);
      if (err != ERROR_SUCCESS)
        break;
    }

    if (ptr < root)
      break;
  }

  return true;
}

//---

enum {
  IDC_BUGLINK = 100,
  IDC_CLOSE
};

INT_PTR WINAPI dialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch (uMsg) {
    case WM_INITDIALOG:
      PostMessage(hwndDlg, WM_APP + 0, 0, 0);
      return TRUE;

    case WM_DESTROY:
      clearDebuggerFor(L"VBoxSvc.exe");
      PostQuitMessage(0);
      return TRUE;

    case WM_CLOSE:
      DestroyWindow(hwndDlg);
      return TRUE;

    case WM_COMMAND:
      switch (LOWORD(wParam)) {
        case IDC_CLOSE:
          DestroyWindow(hwndDlg);
          break;
      }
      return TRUE;

    case WM_APP: {
      WCHAR self[MAX_PATH];
      GetModuleFileName(NULL, self, _countof(self));
      wcscat_s(self, L" /debug");
      if (!setDebuggerFor(L"VBoxSvc.exe", self))
        MessageBox(hwndDlg, TEXT("Could not set everything up. Perhaps you did not run me as an administrator?"), TEXT("Error"), MB_ICONERROR | MB_OK);
      else
        SetWindowText(hwndDlg, L"VirtualBox Windows 10 fix - ACTIVE");
      break;
    }
  }

  return FALSE;
}

class DialogTemplate {
  public:
    enum Classes {
      BUTTON    = 0x0080,
      EDIT      = 0x0081,
      STATIC    = 0x0082,
      LISTBOX   = 0x0083,
      SCROLLBAR = 0x0084,
      COMBOBOX  = 0x0085
    };

  public:
    DialogTemplate(DWORD dwStyle, DWORD dwExtendedStyle, short x, short y, short cx, short cy, LPCWSTR lpszTitle)
    {
      size_t len = wcslen(lpszTitle) + 1;
      m_buffer.resize(sizeof(DLGTEMPLATE) + 2 + 2 + 2 * len);

      DLGTEMPLATE* dlg = reinterpret_cast<DLGTEMPLATE*>(&m_buffer[0]);
      dlg->style = dwStyle & ~DS_SETFONT;
      dlg->dwExtendedStyle = dwExtendedStyle;
      dlg->cdit = 0;
      dlg->x = x;
      dlg->y = y;
      dlg->cx = cx;
      dlg->cy = cy;

      WORD* meta = reinterpret_cast<WORD*>(&m_buffer[sizeof(DLGTEMPLATE)]);
      meta[0] = 0x0000;
      meta[1] = 0x0000;
      memcpy(meta + 2, lpszTitle, 2 * len);
    }

    void setFont(WORD wFontSize, LPCWSTR lpszFontFace)
    {
      size_t ofs = sizeof(DLGTEMPLATE) + 2 + 2 + 2 * (wcslen(reinterpret_cast<WCHAR*>(&m_buffer[sizeof(DLGTEMPLATE) + 2 + 2])) + 1);
      size_t len = wcslen(lpszFontFace) + 1;
      m_buffer.resize(ofs + 2 + 2 * len);

      DLGTEMPLATE* dlg = reinterpret_cast<DLGTEMPLATE*>(&m_buffer[0]);
      dlg->style |= DS_SETFONT;
      dlg->cdit = 0;

      WORD* meta = reinterpret_cast<WORD*>(&m_buffer[ofs]);
      meta[0] = wFontSize;
      memcpy(meta + 1, lpszFontFace, 2 * len);
    }

    void addControl(WORD wId, LPWSTR classNameOrId, short x, short y, short cx, short cy, DWORD dwStyle, DWORD dwExtendedStyle, LPCWSTR lpszTitle)
    {
      size_t pad = (m_buffer.size() & 3) ? 2 : 0;
      size_t ofs = m_buffer.size() + pad;
      size_t classLen = (reinterpret_cast<DWORD_PTR>(classNameOrId) < 0x10000) ? 2 : (wcslen(classNameOrId) + 1);
      size_t titleLen = wcslen(lpszTitle) + 1;
      m_buffer.resize(ofs + sizeof(DLGITEMTEMPLATE) + 2 * classLen + 2 * titleLen + 2);

      DLGTEMPLATE* dlg = reinterpret_cast<DLGTEMPLATE*>(&m_buffer[0]);
      dlg->cdit++;

      DLGITEMTEMPLATE* item = reinterpret_cast<DLGITEMTEMPLATE*>(&m_buffer[ofs]);
      item->style = dwStyle;
      item->dwExtendedStyle = dwExtendedStyle;
      item->x = x;
      item->y = y;
      item->cx = cx;
      item->cy = cy;
      item->id = wId;

      WORD* meta = reinterpret_cast<WORD*>(&m_buffer[ofs + sizeof(DLGITEMTEMPLATE)]);

      if (reinterpret_cast<DWORD_PTR>(classNameOrId) < 0x10000) {
        meta[0] = 0xFFFF;
        meta[1] = reinterpret_cast<WORD>(classNameOrId);
      } else
        memcpy(meta, classNameOrId, 2 * classLen);
      meta += classLen;

      memcpy(meta, lpszTitle, 2 * titleLen);
    }

    void addStatic(WORD wId, short x, short y, short cx, short cy, DWORD dwStyle, LPCWSTR lpszTitle)
    {
      addControl(wId, MAKEINTATOM(STATIC), x, y, cx, cy, dwStyle | WS_GROUP | WS_VISIBLE, 0, lpszTitle);
    }

    void addButton(WORD wId, short x, short y, short cx, short cy, DWORD dwStyle, LPCWSTR lpszTitle)
    {
      addControl(wId, MAKEINTATOM(BUTTON), x, y, cx, cy, dwStyle | WS_TABSTOP | WS_VISIBLE, 0, lpszTitle);
    }

    void addEdit(WORD wId, short x, short y, short cx, short cy, DWORD dwStyle, LPCWSTR lpszTitle)
    {
      addControl(wId, MAKEINTATOM(EDIT), x, y, cx, cy, dwStyle | WS_BORDER | WS_TABSTOP | WS_VISIBLE, 0, lpszTitle);
    }

    operator DLGTEMPLATE*()
    {
      return reinterpret_cast<DLGTEMPLATE*>(&m_buffer[0]);
    }

  protected:
    std::vector<BYTE> m_buffer;
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
  LPWSTR cmdline = GetCommandLineW();
  int argc;
  LPWSTR* argv = CommandLineToArgvW(cmdline, &argc);
  if (!argv)
    return -1;

  wchar_t* selfname = argv[0];
  wchar_t* dot = wcsrchr(selfname, L'.');
  if (dot && dot > wcsrchr(selfname, L'\\'))
    *dot = L'\0';

  if (argv && argc > 1 && wcscmp(argv[1], L"/debug") == 0)
    return runDebugger(selfname, wcsstr(cmdline, L"/debug ") + 7);

  WCHAR runningPath[MAX_PATH];
  wcscpy_s(runningPath, selfname);
  wcscat_s(runningPath, L".running");
  CreateFile(runningPath, 0, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);

  LocalFree(argv);

  INITCOMMONCONTROLSEX icce = {sizeof(icce), ICC_STANDARD_CLASSES | ICC_LINK_CLASS};
  if (!InitCommonControlsEx(&icce))
    return -1;

  HWND hMainWnd;
  {
    DialogTemplate dlg(DS_CENTER | DS_SHELLFONT | WS_CAPTION | WS_SYSMENU, WS_EX_WINDOWEDGE, 0, 0, 233, 70, L"VirtualBox Windows 10 fix - INACTIVE");
    dlg.setFont(8, L"MS Shell Dlg");
    dlg.addStatic (-1,                   7,   7, 220, 17,  SS_LEFT, L"This fixes the incompatibility of VirtualBox with Windows 10 which prevents one from setting up virtual host-only network interfaces.");
    dlg.addStatic (-1,                   7,  26, 220, 17,  SS_LEFT, L"Leave this application running in the background during the setup of your VM, then it should be closed to avoid the overhead for VboxSvc.");
    dlg.addStatic (-1,                   7,  45, 220, 17,  SS_LEFT, L"Created by Jiri Hruska <jirka@fud.cz> (2015-08-01)");
    dlg.addControl(IDC_BUGLINK, WC_LINK, 7,  56, 220, 17,  WS_VISIBLE | WS_CHILD | WS_TABSTOP, 0, L"More information: <a href=\"https://www.virtualbox.org/ticket/14040\">VirtualBox ticket #14040</a>");
    hMainWnd = CreateDialogIndirect(GetModuleHandle(NULL), dlg, NULL, &dialogProc);
  }
  if (!hMainWnd)
    return -1;

  ShowWindow(hMainWnd, nCmdShow);

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0) > 0) {
    if (IsDialogMessage(hMainWnd, &msg))
      continue;
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  return 0;
}
