#pragma once

//=============================================================================
//  lazy_api.hpp  –  Runtime-resolved Win32 API stubs (IAT hiding)
//
//  All DLL names are WOBF-encrypted and all export names are OBF-encrypted so
//  neither appears as plaintext in the binary's .rdata / import table.
//
//  Headers are included for type declarations ONLY.
//  NO #pragma comment(lib, ...) anywhere in this file.
//=============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <dbghelp.h>      // SYMBOL_INFOW, MODLOAD_DATA, etc. – types only, no lib
#include <winhttp.h>      // HINTERNET, URL_COMPONENTS, etc.  – types only, no lib
#include <imm.h>          // HIMC, CANDIDATEFORM, COMPOSITIONFORM – types only, no lib
#include <d3d11.h>        // ID3D11Device, IDXGISwapChain, etc.  – types only, no lib
#include <d3dcompiler.h>  // D3D_SHADER_MACRO, ID3DBlob, etc.    – types only, no lib
#include "string_obf.hpp" // OBF / WOBF / WOBFS macros

namespace lazy {

//─────────────────────────────── kernel32 ─────────────────────────────────────
// kernel32 is always mapped – GetModuleHandleW never fails here.
namespace k32 {

    // ── existing ──────────────────────────────────────────────────────────────
    using fn_CreateFileW              = HANDLE   (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using fn_CreateFileMappingW       = HANDLE   (WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    using fn_MapViewOfFile            = LPVOID   (WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    using fn_UnmapViewOfFile          = BOOL     (WINAPI*)(LPCVOID);
    using fn_DeviceIoControl          = BOOL     (WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using fn_GetCurrentProcess        = HANDLE   (WINAPI*)();
    using fn_GetCurrentProcessId      = DWORD    (WINAPI*)();
    using fn_IsDebuggerPresent        = BOOL     (WINAPI*)();
    using fn_CreateProcessW           = BOOL     (WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                                           LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                                           LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using fn_EnumDeviceDrivers        = BOOL     (WINAPI*)(LPVOID*, DWORD, LPDWORD);
    using fn_GetDeviceDriverFileNameW = DWORD    (WINAPI*)(LPVOID, LPWSTR, DWORD);

    // ── string / encoding ─────────────────────────────────────────────────────
    using fn_MultiByteToWideChar      = int      (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int);
    using fn_WideCharToMultiByte      = int      (WINAPI*)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
    using fn_GetLocaleInfoA           = int      (WINAPI*)(LCID, LCTYPE, LPSTR,  int);
    using fn_GetLocaleInfoW           = int      (WINAPI*)(LCID, LCTYPE, LPWSTR, int);
    using fn_GetLocaleInfoEx          = int      (WINAPI*)(LPCWSTR, LCTYPE, LPWSTR, int);
    using fn_LCMapStringW             = int      (WINAPI*)(LCID, DWORD, LPCWSTR, int, LPWSTR, int);
    using fn_GetStringTypeW           = BOOL     (WINAPI*)(DWORD, LPCWSTR, int, LPWORD);
    using fn_GetCPInfo                = BOOL     (WINAPI*)(UINT, LPCPINFO);
    using fn_GetACP                   = UINT     (WINAPI*)();
    using fn_GetOEMCP                 = UINT     (WINAPI*)();
    using fn_IsValidCodePage          = BOOL     (WINAPI*)(UINT);
    using fn_IsValidLocale            = BOOL     (WINAPI*)(LCID, DWORD);
    using fn_GetUserDefaultLCID       = LCID     (WINAPI*)();
    using fn_EnumSystemLocalesW       = BOOL     (WINAPI*)(LOCALE_ENUMPROCW, DWORD);

    // ── environment / command line ────────────────────────────────────────────
    using fn_GetEnvironmentVariableW  = DWORD    (WINAPI*)(LPCWSTR, LPWSTR, DWORD);
    using fn_GetEnvironmentStringsW   = LPWCH    (WINAPI*)();
    using fn_FreeEnvironmentStringsW  = BOOL     (WINAPI*)(LPWCH);
    using fn_GetCommandLineW          = LPWSTR   (WINAPI*)();
    using fn_GetCommandLineA          = LPSTR    (WINAPI*)();

    // ── file / path ───────────────────────────────────────────────────────────
    using fn_GetTempPathW             = DWORD    (WINAPI*)(DWORD, LPWSTR);
    using fn_GetFileAttributesW       = DWORD    (WINAPI*)(LPCWSTR);
    using fn_GetFileAttributesExW     = BOOL     (WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
    using fn_SetFileAttributesW       = BOOL     (WINAPI*)(LPCWSTR, DWORD);
    using fn_DeleteFileW              = BOOL     (WINAPI*)(LPCWSTR);
    using fn_CloseHandle              = BOOL     (WINAPI*)(HANDLE);
    using fn_WriteFile                = BOOL     (WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using fn_ReadFile                 = BOOL     (WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using fn_SetFilePointerEx         = BOOL     (WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
    using fn_SetEndOfFile             = BOOL     (WINAPI*)(HANDLE);
    using fn_GetFileSizeEx            = BOOL     (WINAPI*)(HANDLE, PLARGE_INTEGER);
    using fn_GetFileType              = DWORD    (WINAPI*)(HANDLE);
    using fn_FlushFileBuffers         = BOOL     (WINAPI*)(HANDLE);
    using fn_GetFileInformationByHandleEx = BOOL (WINAPI*)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
    using fn_AreFileApisANSI          = BOOL     (WINAPI*)();
    using fn_CreateDirectoryW         = BOOL     (WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
    using fn_GetFullPathNameW         = DWORD    (WINAPI*)(LPCWSTR, DWORD, LPWSTR, LPWSTR*);
    using fn_GetModuleFileNameW       = DWORD    (WINAPI*)(HMODULE, LPWSTR, DWORD);

    // ── find files ────────────────────────────────────────────────────────────
    using fn_FindFirstFileW           = HANDLE   (WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
    using fn_FindFirstFileExW         = HANDLE   (WINAPI*)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
    using fn_FindNextFileW            = BOOL     (WINAPI*)(HANDLE, LPWIN32_FIND_DATAW);
    using fn_FindClose                = BOOL     (WINAPI*)(HANDLE);

    // ── module / library ─────────────────────────────────────────────────────
    using fn_GetModuleHandleA         = HMODULE  (WINAPI*)(LPCSTR);
    using fn_GetModuleHandleW         = HMODULE  (WINAPI*)(LPCWSTR);
    using fn_GetModuleHandleExW       = BOOL     (WINAPI*)(DWORD, LPCWSTR, HMODULE*);
    using fn_LoadLibraryA             = HMODULE  (WINAPI*)(LPCSTR);
    using fn_LoadLibraryW             = HMODULE  (WINAPI*)(LPCWSTR);
    using fn_LoadLibraryExW           = HMODULE  (WINAPI*)(LPCWSTR, HANDLE, DWORD);
    using fn_FreeLibrary              = BOOL     (WINAPI*)(HMODULE);
    using fn_GetProcAddress           = FARPROC  (WINAPI*)(HMODULE, LPCSTR);

    // ── resources ────────────────────────────────────────────────────────────
    using fn_FindResourceW            = HRSRC    (WINAPI*)(HMODULE, LPCWSTR, LPCWSTR);
    using fn_LoadResource             = HGLOBAL  (WINAPI*)(HMODULE, HRSRC);
    using fn_LockResource             = LPVOID   (WINAPI*)(HGLOBAL);
    using fn_SizeofResource           = DWORD    (WINAPI*)(HMODULE, HRSRC);

    // ── memory ────────────────────────────────────────────────────────────────
    using fn_LocalFree                = HLOCAL   (WINAPI*)(HLOCAL);
    using fn_GlobalAlloc              = HGLOBAL  (WINAPI*)(UINT, SIZE_T);
    using fn_GlobalFree               = HGLOBAL  (WINAPI*)(HGLOBAL);
    using fn_GlobalLock               = LPVOID   (WINAPI*)(HGLOBAL);
    using fn_GlobalUnlock             = BOOL     (WINAPI*)(HGLOBAL);
    using fn_GetProcessHeap           = HANDLE   (WINAPI*)();
    using fn_HeapAlloc                = LPVOID   (WINAPI*)(HANDLE, DWORD, SIZE_T);
    using fn_HeapReAlloc              = LPVOID   (WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
    using fn_HeapFree                 = BOOL     (WINAPI*)(HANDLE, DWORD, LPVOID);
    using fn_HeapSize                 = SIZE_T   (WINAPI*)(HANDLE, DWORD, LPCVOID);
    using fn_VirtualProtect           = BOOL     (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

    // ── sync / threading ─────────────────────────────────────────────────────
    using fn_Sleep                    = void     (WINAPI*)(DWORD);
    using fn_CreateThread             = HANDLE   (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using fn_GetCurrentThreadId       = DWORD    (WINAPI*)();
    using fn_TlsAlloc                 = DWORD    (WINAPI*)();
    using fn_TlsGetValue              = LPVOID   (WINAPI*)(DWORD);
    using fn_TlsSetValue              = BOOL     (WINAPI*)(DWORD, LPVOID);
    using fn_TlsFree                  = BOOL     (WINAPI*)(DWORD);
    using fn_FlsAlloc                 = DWORD    (WINAPI*)(PFLS_CALLBACK_FUNCTION);
    using fn_FlsGetValue              = LPVOID   (WINAPI*)(DWORD);
    using fn_FlsSetValue              = BOOL     (WINAPI*)(DWORD, LPVOID);
    using fn_FlsFree                  = BOOL     (WINAPI*)(DWORD);
    using fn_InitializeCriticalSectionAndSpinCount = BOOL (WINAPI*)(LPCRITICAL_SECTION, DWORD);
    using fn_InitializeCriticalSectionEx           = BOOL (WINAPI*)(LPCRITICAL_SECTION, DWORD, DWORD);
    using fn_EnterCriticalSection     = void     (WINAPI*)(LPCRITICAL_SECTION);
    using fn_LeaveCriticalSection     = void     (WINAPI*)(LPCRITICAL_SECTION);
    using fn_DeleteCriticalSection    = void     (WINAPI*)(LPCRITICAL_SECTION);
    using fn_InitializeSListHead      = void     (NTAPI* )(PSLIST_HEADER);
    using fn_SleepConditionVariableSRW = BOOL    (WINAPI*)(PCONDITION_VARIABLE, PSRWLOCK, DWORD, ULONG);
    using fn_WakeAllConditionVariable  = void    (WINAPI*)(PCONDITION_VARIABLE);
    using fn_AcquireSRWLockExclusive   = void    (WINAPI*)(PSRWLOCK);
    using fn_ReleaseSRWLockExclusive   = void    (WINAPI*)(PSRWLOCK);

    // ── error / exception / process ──────────────────────────────────────────
    using fn_GetLastError             = DWORD    (WINAPI*)();
    using fn_SetLastError             = void     (WINAPI*)(DWORD);
    using fn_FormatMessageW           = DWORD    (WINAPI*)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
    using fn_FormatMessageA           = DWORD    (WINAPI*)(DWORD, LPCVOID, DWORD, DWORD, LPSTR,  DWORD, va_list*);
    using fn_RaiseException           = void     (WINAPI*)(DWORD, DWORD, DWORD, const ULONG_PTR*);
    using fn_UnhandledExceptionFilter = LONG     (WINAPI*)(LPEXCEPTION_POINTERS);
    using fn_SetUnhandledExceptionFilter = LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
    using fn_RtlPcToFileHeader        = PVOID    (NTAPI* )(PVOID, PVOID*);
    using fn_RtlUnwindEx              = void     (NTAPI* )(PVOID, PVOID, PEXCEPTION_RECORD, PVOID, PCONTEXT, PUNWIND_HISTORY_TABLE);
    using fn_RtlCaptureContext        = void     (NTAPI* )(PCONTEXT);
    using fn_RtlLookupFunctionEntry   = PRUNTIME_FUNCTION (NTAPI*)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
    using fn_RtlVirtualUnwind         = PEXCEPTION_ROUTINE (NTAPI*)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION, PCONTEXT, PVOID*, PDWORD64, PKNONVOLATILE_CONTEXT_POINTERS);
    using fn_ExitProcess              = void     (WINAPI*)(UINT);
    using fn_TerminateProcess         = BOOL     (WINAPI*)(HANDLE, UINT);
    using fn_IsProcessorFeaturePresent = BOOL    (WINAPI*)(DWORD);

    // ── time ─────────────────────────────────────────────────────────────────
    using fn_GetLocalTime             = void     (WINAPI*)(LPSYSTEMTIME);
    using fn_GetSystemTimeAsFileTime  = void     (WINAPI*)(LPFILETIME);
    using fn_QueryPerformanceCounter  = BOOL     (WINAPI*)(LARGE_INTEGER*);
    using fn_QueryPerformanceFrequency = BOOL    (WINAPI*)(LARGE_INTEGER*);

    // ── system info ──────────────────────────────────────────────────────────
    using fn_GetSystemDirectoryW      = UINT     (WINAPI*)(LPWSTR, UINT);
    using fn_GetWindowsDirectoryW     = UINT     (WINAPI*)(LPWSTR, UINT);
    using fn_GetStartupInfoW          = void     (WINAPI*)(LPSTARTUPINFOW);
    using fn_VerSetConditionMask      = ULONGLONG (NTAPI*)(ULONGLONG, DWORD, BYTE);
    using fn_EncodePointer            = PVOID    (WINAPI*)(PVOID);
    using fn_DecodePointer            = PVOID    (WINAPI*)(PVOID);

    // ── console / std handles ─────────────────────────────────────────────────
    using fn_GetStdHandle             = HANDLE   (WINAPI*)(DWORD);
    using fn_SetStdHandle             = BOOL     (WINAPI*)(DWORD, HANDLE);
    using fn_WriteConsoleW            = BOOL     (WINAPI*)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);
    using fn_ReadConsoleW             = BOOL     (WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, PCONSOLE_READCONSOLE_CONTROL);
    using fn_GetConsoleMode           = BOOL     (WINAPI*)(HANDLE, LPDWORD);
    using fn_GetConsoleOutputCP       = UINT     (WINAPI*)();

    struct api_t {
        // existing
        fn_CreateFileW              CreateFileW              = nullptr;
        fn_CreateFileMappingW       CreateFileMappingW       = nullptr;
        fn_MapViewOfFile            MapViewOfFile            = nullptr;
        fn_UnmapViewOfFile          UnmapViewOfFile          = nullptr;
        fn_DeviceIoControl          DeviceIoControl          = nullptr;
        fn_GetCurrentProcess        GetCurrentProcess        = nullptr;
        fn_GetCurrentProcessId      GetCurrentProcessId      = nullptr;
        fn_IsDebuggerPresent        IsDebuggerPresent        = nullptr;
        fn_CreateProcessW           CreateProcessW           = nullptr;
        fn_EnumDeviceDrivers        EnumDeviceDrivers        = nullptr;
        fn_GetDeviceDriverFileNameW GetDeviceDriverFileNameW = nullptr;
        // string / encoding
        fn_MultiByteToWideChar      MultiByteToWideChar      = nullptr;
        fn_WideCharToMultiByte      WideCharToMultiByte      = nullptr;
        fn_GetLocaleInfoA           GetLocaleInfoA           = nullptr;
        fn_GetLocaleInfoW           GetLocaleInfoW           = nullptr;
        fn_GetLocaleInfoEx          GetLocaleInfoEx          = nullptr;
        fn_LCMapStringW             LCMapStringW             = nullptr;
        fn_GetStringTypeW           GetStringTypeW           = nullptr;
        fn_GetCPInfo                GetCPInfo                = nullptr;
        fn_GetACP                   GetACP                   = nullptr;
        fn_GetOEMCP                 GetOEMCP                 = nullptr;
        fn_IsValidCodePage          IsValidCodePage          = nullptr;
        fn_IsValidLocale            IsValidLocale            = nullptr;
        fn_GetUserDefaultLCID       GetUserDefaultLCID       = nullptr;
        fn_EnumSystemLocalesW       EnumSystemLocalesW       = nullptr;
        // environment / command line
        fn_GetEnvironmentVariableW  GetEnvironmentVariableW  = nullptr;
        fn_GetEnvironmentStringsW   GetEnvironmentStringsW   = nullptr;
        fn_FreeEnvironmentStringsW  FreeEnvironmentStringsW  = nullptr;
        fn_GetCommandLineW          GetCommandLineW          = nullptr;
        fn_GetCommandLineA          GetCommandLineA          = nullptr;
        // file / path
        fn_GetTempPathW             GetTempPathW             = nullptr;
        fn_GetFileAttributesW       GetFileAttributesW       = nullptr;
        fn_GetFileAttributesExW     GetFileAttributesExW     = nullptr;
        fn_SetFileAttributesW       SetFileAttributesW       = nullptr;
        fn_DeleteFileW              DeleteFileW              = nullptr;
        fn_CloseHandle              CloseHandle              = nullptr;
        fn_WriteFile                WriteFile                = nullptr;
        fn_ReadFile                 ReadFile                 = nullptr;
        fn_SetFilePointerEx         SetFilePointerEx         = nullptr;
        fn_SetEndOfFile             SetEndOfFile             = nullptr;
        fn_GetFileSizeEx            GetFileSizeEx            = nullptr;
        fn_GetFileType              GetFileType              = nullptr;
        fn_FlushFileBuffers         FlushFileBuffers         = nullptr;
        fn_GetFileInformationByHandleEx GetFileInformationByHandleEx = nullptr;
        fn_AreFileApisANSI          AreFileApisANSI          = nullptr;
        fn_CreateDirectoryW         CreateDirectoryW         = nullptr;
        fn_GetFullPathNameW         GetFullPathNameW         = nullptr;
        fn_GetModuleFileNameW       GetModuleFileNameW       = nullptr;
        // find files
        fn_FindFirstFileW           FindFirstFileW           = nullptr;
        fn_FindFirstFileExW         FindFirstFileExW         = nullptr;
        fn_FindNextFileW            FindNextFileW            = nullptr;
        fn_FindClose                FindClose                = nullptr;
        // module / library
        fn_GetModuleHandleA         GetModuleHandleA         = nullptr;
        fn_GetModuleHandleW         GetModuleHandleW         = nullptr;
        fn_GetModuleHandleExW       GetModuleHandleExW       = nullptr;
        fn_LoadLibraryA             LoadLibraryA             = nullptr;
        fn_LoadLibraryW             LoadLibraryW             = nullptr;
        fn_LoadLibraryExW           LoadLibraryExW           = nullptr;
        fn_FreeLibrary              FreeLibrary              = nullptr;
        fn_GetProcAddress           GetProcAddress           = nullptr;
        // resources
        fn_FindResourceW            FindResourceW            = nullptr;
        fn_LoadResource             LoadResource             = nullptr;
        fn_LockResource             LockResource             = nullptr;
        fn_SizeofResource           SizeofResource           = nullptr;
        // memory
        fn_LocalFree                LocalFree                = nullptr;
        fn_GlobalAlloc              GlobalAlloc              = nullptr;
        fn_GlobalFree               GlobalFree               = nullptr;
        fn_GlobalLock               GlobalLock               = nullptr;
        fn_GlobalUnlock             GlobalUnlock             = nullptr;
        fn_GetProcessHeap           GetProcessHeap           = nullptr;
        fn_HeapAlloc                HeapAlloc                = nullptr;
        fn_HeapReAlloc              HeapReAlloc              = nullptr;
        fn_HeapFree                 HeapFree                 = nullptr;
        fn_HeapSize                 HeapSize                 = nullptr;
        fn_VirtualProtect           VirtualProtect           = nullptr;
        // sync / threading
        fn_Sleep                    Sleep                    = nullptr;
        fn_CreateThread             CreateThread             = nullptr;
        fn_GetCurrentThreadId       GetCurrentThreadId       = nullptr;
        fn_TlsAlloc                 TlsAlloc                 = nullptr;
        fn_TlsGetValue              TlsGetValue              = nullptr;
        fn_TlsSetValue              TlsSetValue              = nullptr;
        fn_TlsFree                  TlsFree                  = nullptr;
        fn_FlsAlloc                 FlsAlloc                 = nullptr;
        fn_FlsGetValue              FlsGetValue              = nullptr;
        fn_FlsSetValue              FlsSetValue              = nullptr;
        fn_FlsFree                  FlsFree                  = nullptr;
        fn_InitializeCriticalSectionAndSpinCount InitializeCriticalSectionAndSpinCount = nullptr;
        fn_InitializeCriticalSectionEx           InitializeCriticalSectionEx           = nullptr;
        fn_EnterCriticalSection     EnterCriticalSection     = nullptr;
        fn_LeaveCriticalSection     LeaveCriticalSection     = nullptr;
        fn_DeleteCriticalSection    DeleteCriticalSection    = nullptr;
        fn_InitializeSListHead      InitializeSListHead      = nullptr;
        fn_SleepConditionVariableSRW SleepConditionVariableSRW = nullptr;
        fn_WakeAllConditionVariable  WakeAllConditionVariable  = nullptr;
        fn_AcquireSRWLockExclusive   AcquireSRWLockExclusive   = nullptr;
        fn_ReleaseSRWLockExclusive   ReleaseSRWLockExclusive   = nullptr;
        // error / exception / process
        fn_GetLastError             GetLastError             = nullptr;
        fn_SetLastError             SetLastError             = nullptr;
        fn_FormatMessageW           FormatMessageW           = nullptr;
        fn_FormatMessageA           FormatMessageA           = nullptr;
        fn_RaiseException           RaiseException           = nullptr;
        fn_UnhandledExceptionFilter UnhandledExceptionFilter = nullptr;
        fn_SetUnhandledExceptionFilter SetUnhandledExceptionFilter = nullptr;
        fn_RtlPcToFileHeader        RtlPcToFileHeader        = nullptr;
        fn_RtlUnwindEx              RtlUnwindEx              = nullptr;
        fn_RtlCaptureContext        RtlCaptureContext        = nullptr;
        fn_RtlLookupFunctionEntry   RtlLookupFunctionEntry   = nullptr;
        fn_RtlVirtualUnwind         RtlVirtualUnwind         = nullptr;
        fn_ExitProcess              ExitProcess              = nullptr;
        fn_TerminateProcess         TerminateProcess         = nullptr;
        fn_IsProcessorFeaturePresent IsProcessorFeaturePresent = nullptr;
        // time
        fn_GetLocalTime             GetLocalTime             = nullptr;
        fn_GetSystemTimeAsFileTime  GetSystemTimeAsFileTime  = nullptr;
        fn_QueryPerformanceCounter  QueryPerformanceCounter  = nullptr;
        fn_QueryPerformanceFrequency QueryPerformanceFrequency = nullptr;
        // system info
        fn_GetSystemDirectoryW      GetSystemDirectoryW      = nullptr;
        fn_GetWindowsDirectoryW     GetWindowsDirectoryW     = nullptr;
        fn_GetStartupInfoW          GetStartupInfoW          = nullptr;
        fn_VerSetConditionMask      VerSetConditionMask      = nullptr;
        fn_EncodePointer            EncodePointer            = nullptr;
        fn_DecodePointer            DecodePointer            = nullptr;
        // console / std handles
        fn_GetStdHandle             GetStdHandle             = nullptr;
        fn_SetStdHandle             SetStdHandle             = nullptr;
        fn_WriteConsoleW            WriteConsoleW            = nullptr;
        fn_ReadConsoleW             ReadConsoleW             = nullptr;
        fn_GetConsoleMode           GetConsoleMode           = nullptr;
        fn_GetConsoleOutputCP       GetConsoleOutputCP       = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::GetModuleHandleW( WOBF( L"kernel32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        // existing
        s.CreateFileW              = reinterpret_cast<fn_CreateFileW>             ( R( OBF( "CreateFileW"                 ) ) );
        s.CreateFileMappingW       = reinterpret_cast<fn_CreateFileMappingW>      ( R( OBF( "CreateFileMappingW"          ) ) );
        s.MapViewOfFile            = reinterpret_cast<fn_MapViewOfFile>           ( R( OBF( "MapViewOfFile"               ) ) );
        s.UnmapViewOfFile          = reinterpret_cast<fn_UnmapViewOfFile>         ( R( OBF( "UnmapViewOfFile"             ) ) );
        s.DeviceIoControl          = reinterpret_cast<fn_DeviceIoControl>         ( R( OBF( "DeviceIoControl"             ) ) );
        s.GetCurrentProcess        = reinterpret_cast<fn_GetCurrentProcess>       ( R( OBF( "GetCurrentProcess"           ) ) );
        s.GetCurrentProcessId      = reinterpret_cast<fn_GetCurrentProcessId>     ( R( OBF( "GetCurrentProcessId"         ) ) );
        s.IsDebuggerPresent        = reinterpret_cast<fn_IsDebuggerPresent>       ( R( OBF( "IsDebuggerPresent"           ) ) );
        s.CreateProcessW           = reinterpret_cast<fn_CreateProcessW>          ( R( OBF( "CreateProcessW"              ) ) );
        s.EnumDeviceDrivers        = reinterpret_cast<fn_EnumDeviceDrivers>       ( R( OBF( "K32EnumDeviceDrivers"        ) ) );
        s.GetDeviceDriverFileNameW = reinterpret_cast<fn_GetDeviceDriverFileNameW>( R( OBF( "K32GetDeviceDriverFileNameW" ) ) );
        // string / encoding
        s.MultiByteToWideChar      = reinterpret_cast<fn_MultiByteToWideChar>     ( R( OBF( "MultiByteToWideChar"         ) ) );
        s.WideCharToMultiByte      = reinterpret_cast<fn_WideCharToMultiByte>     ( R( OBF( "WideCharToMultiByte"         ) ) );
        s.GetLocaleInfoA           = reinterpret_cast<fn_GetLocaleInfoA>          ( R( OBF( "GetLocaleInfoA"              ) ) );
        s.GetLocaleInfoW           = reinterpret_cast<fn_GetLocaleInfoW>          ( R( OBF( "GetLocaleInfoW"              ) ) );
        s.GetLocaleInfoEx          = reinterpret_cast<fn_GetLocaleInfoEx>         ( R( OBF( "GetLocaleInfoEx"             ) ) );
        s.LCMapStringW             = reinterpret_cast<fn_LCMapStringW>            ( R( OBF( "LCMapStringW"                ) ) );
        s.GetStringTypeW           = reinterpret_cast<fn_GetStringTypeW>          ( R( OBF( "GetStringTypeW"              ) ) );
        s.GetCPInfo                = reinterpret_cast<fn_GetCPInfo>               ( R( OBF( "GetCPInfo"                   ) ) );
        s.GetACP                   = reinterpret_cast<fn_GetACP>                  ( R( OBF( "GetACP"                      ) ) );
        s.GetOEMCP                 = reinterpret_cast<fn_GetOEMCP>                ( R( OBF( "GetOEMCP"                    ) ) );
        s.IsValidCodePage          = reinterpret_cast<fn_IsValidCodePage>         ( R( OBF( "IsValidCodePage"             ) ) );
        s.IsValidLocale            = reinterpret_cast<fn_IsValidLocale>           ( R( OBF( "IsValidLocale"               ) ) );
        s.GetUserDefaultLCID       = reinterpret_cast<fn_GetUserDefaultLCID>      ( R( OBF( "GetUserDefaultLCID"          ) ) );
        s.EnumSystemLocalesW       = reinterpret_cast<fn_EnumSystemLocalesW>      ( R( OBF( "EnumSystemLocalesW"          ) ) );
        // environment / command line
        s.GetEnvironmentVariableW  = reinterpret_cast<fn_GetEnvironmentVariableW> ( R( OBF( "GetEnvironmentVariableW"     ) ) );
        s.GetEnvironmentStringsW   = reinterpret_cast<fn_GetEnvironmentStringsW>  ( R( OBF( "GetEnvironmentStringsW"      ) ) );
        s.FreeEnvironmentStringsW  = reinterpret_cast<fn_FreeEnvironmentStringsW> ( R( OBF( "FreeEnvironmentStringsW"     ) ) );
        s.GetCommandLineW          = reinterpret_cast<fn_GetCommandLineW>         ( R( OBF( "GetCommandLineW"             ) ) );
        s.GetCommandLineA          = reinterpret_cast<fn_GetCommandLineA>         ( R( OBF( "GetCommandLineA"             ) ) );
        // file / path
        s.GetTempPathW             = reinterpret_cast<fn_GetTempPathW>            ( R( OBF( "GetTempPathW"                ) ) );
        s.GetFileAttributesW       = reinterpret_cast<fn_GetFileAttributesW>      ( R( OBF( "GetFileAttributesW"          ) ) );
        s.GetFileAttributesExW     = reinterpret_cast<fn_GetFileAttributesExW>    ( R( OBF( "GetFileAttributesExW"        ) ) );
        s.SetFileAttributesW       = reinterpret_cast<fn_SetFileAttributesW>      ( R( OBF( "SetFileAttributesW"          ) ) );
        s.DeleteFileW              = reinterpret_cast<fn_DeleteFileW>             ( R( OBF( "DeleteFileW"                 ) ) );
        s.CloseHandle              = reinterpret_cast<fn_CloseHandle>             ( R( OBF( "CloseHandle"                 ) ) );
        s.WriteFile                = reinterpret_cast<fn_WriteFile>               ( R( OBF( "WriteFile"                   ) ) );
        s.ReadFile                 = reinterpret_cast<fn_ReadFile>                ( R( OBF( "ReadFile"                    ) ) );
        s.SetFilePointerEx         = reinterpret_cast<fn_SetFilePointerEx>        ( R( OBF( "SetFilePointerEx"            ) ) );
        s.SetEndOfFile             = reinterpret_cast<fn_SetEndOfFile>            ( R( OBF( "SetEndOfFile"                ) ) );
        s.GetFileSizeEx            = reinterpret_cast<fn_GetFileSizeEx>           ( R( OBF( "GetFileSizeEx"               ) ) );
        s.GetFileType              = reinterpret_cast<fn_GetFileType>             ( R( OBF( "GetFileType"                 ) ) );
        s.FlushFileBuffers         = reinterpret_cast<fn_FlushFileBuffers>        ( R( OBF( "FlushFileBuffers"            ) ) );
        s.GetFileInformationByHandleEx = reinterpret_cast<fn_GetFileInformationByHandleEx>( R( OBF( "GetFileInformationByHandleEx" ) ) );
        s.AreFileApisANSI          = reinterpret_cast<fn_AreFileApisANSI>         ( R( OBF( "AreFileApisANSI"             ) ) );
        s.CreateDirectoryW         = reinterpret_cast<fn_CreateDirectoryW>        ( R( OBF( "CreateDirectoryW"            ) ) );
        s.GetFullPathNameW         = reinterpret_cast<fn_GetFullPathNameW>        ( R( OBF( "GetFullPathNameW"            ) ) );
        s.GetModuleFileNameW       = reinterpret_cast<fn_GetModuleFileNameW>      ( R( OBF( "GetModuleFileNameW"          ) ) );
        // find files
        s.FindFirstFileW           = reinterpret_cast<fn_FindFirstFileW>          ( R( OBF( "FindFirstFileW"              ) ) );
        s.FindFirstFileExW         = reinterpret_cast<fn_FindFirstFileExW>        ( R( OBF( "FindFirstFileExW"            ) ) );
        s.FindNextFileW            = reinterpret_cast<fn_FindNextFileW>           ( R( OBF( "FindNextFileW"               ) ) );
        s.FindClose                = reinterpret_cast<fn_FindClose>               ( R( OBF( "FindClose"                   ) ) );
        // module / library
        s.GetModuleHandleA         = reinterpret_cast<fn_GetModuleHandleA>        ( R( OBF( "GetModuleHandleA"            ) ) );
        s.GetModuleHandleW         = reinterpret_cast<fn_GetModuleHandleW>        ( R( OBF( "GetModuleHandleW"            ) ) );
        s.GetModuleHandleExW       = reinterpret_cast<fn_GetModuleHandleExW>      ( R( OBF( "GetModuleHandleExW"          ) ) );
        s.LoadLibraryA             = reinterpret_cast<fn_LoadLibraryA>            ( R( OBF( "LoadLibraryA"                ) ) );
        s.LoadLibraryW             = reinterpret_cast<fn_LoadLibraryW>            ( R( OBF( "LoadLibraryW"                ) ) );
        s.LoadLibraryExW           = reinterpret_cast<fn_LoadLibraryExW>          ( R( OBF( "LoadLibraryExW"              ) ) );
        s.FreeLibrary              = reinterpret_cast<fn_FreeLibrary>             ( R( OBF( "FreeLibrary"                 ) ) );
        s.GetProcAddress           = reinterpret_cast<fn_GetProcAddress>          ( R( OBF( "GetProcAddress"              ) ) );
        // resources
        s.FindResourceW            = reinterpret_cast<fn_FindResourceW>           ( R( OBF( "FindResourceW"               ) ) );
        s.LoadResource             = reinterpret_cast<fn_LoadResource>            ( R( OBF( "LoadResource"                ) ) );
        s.LockResource             = reinterpret_cast<fn_LockResource>            ( R( OBF( "LockResource"                ) ) );
        s.SizeofResource           = reinterpret_cast<fn_SizeofResource>          ( R( OBF( "SizeofResource"              ) ) );
        // memory
        s.LocalFree                = reinterpret_cast<fn_LocalFree>               ( R( OBF( "LocalFree"                   ) ) );
        s.GlobalAlloc              = reinterpret_cast<fn_GlobalAlloc>             ( R( OBF( "GlobalAlloc"                 ) ) );
        s.GlobalFree               = reinterpret_cast<fn_GlobalFree>              ( R( OBF( "GlobalFree"                  ) ) );
        s.GlobalLock               = reinterpret_cast<fn_GlobalLock>              ( R( OBF( "GlobalLock"                  ) ) );
        s.GlobalUnlock             = reinterpret_cast<fn_GlobalUnlock>            ( R( OBF( "GlobalUnlock"                ) ) );
        s.GetProcessHeap           = reinterpret_cast<fn_GetProcessHeap>          ( R( OBF( "GetProcessHeap"              ) ) );
        s.HeapAlloc                = reinterpret_cast<fn_HeapAlloc>               ( R( OBF( "HeapAlloc"                   ) ) );
        s.HeapReAlloc              = reinterpret_cast<fn_HeapReAlloc>             ( R( OBF( "HeapReAlloc"                 ) ) );
        s.HeapFree                 = reinterpret_cast<fn_HeapFree>                ( R( OBF( "HeapFree"                    ) ) );
        s.HeapSize                 = reinterpret_cast<fn_HeapSize>                ( R( OBF( "HeapSize"                    ) ) );
        s.VirtualProtect           = reinterpret_cast<fn_VirtualProtect>          ( R( OBF( "VirtualProtect"              ) ) );
        // sync / threading
        s.Sleep                    = reinterpret_cast<fn_Sleep>                   ( R( OBF( "Sleep"                       ) ) );
        s.CreateThread             = reinterpret_cast<fn_CreateThread>            ( R( OBF( "CreateThread"                ) ) );
        s.GetCurrentThreadId       = reinterpret_cast<fn_GetCurrentThreadId>      ( R( OBF( "GetCurrentThreadId"          ) ) );
        s.TlsAlloc                 = reinterpret_cast<fn_TlsAlloc>                ( R( OBF( "TlsAlloc"                    ) ) );
        s.TlsGetValue              = reinterpret_cast<fn_TlsGetValue>             ( R( OBF( "TlsGetValue"                 ) ) );
        s.TlsSetValue              = reinterpret_cast<fn_TlsSetValue>             ( R( OBF( "TlsSetValue"                 ) ) );
        s.TlsFree                  = reinterpret_cast<fn_TlsFree>                 ( R( OBF( "TlsFree"                     ) ) );
        s.FlsAlloc                 = reinterpret_cast<fn_FlsAlloc>                ( R( OBF( "FlsAlloc"                    ) ) );
        s.FlsGetValue              = reinterpret_cast<fn_FlsGetValue>             ( R( OBF( "FlsGetValue"                 ) ) );
        s.FlsSetValue              = reinterpret_cast<fn_FlsSetValue>             ( R( OBF( "FlsSetValue"                 ) ) );
        s.FlsFree                  = reinterpret_cast<fn_FlsFree>                 ( R( OBF( "FlsFree"                     ) ) );
        s.InitializeCriticalSectionAndSpinCount = reinterpret_cast<fn_InitializeCriticalSectionAndSpinCount>( R( OBF( "InitializeCriticalSectionAndSpinCount" ) ) );
        s.InitializeCriticalSectionEx           = reinterpret_cast<fn_InitializeCriticalSectionEx>          ( R( OBF( "InitializeCriticalSectionEx"           ) ) );
        s.EnterCriticalSection     = reinterpret_cast<fn_EnterCriticalSection>    ( R( OBF( "EnterCriticalSection"        ) ) );
        s.LeaveCriticalSection     = reinterpret_cast<fn_LeaveCriticalSection>    ( R( OBF( "LeaveCriticalSection"        ) ) );
        s.DeleteCriticalSection    = reinterpret_cast<fn_DeleteCriticalSection>   ( R( OBF( "DeleteCriticalSection"       ) ) );
        s.InitializeSListHead      = reinterpret_cast<fn_InitializeSListHead>     ( R( OBF( "InitializeSListHead"         ) ) );
        s.SleepConditionVariableSRW = reinterpret_cast<fn_SleepConditionVariableSRW>( R( OBF( "SleepConditionVariableSRW" ) ) );
        s.WakeAllConditionVariable  = reinterpret_cast<fn_WakeAllConditionVariable> ( R( OBF( "WakeAllConditionVariable"  ) ) );
        s.AcquireSRWLockExclusive   = reinterpret_cast<fn_AcquireSRWLockExclusive>  ( R( OBF( "AcquireSRWLockExclusive"  ) ) );
        s.ReleaseSRWLockExclusive   = reinterpret_cast<fn_ReleaseSRWLockExclusive>  ( R( OBF( "ReleaseSRWLockExclusive"  ) ) );
        // error / exception / process
        s.GetLastError             = reinterpret_cast<fn_GetLastError>            ( R( OBF( "GetLastError"                ) ) );
        s.SetLastError             = reinterpret_cast<fn_SetLastError>            ( R( OBF( "SetLastError"                ) ) );
        s.FormatMessageW           = reinterpret_cast<fn_FormatMessageW>          ( R( OBF( "FormatMessageW"              ) ) );
        s.FormatMessageA           = reinterpret_cast<fn_FormatMessageA>          ( R( OBF( "FormatMessageA"              ) ) );
        s.RaiseException           = reinterpret_cast<fn_RaiseException>          ( R( OBF( "RaiseException"              ) ) );
        s.UnhandledExceptionFilter = reinterpret_cast<fn_UnhandledExceptionFilter>( R( OBF( "UnhandledExceptionFilter"    ) ) );
        s.SetUnhandledExceptionFilter = reinterpret_cast<fn_SetUnhandledExceptionFilter>( R( OBF( "SetUnhandledExceptionFilter" ) ) );
        s.RtlPcToFileHeader        = reinterpret_cast<fn_RtlPcToFileHeader>       ( R( OBF( "RtlPcToFileHeader"           ) ) );
        s.RtlUnwindEx              = reinterpret_cast<fn_RtlUnwindEx>             ( R( OBF( "RtlUnwindEx"                 ) ) );
        s.RtlCaptureContext        = reinterpret_cast<fn_RtlCaptureContext>        ( R( OBF( "RtlCaptureContext"           ) ) );
        s.RtlLookupFunctionEntry   = reinterpret_cast<fn_RtlLookupFunctionEntry>  ( R( OBF( "RtlLookupFunctionEntry"      ) ) );
        s.RtlVirtualUnwind         = reinterpret_cast<fn_RtlVirtualUnwind>        ( R( OBF( "RtlVirtualUnwind"            ) ) );
        s.ExitProcess              = reinterpret_cast<fn_ExitProcess>             ( R( OBF( "ExitProcess"                 ) ) );
        s.TerminateProcess         = reinterpret_cast<fn_TerminateProcess>        ( R( OBF( "TerminateProcess"            ) ) );
        s.IsProcessorFeaturePresent = reinterpret_cast<fn_IsProcessorFeaturePresent>( R( OBF( "IsProcessorFeaturePresent" ) ) );
        // time
        s.GetLocalTime             = reinterpret_cast<fn_GetLocalTime>            ( R( OBF( "GetLocalTime"                ) ) );
        s.GetSystemTimeAsFileTime  = reinterpret_cast<fn_GetSystemTimeAsFileTime> ( R( OBF( "GetSystemTimeAsFileTime"     ) ) );
        s.QueryPerformanceCounter  = reinterpret_cast<fn_QueryPerformanceCounter> ( R( OBF( "QueryPerformanceCounter"     ) ) );
        s.QueryPerformanceFrequency = reinterpret_cast<fn_QueryPerformanceFrequency>( R( OBF( "QueryPerformanceFrequency" ) ) );
        // system info
        s.GetSystemDirectoryW      = reinterpret_cast<fn_GetSystemDirectoryW>     ( R( OBF( "GetSystemDirectoryW"         ) ) );
        s.GetWindowsDirectoryW     = reinterpret_cast<fn_GetWindowsDirectoryW>    ( R( OBF( "GetWindowsDirectoryW"        ) ) );
        s.GetStartupInfoW          = reinterpret_cast<fn_GetStartupInfoW>         ( R( OBF( "GetStartupInfoW"             ) ) );
        s.VerSetConditionMask      = reinterpret_cast<fn_VerSetConditionMask>     ( R( OBF( "VerSetConditionMask"         ) ) );
        s.EncodePointer            = reinterpret_cast<fn_EncodePointer>           ( R( OBF( "EncodePointer"               ) ) );
        s.DecodePointer            = reinterpret_cast<fn_DecodePointer>           ( R( OBF( "DecodePointer"               ) ) );
        // console / std handles
        s.GetStdHandle             = reinterpret_cast<fn_GetStdHandle>            ( R( OBF( "GetStdHandle"                ) ) );
        s.SetStdHandle             = reinterpret_cast<fn_SetStdHandle>            ( R( OBF( "SetStdHandle"                ) ) );
        s.WriteConsoleW            = reinterpret_cast<fn_WriteConsoleW>           ( R( OBF( "WriteConsoleW"               ) ) );
        s.ReadConsoleW             = reinterpret_cast<fn_ReadConsoleW>            ( R( OBF( "ReadConsoleW"                ) ) );
        s.GetConsoleMode           = reinterpret_cast<fn_GetConsoleMode>          ( R( OBF( "GetConsoleMode"              ) ) );
        s.GetConsoleOutputCP       = reinterpret_cast<fn_GetConsoleOutputCP>      ( R( OBF( "GetConsoleOutputCP"          ) ) );
        s.loaded = true;
        return s;
    }

} // namespace k32

//─────────────────────────────── dbghelp ──────────────────────────────────────
// Loaded on demand via LoadLibraryW – may not be present on minimal systems.
namespace dbghelp_ {

    using fn_SymInitializeW    = BOOL    (WINAPI*)(HANDLE, PCWSTR, BOOL);
    using fn_SymLoadModuleExW  = DWORD64 (WINAPI*)(HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD);
    using fn_SymFromNameW      = BOOL    (WINAPI*)(HANDLE, PCWSTR, PSYMBOL_INFOW);
    using fn_SymUnloadModule64 = BOOL    (WINAPI*)(HANDLE, DWORD64);
    using fn_SymCleanup        = BOOL    (WINAPI*)(HANDLE);
    using fn_SymGetOptions     = DWORD   (WINAPI*)();
    using fn_SymSetOptions     = DWORD   (WINAPI*)(DWORD);

    struct api_t {
        fn_SymInitializeW    SymInitializeW    = nullptr;
        fn_SymLoadModuleExW  SymLoadModuleExW  = nullptr;
        fn_SymFromNameW      SymFromNameW      = nullptr;
        fn_SymUnloadModule64 SymUnloadModule64 = nullptr;
        fn_SymCleanup        SymCleanup        = nullptr;
        fn_SymGetOptions     SymGetOptions     = nullptr;
        fn_SymSetOptions     SymSetOptions     = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"dbghelp.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.SymInitializeW    = reinterpret_cast<fn_SymInitializeW>   ( R( OBF( "SymInitializeW"    ) ) );
        s.SymLoadModuleExW  = reinterpret_cast<fn_SymLoadModuleExW> ( R( OBF( "SymLoadModuleExW"  ) ) );
        s.SymFromNameW      = reinterpret_cast<fn_SymFromNameW>     ( R( OBF( "SymFromNameW"      ) ) );
        s.SymUnloadModule64 = reinterpret_cast<fn_SymUnloadModule64>( R( OBF( "SymUnloadModule64" ) ) );
        s.SymCleanup        = reinterpret_cast<fn_SymCleanup>       ( R( OBF( "SymCleanup"        ) ) );
        s.SymGetOptions     = reinterpret_cast<fn_SymGetOptions>    ( R( OBF( "SymGetOptions"     ) ) );
        s.SymSetOptions     = reinterpret_cast<fn_SymSetOptions>    ( R( OBF( "SymSetOptions"     ) ) );
        s.loaded = true;
        return s;
    }

} // namespace dbghelp_

//─────────────────────────────── winhttp ──────────────────────────────────────
// Loaded on demand via LoadLibraryW.
namespace winhttp_ {

    using fn_WinHttpCrackUrl         = BOOL      (WINAPI*)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
    using fn_WinHttpOpen             = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    using fn_WinHttpSetTimeouts      = BOOL      (WINAPI*)(HINTERNET, int, int, int, int);
    using fn_WinHttpConnect          = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using fn_WinHttpOpenRequest      = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using fn_WinHttpSendRequest      = BOOL      (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using fn_WinHttpReceiveResponse  = BOOL      (WINAPI*)(HINTERNET, LPVOID);
    using fn_WinHttpQueryHeaders     = BOOL      (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    using fn_WinHttpReadData         = BOOL      (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using fn_WinHttpCloseHandle      = BOOL      (WINAPI*)(HINTERNET);

    struct api_t {
        fn_WinHttpCrackUrl        WinHttpCrackUrl        = nullptr;
        fn_WinHttpOpen            WinHttpOpen            = nullptr;
        fn_WinHttpSetTimeouts     WinHttpSetTimeouts     = nullptr;
        fn_WinHttpConnect         WinHttpConnect         = nullptr;
        fn_WinHttpOpenRequest     WinHttpOpenRequest     = nullptr;
        fn_WinHttpSendRequest     WinHttpSendRequest     = nullptr;
        fn_WinHttpReceiveResponse WinHttpReceiveResponse = nullptr;
        fn_WinHttpQueryHeaders    WinHttpQueryHeaders    = nullptr;
        fn_WinHttpReadData        WinHttpReadData        = nullptr;
        fn_WinHttpCloseHandle     WinHttpCloseHandle     = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"winhttp.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.WinHttpCrackUrl        = reinterpret_cast<fn_WinHttpCrackUrl>       ( R( OBF( "WinHttpCrackUrl"        ) ) );
        s.WinHttpOpen            = reinterpret_cast<fn_WinHttpOpen>           ( R( OBF( "WinHttpOpen"            ) ) );
        s.WinHttpSetTimeouts     = reinterpret_cast<fn_WinHttpSetTimeouts>    ( R( OBF( "WinHttpSetTimeouts"     ) ) );
        s.WinHttpConnect         = reinterpret_cast<fn_WinHttpConnect>        ( R( OBF( "WinHttpConnect"         ) ) );
        s.WinHttpOpenRequest     = reinterpret_cast<fn_WinHttpOpenRequest>    ( R( OBF( "WinHttpOpenRequest"     ) ) );
        s.WinHttpSendRequest     = reinterpret_cast<fn_WinHttpSendRequest>    ( R( OBF( "WinHttpSendRequest"     ) ) );
        s.WinHttpReceiveResponse = reinterpret_cast<fn_WinHttpReceiveResponse>( R( OBF( "WinHttpReceiveResponse" ) ) );
        s.WinHttpQueryHeaders    = reinterpret_cast<fn_WinHttpQueryHeaders>   ( R( OBF( "WinHttpQueryHeaders"    ) ) );
        s.WinHttpReadData        = reinterpret_cast<fn_WinHttpReadData>       ( R( OBF( "WinHttpReadData"        ) ) );
        s.WinHttpCloseHandle     = reinterpret_cast<fn_WinHttpCloseHandle>    ( R( OBF( "WinHttpCloseHandle"     ) ) );
        s.loaded = true;
        return s;
    }

} // namespace winhttp_

//─────────────────────── advapi32 (registry functions) ────────────────────────
// advapi32 is always loaded in user-mode – GetModuleHandleW is sufficient.
// NOTE: Service-control functions (OpenSCManagerW etc.) are handled separately
//       by kvc_session::InitDynamicAPIs() via its own g_p* pointer set.
namespace advapi32_ {

    using fn_RegCreateKeyExW  = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
                                                  LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    using fn_RegOpenKeyExW    = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    using fn_RegQueryValueExW = LSTATUS (WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using fn_RegSetValueExW   = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    using fn_RegCloseKey      = LSTATUS (WINAPI*)(HKEY);
    using fn_RegDeleteValueW  = LSTATUS (WINAPI*)(HKEY, LPCWSTR);

    struct api_t {
        fn_RegCreateKeyExW  RegCreateKeyExW  = nullptr;
        fn_RegOpenKeyExW    RegOpenKeyExW    = nullptr;
        fn_RegQueryValueExW RegQueryValueExW = nullptr;
        fn_RegSetValueExW   RegSetValueExW   = nullptr;
        fn_RegCloseKey      RegCloseKey      = nullptr;
        fn_RegDeleteValueW  RegDeleteValueW  = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::GetModuleHandleW( WOBF( L"advapi32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.RegCreateKeyExW  = reinterpret_cast<fn_RegCreateKeyExW> ( R( OBF( "RegCreateKeyExW"  ) ) );
        s.RegOpenKeyExW    = reinterpret_cast<fn_RegOpenKeyExW>   ( R( OBF( "RegOpenKeyExW"    ) ) );
        s.RegQueryValueExW = reinterpret_cast<fn_RegQueryValueExW>( R( OBF( "RegQueryValueExW" ) ) );
        s.RegSetValueExW   = reinterpret_cast<fn_RegSetValueExW>  ( R( OBF( "RegSetValueExW"   ) ) );
        s.RegCloseKey      = reinterpret_cast<fn_RegCloseKey>     ( R( OBF( "RegCloseKey"      ) ) );
        s.RegDeleteValueW  = reinterpret_cast<fn_RegDeleteValueW> ( R( OBF( "RegDeleteValueW"  ) ) );
        s.loaded = true;
        return s;
    }

} // namespace advapi32_

//─────────────────────────────── user32 ──────────────────────────────────────
// user32 is always loaded in user-mode – GetModuleHandleW is sufficient.
namespace user32_ {

    using fn_GetWindowLongW           = LONG      (WINAPI*)(HWND, int);
    using fn_SetWindowLongW           = LONG      (WINAPI*)(HWND, int, LONG);
    using fn_SetWindowLongPtrW        = LONG_PTR  (WINAPI*)(HWND, int, LONG_PTR);
    using fn_AdjustWindowRectEx       = BOOL      (WINAPI*)(LPRECT, DWORD, BOOL, DWORD);
    using fn_GetKeyState              = SHORT     (WINAPI*)(int);
    using fn_GetMessageExtraInfo      = LPARAM    (WINAPI*)();
    using fn_SetPropA                 = BOOL      (WINAPI*)(HWND, LPCSTR, HANDLE);
    using fn_GetPropA                 = HANDLE    (WINAPI*)(HWND, LPCSTR);
    using fn_GetDC                    = HDC       (WINAPI*)(HWND);
    using fn_ReleaseDC                = int       (WINAPI*)(HWND, HDC);
    using fn_MonitorFromWindow        = HMONITOR  (WINAPI*)(HWND, DWORD);
    using fn_EnumDisplayMonitors      = BOOL      (WINAPI*)(HDC, LPCRECT, MONITORENUMPROC, LPARAM);
    using fn_GetMonitorInfoW          = BOOL      (WINAPI*)(HMONITOR, LPMONITORINFO);
    using fn_ScreenToClient           = BOOL      (WINAPI*)(HWND, LPPOINT);
    using fn_ClientToScreen           = BOOL      (WINAPI*)(HWND, LPPOINT);
    using fn_WindowFromPoint          = HWND      (WINAPI*)(POINT);
    using fn_GetCapture               = HWND      (WINAPI*)();
    using fn_SetCapture               = HWND      (WINAPI*)(HWND);
    using fn_ReleaseCapture           = BOOL      (WINAPI*)();
    using fn_IsChild                  = BOOL      (WINAPI*)(HWND, HWND);
    using fn_TrackMouseEvent          = BOOL      (WINAPI*)(LPTRACKMOUSEEVENT);
    using fn_GetKeyboardLayout        = HKL       (WINAPI*)(DWORD);
    using fn_GetForegroundWindow      = HWND      (WINAPI*)();
    using fn_SetForegroundWindow      = BOOL      (WINAPI*)(HWND);
    using fn_SetLayeredWindowAttributes = BOOL    (WINAPI*)(HWND, COLORREF, BYTE, DWORD);
    using fn_SetFocus                 = HWND      (WINAPI*)(HWND);
    using fn_BringWindowToTop         = BOOL      (WINAPI*)(HWND);
    using fn_SetCursor                = HCURSOR   (WINAPI*)(HCURSOR);
    using fn_SetCursorPos             = BOOL      (WINAPI*)(int, int);
    using fn_GetCursorPos             = BOOL      (WINAPI*)(LPPOINT);
    using fn_GetClientRect            = BOOL      (WINAPI*)(HWND, LPRECT);
    using fn_GetWindowRect            = BOOL      (WINAPI*)(HWND, LPRECT);
    using fn_IsWindowUnicode          = BOOL      (WINAPI*)(HWND);
    using fn_IsIconic                 = BOOL      (WINAPI*)(HWND);
    using fn_OpenClipboard            = BOOL      (WINAPI*)(HWND);
    using fn_CloseClipboard           = BOOL      (WINAPI*)();
    using fn_EmptyClipboard           = BOOL      (WINAPI*)();
    using fn_GetClipboardData         = HANDLE    (WINAPI*)(UINT);
    using fn_SetClipboardData         = HANDLE    (WINAPI*)(UINT, HANDLE);
    using fn_DefWindowProcW           = LRESULT   (WINAPI*)(HWND, UINT, WPARAM, LPARAM);
    using fn_DestroyWindow            = BOOL      (WINAPI*)(HWND);
    using fn_SetWindowPos             = BOOL      (WINAPI*)(HWND, HWND, int, int, int, int, UINT);
    using fn_MessageBoxW              = int       (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
    using fn_CreateWindowExW          = HWND      (WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
    using fn_GetSystemMetrics         = int       (WINAPI*)(int);
    using fn_UnregisterClassW         = BOOL      (WINAPI*)(LPCWSTR, HINSTANCE);
    using fn_RegisterClassExW         = ATOM      (WINAPI*)(const WNDCLASSEXW*);
    using fn_ShowWindow               = BOOL      (WINAPI*)(HWND, int);
    using fn_UpdateWindow             = BOOL      (WINAPI*)(HWND);
    using fn_DispatchMessageW         = LRESULT   (WINAPI*)(const MSG*);
    using fn_PeekMessageW             = BOOL      (WINAPI*)(LPMSG, HWND, UINT, UINT, UINT);
    using fn_TranslateMessage         = BOOL      (WINAPI*)(const MSG*);
    using fn_LoadCursorW              = HCURSOR   (WINAPI*)(HINSTANCE, LPCWSTR);
    using fn_PostQuitMessage          = void      (WINAPI*)(int);

    struct api_t {
        fn_GetWindowLongW           GetWindowLongW           = nullptr;
        fn_SetWindowLongW           SetWindowLongW           = nullptr;
        fn_SetWindowLongPtrW        SetWindowLongPtrW        = nullptr;
        fn_AdjustWindowRectEx       AdjustWindowRectEx       = nullptr;
        fn_GetKeyState              GetKeyState              = nullptr;
        fn_GetMessageExtraInfo      GetMessageExtraInfo      = nullptr;
        fn_SetPropA                 SetPropA                 = nullptr;
        fn_GetPropA                 GetPropA                 = nullptr;
        fn_GetDC                    GetDC                    = nullptr;
        fn_ReleaseDC                ReleaseDC                = nullptr;
        fn_MonitorFromWindow        MonitorFromWindow        = nullptr;
        fn_EnumDisplayMonitors      EnumDisplayMonitors      = nullptr;
        fn_GetMonitorInfoW          GetMonitorInfoW          = nullptr;
        fn_ScreenToClient           ScreenToClient           = nullptr;
        fn_ClientToScreen           ClientToScreen           = nullptr;
        fn_WindowFromPoint          WindowFromPoint          = nullptr;
        fn_GetCapture               GetCapture               = nullptr;
        fn_SetCapture               SetCapture               = nullptr;
        fn_ReleaseCapture           ReleaseCapture           = nullptr;
        fn_IsChild                  IsChild                  = nullptr;
        fn_TrackMouseEvent          TrackMouseEvent          = nullptr;
        fn_GetKeyboardLayout        GetKeyboardLayout        = nullptr;
        fn_GetForegroundWindow      GetForegroundWindow      = nullptr;
        fn_SetForegroundWindow      SetForegroundWindow      = nullptr;
        fn_SetLayeredWindowAttributes SetLayeredWindowAttributes = nullptr;
        fn_SetFocus                 SetFocus                 = nullptr;
        fn_BringWindowToTop         BringWindowToTop         = nullptr;
        fn_SetCursor                SetCursor                = nullptr;
        fn_SetCursorPos             SetCursorPos             = nullptr;
        fn_GetCursorPos             GetCursorPos             = nullptr;
        fn_GetClientRect            GetClientRect            = nullptr;
        fn_GetWindowRect            GetWindowRect            = nullptr;
        fn_IsWindowUnicode          IsWindowUnicode          = nullptr;
        fn_IsIconic                 IsIconic                 = nullptr;
        fn_OpenClipboard            OpenClipboard            = nullptr;
        fn_CloseClipboard           CloseClipboard           = nullptr;
        fn_EmptyClipboard           EmptyClipboard           = nullptr;
        fn_GetClipboardData         GetClipboardData         = nullptr;
        fn_SetClipboardData         SetClipboardData         = nullptr;
        fn_DefWindowProcW           DefWindowProcW           = nullptr;
        fn_DestroyWindow            DestroyWindow            = nullptr;
        fn_SetWindowPos             SetWindowPos             = nullptr;
        fn_MessageBoxW              MessageBoxW              = nullptr;
        fn_CreateWindowExW          CreateWindowExW          = nullptr;
        fn_GetSystemMetrics         GetSystemMetrics         = nullptr;
        fn_UnregisterClassW         UnregisterClassW         = nullptr;
        fn_RegisterClassExW         RegisterClassExW         = nullptr;
        fn_ShowWindow               ShowWindow               = nullptr;
        fn_UpdateWindow             UpdateWindow             = nullptr;
        fn_DispatchMessageW         DispatchMessageW         = nullptr;
        fn_PeekMessageW             PeekMessageW             = nullptr;
        fn_TranslateMessage         TranslateMessage         = nullptr;
        fn_LoadCursorW              LoadCursorW              = nullptr;
        fn_PostQuitMessage          PostQuitMessage          = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::GetModuleHandleW( WOBF( L"user32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.GetWindowLongW           = reinterpret_cast<fn_GetWindowLongW>          ( R( OBF( "GetWindowLongW"           ) ) );
        s.SetWindowLongW           = reinterpret_cast<fn_SetWindowLongW>          ( R( OBF( "SetWindowLongW"           ) ) );
        s.SetWindowLongPtrW        = reinterpret_cast<fn_SetWindowLongPtrW>       ( R( OBF( "SetWindowLongPtrW"        ) ) );
        s.AdjustWindowRectEx       = reinterpret_cast<fn_AdjustWindowRectEx>      ( R( OBF( "AdjustWindowRectEx"       ) ) );
        s.GetKeyState              = reinterpret_cast<fn_GetKeyState>             ( R( OBF( "GetKeyState"              ) ) );
        s.GetMessageExtraInfo      = reinterpret_cast<fn_GetMessageExtraInfo>     ( R( OBF( "GetMessageExtraInfo"      ) ) );
        s.SetPropA                 = reinterpret_cast<fn_SetPropA>                ( R( OBF( "SetPropA"                 ) ) );
        s.GetPropA                 = reinterpret_cast<fn_GetPropA>                ( R( OBF( "GetPropA"                 ) ) );
        s.GetDC                    = reinterpret_cast<fn_GetDC>                   ( R( OBF( "GetDC"                    ) ) );
        s.ReleaseDC                = reinterpret_cast<fn_ReleaseDC>               ( R( OBF( "ReleaseDC"                ) ) );
        s.MonitorFromWindow        = reinterpret_cast<fn_MonitorFromWindow>       ( R( OBF( "MonitorFromWindow"        ) ) );
        s.EnumDisplayMonitors      = reinterpret_cast<fn_EnumDisplayMonitors>     ( R( OBF( "EnumDisplayMonitors"      ) ) );
        s.GetMonitorInfoW          = reinterpret_cast<fn_GetMonitorInfoW>         ( R( OBF( "GetMonitorInfoW"          ) ) );
        s.ScreenToClient           = reinterpret_cast<fn_ScreenToClient>          ( R( OBF( "ScreenToClient"           ) ) );
        s.ClientToScreen           = reinterpret_cast<fn_ClientToScreen>          ( R( OBF( "ClientToScreen"           ) ) );
        s.WindowFromPoint          = reinterpret_cast<fn_WindowFromPoint>         ( R( OBF( "WindowFromPoint"          ) ) );
        s.GetCapture               = reinterpret_cast<fn_GetCapture>              ( R( OBF( "GetCapture"               ) ) );
        s.SetCapture               = reinterpret_cast<fn_SetCapture>              ( R( OBF( "SetCapture"               ) ) );
        s.ReleaseCapture           = reinterpret_cast<fn_ReleaseCapture>          ( R( OBF( "ReleaseCapture"           ) ) );
        s.IsChild                  = reinterpret_cast<fn_IsChild>                 ( R( OBF( "IsChild"                  ) ) );
        s.TrackMouseEvent          = reinterpret_cast<fn_TrackMouseEvent>         ( R( OBF( "TrackMouseEvent"          ) ) );
        s.GetKeyboardLayout        = reinterpret_cast<fn_GetKeyboardLayout>       ( R( OBF( "GetKeyboardLayout"        ) ) );
        s.GetForegroundWindow      = reinterpret_cast<fn_GetForegroundWindow>     ( R( OBF( "GetForegroundWindow"      ) ) );
        s.SetForegroundWindow      = reinterpret_cast<fn_SetForegroundWindow>     ( R( OBF( "SetForegroundWindow"      ) ) );
        s.SetLayeredWindowAttributes = reinterpret_cast<fn_SetLayeredWindowAttributes>( R( OBF( "SetLayeredWindowAttributes" ) ) );
        s.SetFocus                 = reinterpret_cast<fn_SetFocus>                ( R( OBF( "SetFocus"                 ) ) );
        s.BringWindowToTop         = reinterpret_cast<fn_BringWindowToTop>        ( R( OBF( "BringWindowToTop"         ) ) );
        s.SetCursor                = reinterpret_cast<fn_SetCursor>               ( R( OBF( "SetCursor"                ) ) );
        s.SetCursorPos             = reinterpret_cast<fn_SetCursorPos>            ( R( OBF( "SetCursorPos"             ) ) );
        s.GetCursorPos             = reinterpret_cast<fn_GetCursorPos>            ( R( OBF( "GetCursorPos"             ) ) );
        s.GetClientRect            = reinterpret_cast<fn_GetClientRect>           ( R( OBF( "GetClientRect"            ) ) );
        s.GetWindowRect            = reinterpret_cast<fn_GetWindowRect>           ( R( OBF( "GetWindowRect"            ) ) );
        s.IsWindowUnicode          = reinterpret_cast<fn_IsWindowUnicode>         ( R( OBF( "IsWindowUnicode"          ) ) );
        s.IsIconic                 = reinterpret_cast<fn_IsIconic>                ( R( OBF( "IsIconic"                 ) ) );
        s.OpenClipboard            = reinterpret_cast<fn_OpenClipboard>           ( R( OBF( "OpenClipboard"            ) ) );
        s.CloseClipboard           = reinterpret_cast<fn_CloseClipboard>          ( R( OBF( "CloseClipboard"           ) ) );
        s.EmptyClipboard           = reinterpret_cast<fn_EmptyClipboard>          ( R( OBF( "EmptyClipboard"           ) ) );
        s.GetClipboardData         = reinterpret_cast<fn_GetClipboardData>        ( R( OBF( "GetClipboardData"         ) ) );
        s.SetClipboardData         = reinterpret_cast<fn_SetClipboardData>        ( R( OBF( "SetClipboardData"         ) ) );
        s.DefWindowProcW           = reinterpret_cast<fn_DefWindowProcW>          ( R( OBF( "DefWindowProcW"           ) ) );
        s.DestroyWindow            = reinterpret_cast<fn_DestroyWindow>           ( R( OBF( "DestroyWindow"            ) ) );
        s.SetWindowPos             = reinterpret_cast<fn_SetWindowPos>            ( R( OBF( "SetWindowPos"             ) ) );
        s.MessageBoxW              = reinterpret_cast<fn_MessageBoxW>             ( R( OBF( "MessageBoxW"              ) ) );
        s.CreateWindowExW          = reinterpret_cast<fn_CreateWindowExW>         ( R( OBF( "CreateWindowExW"          ) ) );
        s.GetSystemMetrics         = reinterpret_cast<fn_GetSystemMetrics>        ( R( OBF( "GetSystemMetrics"         ) ) );
        s.UnregisterClassW         = reinterpret_cast<fn_UnregisterClassW>        ( R( OBF( "UnregisterClassW"         ) ) );
        s.RegisterClassExW         = reinterpret_cast<fn_RegisterClassExW>        ( R( OBF( "RegisterClassExW"         ) ) );
        s.ShowWindow               = reinterpret_cast<fn_ShowWindow>              ( R( OBF( "ShowWindow"               ) ) );
        s.UpdateWindow             = reinterpret_cast<fn_UpdateWindow>            ( R( OBF( "UpdateWindow"             ) ) );
        s.DispatchMessageW         = reinterpret_cast<fn_DispatchMessageW>        ( R( OBF( "DispatchMessageW"         ) ) );
        s.PeekMessageW             = reinterpret_cast<fn_PeekMessageW>            ( R( OBF( "PeekMessageW"             ) ) );
        s.TranslateMessage         = reinterpret_cast<fn_TranslateMessage>        ( R( OBF( "TranslateMessage"         ) ) );
        s.LoadCursorW              = reinterpret_cast<fn_LoadCursorW>             ( R( OBF( "LoadCursorW"              ) ) );
        s.PostQuitMessage          = reinterpret_cast<fn_PostQuitMessage>         ( R( OBF( "PostQuitMessage"          ) ) );
        s.loaded = true;
        return s;
    }

} // namespace user32_

//─────────────────────────────── gdi32 ────────────────────────────────────────
// gdi32 is always loaded in user-mode.
namespace gdi32_ {

    using fn_GetDeviceCaps = int (WINAPI*)(HDC, int);

    struct api_t {
        fn_GetDeviceCaps GetDeviceCaps = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::GetModuleHandleW( WOBF( L"gdi32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.GetDeviceCaps = reinterpret_cast<fn_GetDeviceCaps>( R( OBF( "GetDeviceCaps" ) ) );
        s.loaded = true;
        return s;
    }

} // namespace gdi32_

//─────────────────────────────── shell32 ──────────────────────────────────────
// Loaded on demand via LoadLibraryW.
namespace shell32_ {

    using fn_ShellExecuteW = HINSTANCE (WINAPI*)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);

    struct api_t {
        fn_ShellExecuteW ShellExecuteW = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"shell32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.ShellExecuteW = reinterpret_cast<fn_ShellExecuteW>( R( OBF( "ShellExecuteW" ) ) );
        s.loaded = true;
        return s;
    }

} // namespace shell32_

//─────────────────────────────── imm32 ────────────────────────────────────────
// Loaded on demand via LoadLibraryW – IME support.
namespace imm32_ {

    using fn_ImmGetContext          = HIMC (WINAPI*)(HWND);
    using fn_ImmReleaseContext      = BOOL (WINAPI*)(HWND, HIMC);
    using fn_ImmSetCandidateWindow  = BOOL (WINAPI*)(HIMC, LPCANDIDATEFORM);
    using fn_ImmSetCompositionWindow = BOOL (WINAPI*)(HIMC, LPCOMPOSITIONFORM);

    struct api_t {
        fn_ImmGetContext           ImmGetContext           = nullptr;
        fn_ImmReleaseContext       ImmReleaseContext       = nullptr;
        fn_ImmSetCandidateWindow   ImmSetCandidateWindow   = nullptr;
        fn_ImmSetCompositionWindow ImmSetCompositionWindow = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"imm32.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.ImmGetContext           = reinterpret_cast<fn_ImmGetContext>          ( R( OBF( "ImmGetContext"           ) ) );
        s.ImmReleaseContext       = reinterpret_cast<fn_ImmReleaseContext>      ( R( OBF( "ImmReleaseContext"       ) ) );
        s.ImmSetCandidateWindow   = reinterpret_cast<fn_ImmSetCandidateWindow>  ( R( OBF( "ImmSetCandidateWindow"   ) ) );
        s.ImmSetCompositionWindow = reinterpret_cast<fn_ImmSetCompositionWindow>( R( OBF( "ImmSetCompositionWindow" ) ) );
        s.loaded = true;
        return s;
    }

} // namespace imm32_

//─────────────────────────────── d3d11 ────────────────────────────────────────
// Loaded on demand via LoadLibraryW.
namespace d3d11_ {

    using fn_D3D11CreateDeviceAndSwapChain = HRESULT (WINAPI*)(
        IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
        const D3D_FEATURE_LEVEL*, UINT, UINT,
        const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**,
        ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);

    struct api_t {
        fn_D3D11CreateDeviceAndSwapChain D3D11CreateDeviceAndSwapChain = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"d3d11.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.D3D11CreateDeviceAndSwapChain = reinterpret_cast<fn_D3D11CreateDeviceAndSwapChain>(
            R( OBF( "D3D11CreateDeviceAndSwapChain" ) ) );
        s.loaded = true;
        return s;
    }

} // namespace d3d11_

//─────────────────────────────── d3dcompiler ──────────────────────────────────
// Loaded on demand via LoadLibraryW.
namespace d3dcompiler_ {

    using fn_D3DCompile = HRESULT (WINAPI*)(
        LPCVOID, SIZE_T, LPCSTR, const D3D_SHADER_MACRO*, ID3DInclude*,
        LPCSTR, LPCSTR, UINT, UINT, ID3DBlob**, ID3DBlob**);

    struct api_t {
        fn_D3DCompile D3DCompile = nullptr;
        bool loaded = false;
    };

    [[nodiscard]] inline api_t& get() noexcept
    {
        static api_t s;
        if ( s.loaded ) return s;
        HMODULE h = ::LoadLibraryW( WOBF( L"d3dcompiler_47.dll" ) );
        if ( !h ) { s.loaded = true; return s; }
        auto R = [&]( const char* n ) { return ::GetProcAddress( h, n ); };
        s.D3DCompile = reinterpret_cast<fn_D3DCompile>( R( OBF( "D3DCompile" ) ) );
        s.loaded = true;
        return s;
    }

} // namespace d3dcompiler_

} // namespace lazy
