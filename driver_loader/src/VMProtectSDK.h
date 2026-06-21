#pragma once

//=============================================================================
//  VMProtectSDK.h  -  VMProtect 3.x Ultimate SDK header
//
//  TWO MODES controlled by the VMP_ENABLE preprocessor define:
//
//  -- Default (VMP_ENABLE not defined) ------------------------------------
//  All VMProtect* functions are inline no-ops. No lib needed. The binary
//  builds and runs normally; call sites remain identifiable in the map
//  output so VMProtectCon.exe can locate and replace them at post-build.
//
//  -- With VMP installed (define VMP_ENABLE) ------------------------------
//  Links VMProtectSDK64.lib and uses real extern "C" declarations.
//  VMProtectCon.exe then virtualises/mutates every marked region.
//  To enable: add VMP_ENABLE to PreprocessorDefinitions in the
//  Release|x64 ItemDefinitionGroup in driver_loader.vcxproj.
//=============================================================================

#ifdef VMP_ENABLE
//------------- Real SDK mode: link the VMProtect stub lib -------------------
#  if defined(_MSC_VER) && defined(_WIN64)
#    ifdef VMPROTECT_DIR
#      pragma comment(lib, VMPROTECT_DIR "\\VMProtectSDK64.lib")
#    else
#      pragma comment(lib, "C:\\Users\\DeFexGG\\Downloads\\VMProtect\\VMProtect\\Lib\\Windows\\VMProtectSDK64.lib")
#    endif
#  endif

extern "C" {
    void   VMProtectBegin                       (const char* FunctionName);
    void   VMProtectBeginVirtualization         (const char* FunctionName);
    void   VMProtectBeginMutation               (const char* FunctionName);
    void   VMProtectBeginUltra                  (const char* FunctionName);
    void   VMProtectBeginVirtualizationLockByKey(const char* FunctionName);
    void   VMProtectBeginUltraLockByKey         (const char* FunctionName);
    void   VMProtectEnd                         (void);
    int    VMProtectIsDebuggerPresent           (int bAdvanced);
    int    VMProtectIsVirtualMachinePresent     (void);
    int    VMProtectIsProtected                 (void);
    int    VMProtectIsValidImageCRC             (void);
    const char*    VMProtectDecryptStringA      (const char*    value);
    const wchar_t* VMProtectDecryptStringW      (const wchar_t* value);
    void           VMProtectFreeString          (void* value);
    int    VMProtectSetSerialNumber             (const char* serial);
    int    VMProtectGetSerialNumberState        (void);
}

#else // VMP_ENABLE not defined - use inline no-op stubs
//------------- No-op stub mode: zero dependencies ---------------------------
// These inline stubs satisfy the linker without any external lib. They compile
// to almost nothing (a single ret) and VMProtectCon.exe can still identify
// and replace them at post-build time.

__forceinline void VMProtectBegin                       (const char*) noexcept {}
__forceinline void VMProtectBeginVirtualization         (const char*) noexcept {}
__forceinline void VMProtectBeginMutation               (const char*) noexcept {}
__forceinline void VMProtectBeginUltra                  (const char*) noexcept {}
__forceinline void VMProtectBeginVirtualizationLockByKey(const char*) noexcept {}
__forceinline void VMProtectBeginUltraLockByKey         (const char*) noexcept {}
__forceinline void VMProtectEnd                         ()            noexcept {}
__forceinline int  VMProtectIsDebuggerPresent           (int)         noexcept { return 0; }
__forceinline int  VMProtectIsVirtualMachinePresent     ()            noexcept { return 0; }
__forceinline int  VMProtectIsProtected                 ()            noexcept { return 0; }
__forceinline int  VMProtectIsValidImageCRC             ()            noexcept { return 1; }
__forceinline const char*    VMProtectDecryptStringA    (const char*    v) noexcept { return v; }
__forceinline const wchar_t* VMProtectDecryptStringW    (const wchar_t* v) noexcept { return v; }
__forceinline void           VMProtectFreeString        (void*)           noexcept {}
__forceinline int  VMProtectSetSerialNumber             (const char*)  noexcept { return 0; }
__forceinline int  VMProtectGetSerialNumberState        ()             noexcept { return 0; }

#endif // VMP_ENABLE

//---------------------------- convenience macros ----------------------------

#define VMP_BEGIN(n)            VMProtectBeginMutation(n)
#define VMP_BEGIN_VIRT(n)       VMProtectBeginVirtualization(n)
#define VMP_BEGIN_MUTATION(n)   VMProtectBeginMutation(n)
#define VMP_BEGIN_ULTRA(n)      VMProtectBeginUltra(n)
#define VMP_END()               VMProtectEnd()

#define VMP_IS_DBG()            (VMProtectIsDebuggerPresent(1) != 0)
#define VMP_IS_DBG_BASIC()      (VMProtectIsDebuggerPresent(0) != 0)
#define VMP_IS_VM()             (VMProtectIsVirtualMachinePresent() != 0)
#define VMP_IS_PROTECTED()      (VMProtectIsProtected() != 0)
#define VMP_CRC_OK()            (VMProtectIsValidImageCRC() != 0)

// Guard macro: terminates instantly if debugger/VM detected.
// Skipped entirely in Debug builds so the debugger can attach normally.
#ifdef _DEBUG
#  define VMP_GUARD()       ((void)0)
#  define VMP_GUARD_NOVM()  ((void)0)
#else
// Wrap the guard bodies in noinline functions so VMProtect sees a unique
// entry-point address for "__guard" that never coincides with the caller's
// own VMP marker (would happen if the macro expanded inline in the caller).
namespace _vmp_detail {
    __declspec(noinline) inline void _guard() {
        VMProtectBeginMutation("__guard");
        if (VMProtectIsDebuggerPresent(1) || VMProtectIsVirtualMachinePresent()) {
            VMProtectEnd();
            ::TerminateProcess(::GetCurrentProcess(), 0xDEAD'C0DE);
        }
        VMProtectEnd();
    }
    __declspec(noinline) inline void _guard_novm() {
        VMProtectBeginMutation("__guard_novm");
        if (VMProtectIsDebuggerPresent(1)) {
            VMProtectEnd();
            ::TerminateProcess(::GetCurrentProcess(), 0xDEAD'C0DE);
        }
        VMProtectEnd();
    }
} // namespace _vmp_detail
#  define VMP_GUARD()       _vmp_detail::_guard()
#  define VMP_GUARD_NOVM()  _vmp_detail::_guard_novm()
#endif
