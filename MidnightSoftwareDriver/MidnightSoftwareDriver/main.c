/*
 * MidnightSoftwareDriver - Kernel-mode memory read/write driver
 * Communicates with user-mode via IOCTL (METHOD_BUFFERED) through \\.\DXGKrnl.
 *
 * Supported IOCTLs:
 *   MidnightSoftware_MAGIC_ECHO       - round-trip connectivity test
 *   MidnightSoftware_MAGIC_READ_MEM   - read N bytes from target process
 *   MidnightSoftware_MAGIC_WRITE_MEM  - write N bytes to target process
 *   MidnightSoftware_MAGIC_ENUM_PROCS - enumerate running processes
 *   MidnightSoftware_MAGIC_QUERY_REGS - query virtual memory regions of a process
 *   MidnightSoftware_MAGIC_GET_CR3    - query DirectoryTableBase of a process
 *
 * Communication paths (user always opens \\.\DXGKrnl):
 *   GPU present:  hook dxgkrnl's IRP_MJ_DEVICE_CONTROL dispatch pointer.
 *                 No device object is created by this driver.
 *   No GPU / VM:  create \Device\DxgKrnl + \DosDevices\DXGKrnl alias.
 *                 Identical layout to a real dxgkrnl – no named trace of
 *                 this driver exists in the kernel object namespace.
 *
 * Memory access strategy (no Windows API context switch):
 *   All read/write goes through ReadMemoryCr3 / WriteMemoryCr3.
 *   KeStackAttachProcess / KeUnstackDetachProcess are NOT used – they leave
 *   artifacts in KTHREAD.ApcState that anti-cheats scan for.
 *   Physical memory reads use MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) which
 *   does not allocate persistent system PTEs unlike MmMapIoSpace.
 *   KPTI (Meltdown mitigation): user-mode addresses use UserDirectoryTableBase;
 *   kernel addresses use DirectoryTableBase – both selected automatically.
 *
 * Build: WDK + KMDF, x64, Windows 10+
 */

#include <ntifs.h>
#include <wdm.h>

 // -----------------------------------------------------------------
 // Shared definitions (mirror of MidnightSoftwareCommon.h)
 // -----------------------------------------------------------------
#define FILE_DEVICE_MidnightSoftware      0x8888u   // used only in the no-GPU path

// ─────────────────────────────────────────────────────────────────
// Magic IOCTL codes routed through \\.\DXGKrnl (FILE_DEVICE_VIDEO=0x23).
// Intercepted by DxgHookedIoControl *before* dxgkrnl ever sees them.
// ─────────────────────────────────────────────────────────────────
#define MidnightSoftware_MAGIC_ECHO       CTL_CODE(0x23u, 0x0DEFu, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MidnightSoftware_MAGIC_READ_MEM   CTL_CODE(0x23u, 0x0DE0u, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MidnightSoftware_MAGIC_WRITE_MEM  CTL_CODE(0x23u, 0x0DE1u, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MidnightSoftware_MAGIC_ENUM_PROCS CTL_CODE(0x23u, 0x0DE2u, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MidnightSoftware_MAGIC_QUERY_REGS CTL_CODE(0x23u, 0x0DE3u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Query DirectoryTableBase (CR3) of a target process
#define MidnightSoftware_MAGIC_GET_CR3    CTL_CODE(0x23u, 0x0DE4u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Queue a user-mode APC to a thread in the target process
#define MidnightSoftware_MAGIC_QUEUE_APC  CTL_CODE(0x23u, 0x0DE5u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Allocate virtual memory in target process via kernel-mode handle
#define MidnightSoftware_MAGIC_ALLOC_MEM  CTL_CODE(0x23u, 0x0DE6u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Free virtual memory in target process via kernel-mode handle
#define MidnightSoftware_MAGIC_FREE_MEM   CTL_CODE(0x23u, 0x0DE7u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Enumerate loaded modules via PEB Ldr walk (CR3 physical read, no handle)
#define MidnightSoftware_MAGIC_ENUM_MODS  CTL_CODE(0x23u, 0x0DE8u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Change page protection of a VA range in a target process via kernel-mode handle
#define MidnightSoftware_MAGIC_PROTECT_MEM  CTL_CODE(0x23u, 0x0DE9u, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Register a PID for ObRegisterCallbacks-based process protection (anti-dump / anti-attach)
#define MidnightSoftware_MAGIC_PROTECT_PROC CTL_CODE(0x23u, 0x0DEAu, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MidnightSoftware_MAX_BUFFER       (4 * 1024 * 1024)   // 4 MB max per single IOCTL
#define MidnightSoftware_MAX_PROCESSES    4096               // max entries per IOCTL_ENUM_PROCESSES call
#define MidnightSoftware_MAX_REGIONS      65536              // max entries per IOCTL_QUERY_REGIONS call

// Output entry for IOCTL_ENUM_PROCESSES
// Must match PROCESS_ENTRY in MidnightSoftwareCommon.h
#pragma pack(push, 1)
typedef struct _PROCESS_ENTRY {
    ULONG_PTR ProcessId;
    CHAR      ImageName[256];
} PROCESS_ENTRY, *PPROCESS_ENTRY;
#pragma pack(pop)

// Input for IOCTL_QUERY_REGIONS
#pragma pack(push, 1)
typedef struct _QUERY_REGIONS_REQUEST {
    ULONG_PTR ProcessId;
} QUERY_REGIONS_REQUEST, *PQUERY_REGIONS_REQUEST;

// Output entry for IOCTL_QUERY_REGIONS
typedef struct _REGION_ENTRY {
    ULONG_PTR Base;
    SIZE_T    Size;
    ULONG     Protect;
} REGION_ENTRY, *PREGION_ENTRY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _GET_CR3_REQUEST {
    ULONG_PTR ProcessId;
} GET_CR3_REQUEST, *PGET_CR3_REQUEST;

typedef struct _GET_CR3_RESPONSE {
    ULONG_PTR Cr3Value;       // DirectoryTableBase of target process
    ULONG_PTR UserCr3Value;   // UserDirectoryTableBase (KPTI user CR3, 0 if not present)
} GET_CR3_RESPONSE, *PGET_CR3_RESPONSE;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _QUEUE_APC_REQUEST {
    ULONG_PTR ProcessId;    // informational
    ULONG_PTR ThreadId;     // thread to receive the APC
    ULONG_PTR ShellcodeVA;  // user-mode NormalRoutine address
} QUEUE_APC_REQUEST, *PQUEUE_APC_REQUEST;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _ALLOC_MEMORY_REQUEST {
    ULONG_PTR ProcessId;     // target PID
    ULONG_PTR PreferredBase; // desired VA (0 = OS picks)
    SIZE_T    Size;          // bytes to allocate
    ULONG     AllocType;     // MEM_COMMIT | MEM_RESERVE etc.
    ULONG     Protect;       // PAGE_EXECUTE_READWRITE etc.
} ALLOC_MEMORY_REQUEST, *PALLOC_MEMORY_REQUEST;

typedef struct _ALLOC_MEMORY_RESPONSE {
    ULONG_PTR AllocatedBase; // actual VA of allocation in target process
} ALLOC_MEMORY_RESPONSE, *PALLOC_MEMORY_RESPONSE;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _FREE_MEMORY_REQUEST {
    ULONG_PTR ProcessId; // target PID
    ULONG_PTR Address;   // VA to free
    SIZE_T    Size;      // 0 = MEM_RELEASE whole region
    ULONG     FreeType;  // MEM_RELEASE or MEM_DECOMMIT
} FREE_MEMORY_REQUEST, *PFREE_MEMORY_REQUEST;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _ENUM_MODS_REQUEST {
    ULONG_PTR ProcessId; // target PID
} ENUM_MODS_REQUEST, *PENUM_MODS_REQUEST;

typedef struct _MODULE_ENTRY_DRV {
    ULONG_PTR BaseAddress;
    CHAR      ModuleName[256];
} MODULE_ENTRY_DRV, *PMODULE_ENTRY_DRV;
#pragma pack(pop)

#define MidnightSoftware_MAX_MODULES 1024

#pragma pack(push, 1)
typedef struct _READ_MEMORY_REQUEST {
    ULONG_PTR ProcessId;    // target PID
    ULONG_PTR Address;      // virtual address in target
    SIZE_T    Size;         // bytes to read (≤ MidnightSoftware_MAX_BUFFER)
} READ_MEMORY_REQUEST, * PREAD_MEMORY_REQUEST;

typedef struct _WRITE_MEMORY_REQUEST {
    ULONG_PTR ProcessId;    // target PID
    ULONG_PTR Address;      // virtual address in target
    SIZE_T    Size;         // bytes to write
    // BYTE Data[Size] follows immediately in the same buffer
} WRITE_MEMORY_REQUEST, * PWRITE_MEMORY_REQUEST;
#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────
// Kernel API declarations
// ─────────────────────────────────────────────────────────────────

// ObReferenceObjectByName - undocumented, lets us look up a named kernel object
// (e.g. a DRIVER_OBJECT by its registry path such as \Driver\dxgkrnl) without
// needing an open handle.  Exported from ntoskrnl.exe since Windows 2000.
NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   PassedAccessState OPTIONAL,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext OPTIONAL,
    PVOID          *Object
);

// ZwQuerySystemInformation - enumerate running processes from kernel
// exported from ntoskrnl.exe, accessible from kernel drivers
NTSTATUS ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// SYSTEM_PROCESS_INFORMATION for SystemInformationClass = 5
// Using Reserved1[48] to stay compatible with all WDK versions;
// ImageName and UniqueProcessId offsets are stable across all Win10+ builds.
typedef struct _MY_SYSTEM_PROCESS_INFO {
    ULONG          NextEntryOffset;   // 0
    ULONG          NumberOfThreads;   // 4
    UCHAR          Reserved1[48];     // 8  (WorkingSetPrivateSize etc.)
    UNICODE_STRING ImageName;         // 56 (Length+MaxLength+pad+Buffer = 16 bytes x64)
    LONG           BasePriority;      // 72
    ULONG          _pad;              // 76
    HANDLE         UniqueProcessId;   // 80
} MY_SYSTEM_PROCESS_INFO, *PMY_SYSTEM_PROCESS_INFO;

// ─────────────────────────────────────────────────────────────────
// IoDriverObjectType – declared in ntddk/ntifs but not always forwarded;
// exported from ntoskrnl.exe, safe to reference from a WDM driver.
// ─────────────────────────────────────────────────────────────────
extern POBJECT_TYPE *IoDriverObjectType;

// CR3 register intrinsic
// Note: MmGetPhysicalMemoryRanges is already declared with NTKERNELAPI in
// the WDK ntifs.h; redeclaring it here without NTKERNELAPI causes C4273.
unsigned __int64 __readcr3(void);
#pragma intrinsic(__readcr3)

// ─────────────────────────────────────────────────────────────────
// APC support
//
// KeInitializeApc and KeInsertQueueApc are exported from ntoskrnl
// but not declared in public WDK headers – declare them manually.
// KAPC_ENVIRONMENT / PKKERNEL_ROUTINE / PKNORMAL_ROUTINE are also
// missing from some WDK configurations, so we define them ourselves.
// ─────────────────────────────────────────────────────────────────
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID (NTAPI *PKNORMAL_ROUTINE_MidnightSoftware)(
    IN PVOID NormalContext,
    IN OUT PVOID *SystemArgument1,
    IN OUT PVOID *SystemArgument2
);

typedef VOID (NTAPI *PKKERNEL_ROUTINE_MidnightSoftware)(
    IN PRKAPC Apc,
    IN OUT PKNORMAL_ROUTINE_MidnightSoftware *NormalRoutine,
    IN OUT PVOID *NormalContext,
    IN OUT PVOID *SystemArgument1,
    IN OUT PVOID *SystemArgument2
);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE_MidnightSoftware)(
    IN PRKAPC Apc
);

NTKERNELAPI VOID KeInitializeApc(
    OUT PRKAPC                   Apc,
    IN  PKTHREAD                 Thread,
    IN  KAPC_ENVIRONMENT         Environment,
    IN  PKKERNEL_ROUTINE_MidnightSoftware   KernelRoutine,
    IN  PKRUNDOWN_ROUTINE_MidnightSoftware  RundownRoutine OPTIONAL,
    IN  PKNORMAL_ROUTINE_MidnightSoftware   NormalRoutine  OPTIONAL,
    IN  KPROCESSOR_MODE          ApcMode        OPTIONAL,
    IN  PVOID                    NormalContext  OPTIONAL
);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    IN PRKAPC    Apc,
    IN PVOID     SystemArgument1 OPTIONAL,
    IN PVOID     SystemArgument2 OPTIONAL,
    IN KPRIORITY Increment
);

/*
 * KeAlertThread – exported from ntoskrnl, not in public WDK headers.
 * Transitions the target thread to Alert state, waking it from any
 * current alertable or non-alertable wait so a pending user-mode APC
 * can be dispatched at the next user-mode return or alertable wait.
 */
NTKERNELAPI BOOLEAN KeAlertThread(
    IN PKTHREAD      Thread,
    IN KPROCESSOR_MODE AlertMode
);

// -----------------------------------------------------------------
// Globals
// -----------------------------------------------------------------
// Primary device name: used in the no-GPU path where \Device\DxgKrnl
// does not yet exist. Matches the real dxgkrnl naming exactly.
static UNICODE_STRING g_DeviceName    = RTL_CONSTANT_STRING(L"\\Device\\DxgKrnl");
// Fallback device name: used in the GPU path where dxgkrnl.sys has
// already claimed \Device\DxgKrnl. Looks like a legitimate DXG ICD.
static UNICODE_STRING g_DeviceNameAlt = RTL_CONSTANT_STRING(L"\\Device\\DxgKrnlGdi");

// \DosDevices\DXGKrnl: dxgkrnl does not expose this symlink on modern
// Windows builds, so we always create it pointing at our device.
static UNICODE_STRING g_DxgKrnlLink  = RTL_CONSTANT_STRING(L"\\DosDevices\\DXGKrnl");
static BOOLEAN        g_CreatedDxgLink = FALSE;

static PDEVICE_OBJECT g_DeviceObject = NULL;

// ─────────────────────────────────────────────────────────────────
// DXG data-hook state
// ─────────────────────────────────────────────────────────────────
static PDRIVER_DISPATCH g_OrigDxgIoControl = NULL;  // original dxgkrnl IRP_MJ_DEVICE_CONTROL
static PDRIVER_OBJECT   g_DxgDriverObj     = NULL;  // borrowed reference (ObReferenceObjectByName)
static volatile LONG    g_HookActive       = 0;     // 1 = hook is installed

// -----------------------------------------------------------------
// Process-protection state (ObRegisterCallbacks + EPROCESS PPL anti-dump)
// -----------------------------------------------------------------
static volatile LONGLONG g_ProtectedPid       = 0;     // PID being protected (0 = none)
static PVOID             g_ObCallbackHandle   = NULL;  // handle from ObRegisterCallbacks
static ULONG             g_EprocProtectionOff = 0;     // EPROCESS.Protection byte offset (discovered)
static BOOLEAN           g_ProcNotifyReg      = FALSE; // TRUE once PsSetCreateProcessNotifyRoutineEx called

// Handle-stripping thread
static PKTHREAD          g_HandleStripThread  = NULL;  // kernel thread PKTHREAD object
static KEVENT            g_HandleStripStop;            // signal to stop the thread

// Access mask bits to silently strip from every OpenProcess / DuplicateHandle
// targeting our protected process.  We intentionally keep
// PROCESS_QUERY_LIMITED_INFORMATION so Task Manager still shows the process
// name and CPU/memory stats, but cannot read or write its memory, attach a
// debugger, or inject threads.
//
// These are user-mode values (from winnt.h) -- not always exposed in kernel
// headers, so we define them explicitly to avoid C2065.
#ifndef PROCESS_TERMINATE
#  define PROCESS_TERMINATE            0x0001UL
#endif
#ifndef PROCESS_CREATE_THREAD
#  define PROCESS_CREATE_THREAD        0x0002UL
#endif
#ifndef PROCESS_VM_OPERATION
#  define PROCESS_VM_OPERATION         0x0008UL
#endif
#ifndef PROCESS_VM_READ
#  define PROCESS_VM_READ              0x0010UL
#endif
#ifndef PROCESS_VM_WRITE
#  define PROCESS_VM_WRITE             0x0020UL
#endif
#ifndef PROCESS_DUP_HANDLE
#  define PROCESS_DUP_HANDLE           0x0040UL
#endif
#ifndef PROCESS_SUSPEND_RESUME
#  define PROCESS_SUSPEND_RESUME       0x0800UL
#endif

#define PROC_DUMP_ACCESS ( PROCESS_VM_READ            \
                         | PROCESS_VM_WRITE           \
                         | PROCESS_VM_OPERATION       \
                         | PROCESS_CREATE_THREAD      \
                         | PROCESS_DUP_HANDLE         \
                         | PROCESS_SUSPEND_RESUME      \
                         | PROCESS_TERMINATE )

// -----------------------------------------------------------------
// SystemExtendedHandleInformation (class 64) structures
// Used by the handle-stripping thread to enumerate all open handles.
// -----------------------------------------------------------------
#pragma pack(push, 8)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;           // kernel object pointer
    ULONG_PTR   UniqueProcessId;  // owner PID
    ULONG_PTR   HandleValue;      // handle value
    ULONG       GrantedAccess;    // access mask granted to the handle
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;  // e.g. 7 = Process
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR                       NumberOfHandles;
    ULONG_PTR                       Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
#pragma pack(pop)

#define SystemExtendedHandleInformation 64

// ─────────────────────────────────────────────────────────────────
// Dynamically discovered KPROCESS offsets
//
// g_DirBaseOffset / g_UserDirBaseOffset are discovered at load time by
// matching the live hardware CR3 (__readcr3) against the System EPROCESS.
// Because the scheduler MUST read from these offsets to context-switch
// threads, the offsets we discover are exactly the ones the CPU uses –
// they will be correct regardless of the Windows build number and even
// if an anti-cheat zeros a different field hoping it looks like DirectoryTableBase.
//
// Fallback values (0x28 / 0x30) are used only if discovery fails.
// ─────────────────────────────────────────────────────────────────
static ULONG     g_DirBaseOffset      = 0x28; // KPROCESS->DirectoryTableBase     (fallback)
static ULONG     g_UserDirBaseOffset  = 0x30; // KPROCESS->UserDirectoryTableBase (fallback, 0 = absent)
static ULONG_PTR g_SysCr3             = 0;    // Validated System-process kernel PML4 base
static ULONG_PTR g_SysPml4Sig[4]      = {0};  // PML4[256..259] of System process – used as
                                               // kernel-space signature during PML4 scan

// ─────────────────────────────────────────────────────────────────
// CR3 per-PID cache
//
// Avoids re-scanning physical memory on every READ_MEM IOCTL when the
// anti-cheat has spoofed EPROCESS->DirectoryTableBase.  A PML4 scan on a
// 32 GB+ machine can touch hundreds of thousands of 4 KB pages which costs
// tens of milliseconds and would destroy game FPS if done per-read.
//
// Cache layout: fixed 32-slot array protected by a KSPIN_LOCK.
// Eviction: round-robin (oldest slot) when all 32 slots are full.
// Invalidation: next READ_MEM that calls ValidateCr3 and finds the page
// gone (Present==0) will evict the stale entry and re-scan.
// ─────────────────────────────────────────────────────────────────
#define CR3_CACHE_CAP 32

typedef struct _CR3_CACHE_ENTRY {
    volatile ULONG_PTR Pid;      // 0 = empty slot
    volatile ULONG_PTR Cr3;      // validated kernel PML4 base
    volatile ULONG_PTR UserCr3;  // validated user PML4 base (0 = absent)
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY g_Cr3Cache[CR3_CACHE_CAP];
static KSPIN_LOCK      g_Cr3CacheLock;
static volatile LONG   g_Cr3CacheEvict = 0;    // round-robin eviction counter

// Forward declarations of helpers defined later in this file
static NTSTATUS CopyFromProcess(HANDLE ProcessId, PVOID SourceAddress, PVOID Buffer, SIZE_T Size, PSIZE_T Copied);
static NTSTATUS CopyToProcess  (HANDLE ProcessId, PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T Copied);

// CR3 / physical memory helpers (forward declarations)
static NTSTATUS  DiscoverEprocessOffsets(VOID);
static BOOLEAN   ValidateCr3(ULONG_PTR Cr3);
static VOID      CacheStoreCr3(ULONG_PTR Pid, ULONG_PTR Cr3, ULONG_PTR UserCr3);
static BOOLEAN   CacheLookupCr3(ULONG_PTR Pid, PULONG_PTR Cr3Out, PULONG_PTR UserCr3Out);
static VOID      CacheInvalidatePid(ULONG_PTR Pid);
static ULONG_PTR ScanRangesForPml4(PPHYSICAL_MEMORY_RANGE Ranges, ULONG_PTR FromPhys, ULONG_PTR ToPhys);
static ULONG_PTR FindRealCr3ByPml4Scan(PEPROCESS TargetProcess);
static ULONG_PTR GetProcessCr3(PEPROCESS Process);
static ULONG_PTR GetProcessUserCr3(PEPROCESS Process);
static BOOLEAN   ReadPhysQword(ULONG_PTR physAddr, PULONG_PTR outValue);
static ULONG_PTR Cr3VirtToPhys(ULONG_PTR Cr3, ULONG_PTR Va);
static NTSTATUS  ReadMemoryCr3 (ULONG_PTR Cr3, ULONG_PTR Va, PVOID Buffer, SIZE_T Size, PSIZE_T Copied);
static NTSTATUS  WriteMemoryCr3(ULONG_PTR Cr3, ULONG_PTR Va, PVOID Buffer, SIZE_T Size, PSIZE_T Copied);

// -----------------------------------------------------------------
// DXG communication - two complementary paths, same handler:
//
//   GPU present:  dxgkrnl.sys owns \DosDevices\DXGKrnl.  We obtain its
//                 DRIVER_OBJECT and atomically swap MajorFunction[
//                 IRP_MJ_DEVICE_CONTROL] with DxgHookedIoControl (pure
//                 data hook - no code bytes in dxgkrnl are patched).
//                 MidnightSoftware_MAGIC_* IOCTLs are handled in-place; all other
//                 codes are forwarded to the original handler.
//
//   No GPU / VM:  dxgkrnl is absent so \DosDevices\DXGKrnl does not
//                 exist.  We create that symlink ourselves pointing at
//                 \Device\DxgKrnl.  User-mode opens \\.\DXGKrnl and
//                 IRPs arrive directly at DxgHookedIoControl via our
//                 own DispatchIoControl.
// -----------------------------------------------------------------

/*
 * ApcKernelRoutine – KernelRoutine callback for user-mode APCs queued via
 * MidnightSoftware_MAGIC_QUEUE_APC.  Fires at APC_LEVEL (before NormalRoutine runs).
 * Its only job is to free the KAPC block that was allocated in the IOCTL
 * handler; this keeps pool usage self-contained regardless of whether the
 * NormalRoutine actually runs (thread exits, APC is rundown, etc.).
 */
static VOID NTAPI
ApcKernelRoutine(
    IN PRKAPC                   Apc,
    IN OUT PKNORMAL_ROUTINE_MidnightSoftware *NormalRoutine,
    IN OUT PVOID               *NormalContext,
    IN OUT PVOID               *SystemArgument1,
    IN OUT PVOID               *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}

/*
 * DHDispatch – declared in ioctl_handlers.c.
 * Handles QUEUE_APC, ALLOC_MEM, FREE_MEM, ENUM_MODS.
 * All four use KeStackAttachProcess / ZwCurrentProcess() / KeAlertThread.
 */
extern NTSTATUS DHDispatch(
    IN  ULONG      IoctlCode,
    IN  PVOID      Buffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten);

/*
 * DxgHookedIoControl - central IOCTL handler for all MidnightSoftware_MAGIC_* codes.
 *
 * Reached via two paths:
 *   - GPU present: installed as dxgkrnl MajorFunction[IRP_MJ_DEVICE_CONTROL]
 *     (data hook).  Non-MidnightSoftware codes are forwarded to the original handler.
 *   - No GPU:     called directly from DispatchIoControl because
 *     \DosDevices\DXGKrnl points at our own \Device\DxgKrnl.
 *
 * In both cases IRPs arrive at IRQL PASSIVE_LEVEL.
 */

// -----------------------------------------------------------------
// PROTECT_PROC IOCTL request struct (mirrors MidnightSoftwareCommon.h)
// -----------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _PROTECT_PROC_REQUEST_K {
    ULONG_PTR ProcessId;    // PID to protect (0 = unregister)
} PROTECT_PROC_REQUEST_K, *PPROTECT_PROC_REQUEST_K;
#pragma pack(pop)

// -----------------------------------------------------------------
// ObRegisterCallbacks pre-operation callback
// Strips dump/attach/inject access bits from OpenProcess and
// NtDuplicateObject calls targeting g_ProtectedPid.
// -----------------------------------------------------------------
static OB_PREOP_CALLBACK_STATUS
ProcProtectPreCallback(
    _In_ PVOID                          context,
    _Inout_ POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);

    // Only care about process objects
    if (info->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    ULONG_PTR targetPid = (ULONG_PTR)PsGetProcessId((PEPROCESS)info->Object);
    LONG64    guardPid  = InterlockedCompareExchange64(&g_ProtectedPid, 0, 0);

    if (targetPid != (ULONG_PTR)guardPid || guardPid == 0)
        return OB_PREOP_SUCCESS;

    // Let the protected process open itself and let System (PID 4) pass
    ULONG_PTR callerPid = (ULONG_PTR)PsGetCurrentProcessId();
    if (callerPid == targetPid || callerPid == 4)
        return OB_PREOP_SUCCESS;

    // Strip dangerous access bits
    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
        info->Parameters->CreateHandleInformation.DesiredAccess    &= ~PROC_DUMP_ACCESS;
    else
        info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROC_DUMP_ACCESS;

    return OB_PREOP_SUCCESS;
}

// -----------------------------------------------------------------
// DiscoverProtectionOffset
//
// PRIMARY:   Build-number lookup table – works on all shipping Windows
//            10/11 versions and requires zero scanning.
//
// SECONDARY: EPROCESS byte scan on smss.exe.
//            The correct smss.exe pattern is:
//              ep[off-2] = SignatureLevel        (any non-zero value, same as ep[off-1])
//              ep[off-1] = SectionSignatureLevel (same as ep[off-2])
//              ep[off]   = 0x62                  (Protection: WinTcb | Protected)
//            NOTE: the old code used "06 06 62" which was WRONG – the
//            SignatureLevel for smss is NOT 0x06 (PS_PROTECTED_SIGNER).
//            It is a SE_SIGNING_LEVEL value (0x06 on Win10 old builds,
//            0x1E on Win11).  We now match regardless of the exact value.
// -----------------------------------------------------------------
static ULONG
DiscoverProtectionOffset(VOID)
{
    ULONG found = 0;

    /* ── 1. Build-number table ─────────────────────────────── */
    RTL_OSVERSIONINFOW vi = { sizeof(vi) };
    if (NT_SUCCESS(RtlGetVersion(&vi))) {
        ULONG b = vi.dwBuildNumber;
        KdPrint(("[MidnightSoftwareDriver] Windows build %lu\n", b));

        if      (b >= 26100) found = 0x9F8; /* Win11 24H2 */
        else if (b >= 22000) found = 0x87A; /* Win11 21H2 / 22H2 / 23H2 */
        else if (b >= 19041) found = 0x87A; /* Win10 20H1 / 20H2 / 21H1 / 21H2 */
        else if (b >= 17763) found = 0x6FA; /* Win10 1809 / 1903 / 1909 */
        else if (b >= 16299) found = 0x6FA; /* Win10 1709 / 1803 */
        else if (b >= 10240) found = 0x6B2; /* Win10 1507 – 1703 */

        if (found)
            KdPrint(("[MidnightSoftwareDriver] Protection offset (build table) = 0x%X\n", found));
    }

    /* ── 2. Validate / discover via smss.exe pattern scan ─── */
    {
        ULONG     querySize = 128 * 1024;
        PVOID     queryBuf  = NULL;
        NTSTATUS  qs        = STATUS_UNSUCCESSFUL;
        ULONG     needed    = 0;
        HANDLE    smssPid   = NULL;
        PEPROCESS smssProc  = NULL;
        int       retries   = 0;
        PMY_SYSTEM_PROCESS_INFO entry;
        PUCHAR cursor;
        static const WCHAR smssW[] = L"smss.exe";

        do {
            queryBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, querySize, 'xfeD');
            if (!queryBuf) break;
            qs = ZwQuerySystemInformation(5, queryBuf, querySize, &needed);
            if (qs == STATUS_INFO_LENGTH_MISMATCH) {
                ExFreePoolWithTag(queryBuf, 'xfeD');
                queryBuf  = NULL;
                querySize = needed + 4096;
            }
            retries++;
        } while (qs == STATUS_INFO_LENGTH_MISMATCH && retries < 6);

        if (NT_SUCCESS(qs) && queryBuf) {
            cursor = (PUCHAR)queryBuf;
            for (;;) {
                entry = (PMY_SYSTEM_PROCESS_INFO)cursor;
                if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
                    ULONG nch = entry->ImageName.Length / sizeof(WCHAR);
                    if (nch == 8 &&
                        RtlCompareMemory(entry->ImageName.Buffer, smssW,
                                         8 * sizeof(WCHAR)) == 8 * sizeof(WCHAR)) {
                        smssPid = entry->UniqueProcessId;
                        break;
                    }
                }
                if (entry->NextEntryOffset == 0) break;
                cursor += entry->NextEntryOffset;
            }
            ExFreePoolWithTag(queryBuf, 'xfeD');
        }

        if (smssPid && NT_SUCCESS(PsLookupProcessByProcessId(smssPid, &smssProc))) {
            PUCHAR ep  = (PUCHAR)smssProc;
            ULONG  off, scan_found = 0;

            /* Correct pattern: both preceding bytes must be equal and in
             * the SE_SIGNING_LEVEL range (1..31).  The Protection byte
             * for smss.exe is always 0x62 on all Windows versions. */
            for (off = 0x402; off < 0xE00; off++) {
                if (ep[off] == 0x62 &&
                    ep[off - 1] == ep[off - 2] &&
                    ep[off - 1] >= 0x01 &&
                    ep[off - 1] <= 0x1F) {
                    scan_found = off;
                    break;
                }
            }

            ObDereferenceObject(smssProc);

            if (scan_found) {
                KdPrint(("[MidnightSoftwareDriver] Protection offset (pattern scan) = 0x%X\n", scan_found));
                /* Pattern scan is definitive – use it over the table value */
                found = scan_found;
            } else {
                KdPrint(("[MidnightSoftwareDriver] Protection offset pattern scan failed – "
                         "using table value 0x%X\n", found));
            }
        }
    }

    return found;
}

// -----------------------------------------------------------------
// HandleStripThread
//
// Kernel thread that runs every 1 second.  It enumerates every handle
// in the system via SystemExtendedHandleInformation (class 64) and
// closes any handle TO OUR PROTECTED PROCESS that has dangerous memory
// access bits set, from any process other than the protected process
// itself and System (PID 4).
//
// Uses ZwDuplicateObject(DUPLICATE_CLOSE_SOURCE) on the owner process's
// handle – this atomically closes the handle in the owner's table from
// kernel context without needing KeStackAttachProcess.
//
// This removes pre-existing handles that ObRegisterCallbacks cannot
// retroactively revoke, such as handles Task Manager opened before
// protection was enabled.
// -----------------------------------------------------------------
static VOID
HandleStripThread(PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    LARGE_INTEGER interval;
    interval.QuadPart = -10000LL * 1000; /* 1 000 ms */

    for (;;) {
        NTSTATUS waitSt = KeWaitForSingleObject(
            &g_HandleStripStop, Executive, KernelMode, FALSE, &interval);
        if (waitSt == STATUS_SUCCESS) break;

        ULONG_PTR protectedPid = (ULONG_PTR)InterlockedCompareExchange64(
            &g_ProtectedPid, 0, 0);
        if (protectedPid == 0) continue;

        /* Look up the EPROCESS pointer so we can match h->Object */
        PEPROCESS protectedEproc = NULL;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)protectedPid, &protectedEproc))) continue;

        /* Allocate buffer for SystemExtendedHandleInformation */
        ULONG   qsize  = 512 * 1024;
        PVOID   qbuf   = NULL;
        ULONG   needed = 0;
        NTSTATUS qs;
        int     tries  = 0;

        do {
            qbuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, qsize, 'prtS');
            if (!qbuf) break;
            qs = ZwQuerySystemInformation(
                (ULONG)SystemExtendedHandleInformation,
                qbuf, qsize, &needed);
            if (qs == STATUS_INFO_LENGTH_MISMATCH) {
                ExFreePoolWithTag(qbuf, 'prtS');
                qbuf  = NULL;
                qsize = needed + 16384;
            }
            tries++;
        } while (qs == STATUS_INFO_LENGTH_MISMATCH && tries < 8);

        if (!qbuf) { ObDereferenceObject(protectedEproc); continue; }
        if (!NT_SUCCESS(qs)) {
            ExFreePoolWithTag(qbuf, 'prtS');
            ObDereferenceObject(protectedEproc);
            continue;
        }

        PSYSTEM_HANDLE_INFORMATION_EX shi = (PSYSTEM_HANDLE_INFORMATION_EX)qbuf;
        ULONG_PTR i;

        for (i = 0; i < shi->NumberOfHandles; i++) {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX h = &shi->Handles[i];

            if ((PVOID)h->Object       != (PVOID)protectedEproc) continue;
            if (h->UniqueProcessId     == protectedPid)           continue;
            if (h->UniqueProcessId     == 4)                      continue;
            if (!(h->GrantedAccess & PROC_DUMP_ACCESS))           continue;

            /* Open the owning process with PROCESS_DUP_HANDLE so we can
             * forcibly close the dangerous handle inside its table. */
            OBJECT_ATTRIBUTES oa;
            CLIENT_ID         cid;
            HANDLE            hOwner = NULL;

            InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
            cid.UniqueProcess = (HANDLE)h->UniqueProcessId;
            cid.UniqueThread  = NULL;

            if (!NT_SUCCESS(ZwOpenProcess(&hOwner,
                    PROCESS_DUP_HANDLE, &oa, &cid))) continue;

            /* DUPLICATE_CLOSE_SOURCE with DesiredAccess=0 closes the source
             * handle in the owner process without needing a target. */
            (VOID)ZwDuplicateObject(
                hOwner,
                (HANDLE)h->HandleValue,
                NULL, NULL,
                0, 0,
                0x00000004 /* DUPLICATE_CLOSE_SOURCE */);

            KdPrint(("[MidnightSoftwareDriver] HandleStrip: closed handle 0x%llX "
                     "(access=0x%X) in PID %llu\n",
                     (unsigned long long)h->HandleValue,
                     h->GrantedAccess,
                     (unsigned long long)h->UniqueProcessId));

            ZwClose(hOwner);
        }

        ExFreePoolWithTag(qbuf, 'prtS');
        ObDereferenceObject(protectedEproc);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// -----------------------------------------------------------------
// ProcExitNotifyCallback (PsSetCreateProcessNotifyRoutineEx)
// -----------------------------------------------------------------
static VOID
ProcExitNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE     ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo != NULL) return;
    LONG64 guarded = InterlockedCompareExchange64(&g_ProtectedPid, 0, 0);
    if (guarded != 0 && (ULONG_PTR)ProcessId == (ULONG_PTR)guarded) {
        InterlockedExchange64(&g_ProtectedPid, 0);
        KdPrint(("[MidnightSoftwareDriver] Protected process PID %llu exited\n",
                 (unsigned long long)(ULONG_PTR)ProcessId));
    }
}

static NTSTATUS
DxgHookedIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code   = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf    = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS   status      = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR  information = 0;

    switch (code)
    {
    // ── ECHO / connectivity test ──────────────────────────────────────────
    case MidnightSoftware_MAGIC_ECHO:
    {
        static const UCHAR k_Tag[4] = { 'D', 'F', 'X', 0 };
        ULONG echoBytes;

        if (outLen >= 4 + inLen && inLen > 0)
        {
            RtlMoveMemory((PUCHAR)buf + 4, buf, inLen);
            RtlCopyMemory(buf, k_Tag, 4);
            echoBytes = 4 + inLen;
        }
        else
        {
            echoBytes = min(inLen, outLen);
        }

        KdPrint(("[MidnightSoftwareDriver] ECHO via DXG hook – %u bytes\n", echoBytes));
        status      = STATUS_SUCCESS;
        information = echoBytes;
        break;
    }

    // ── READ MEMORY ──────────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_READ_MEM:
    {
        PREAD_MEMORY_REQUEST req;
        HANDLE    pid;
        PVOID     srcAddr;
        SIZE_T    requested;
        SIZE_T    copied = 0;

        if (inLen < sizeof(READ_MEMORY_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        req       = (PREAD_MEMORY_REQUEST)buf;
        pid       = (HANDLE)(ULONG_PTR)req->ProcessId;
        srcAddr   = (PVOID)req->Address;
        requested = req->Size;

        if (requested == 0 || requested > MidnightSoftware_MAX_BUFFER) { status = STATUS_INVALID_PARAMETER; break; }
        if (outLen < (ULONG)requested)                       { status = STATUS_BUFFER_TOO_SMALL;  break; }

        /* sysBuffer doubles as output – safe to overwrite after params are saved */
        status = CopyFromProcess(pid, srcAddr, buf, requested, &copied);
        information = (ULONG_PTR)copied;   /* always report bytes transferred */
        if (copied == requested) status = STATUS_SUCCESS;
        break;
    }

    // ── WRITE MEMORY ─────────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_WRITE_MEM:
    {
        PWRITE_MEMORY_REQUEST req;
        HANDLE pid;
        PVOID  dstAddr;
        SIZE_T dataSize;
        SIZE_T copied = 0;

        if (inLen < sizeof(WRITE_MEMORY_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        req      = (PWRITE_MEMORY_REQUEST)buf;
        pid      = (HANDLE)(ULONG_PTR)req->ProcessId;
        dstAddr  = (PVOID)req->Address;
        dataSize = req->Size;

        if (dataSize == 0 || dataSize > MidnightSoftware_MAX_BUFFER) { status = STATUS_INVALID_PARAMETER; break; }
        if (inLen < (ULONG)(sizeof(WRITE_MEMORY_REQUEST) + dataSize)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        status = CopyToProcess(pid, dstAddr, (PUCHAR)buf + sizeof(WRITE_MEMORY_REQUEST), dataSize, &copied);
        information = (ULONG_PTR)copied;   /* always report bytes transferred */
        if (copied == dataSize) status = STATUS_SUCCESS;
        break;
    }

    // ── ENUM PROCESSES ───────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_ENUM_PROCS:
    {
        ULONG  querySize = 256 * 1024;
        PVOID  queryBuf  = NULL;
        NTSTATUS qs      = STATUS_UNSUCCESSFUL;
        int    retries   = 0;
        ULONG  needed    = 0;
        PPROCESS_ENTRY outEntries;
        ULONG  maxCount;
        ULONG  count;
        PUCHAR cursor;
        PMY_SYSTEM_PROCESS_INFO entry;

        do {
            queryBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, querySize, 'xfeD');
            if (!queryBuf) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
            needed = 0;
            qs = ZwQuerySystemInformation(5, queryBuf, querySize, &needed);
            if (qs == STATUS_INFO_LENGTH_MISMATCH) {
                ExFreePoolWithTag(queryBuf, 'xfeD');
                queryBuf  = NULL;
                querySize = needed + 4096;
            }
            retries++;
        } while (qs == STATUS_INFO_LENGTH_MISMATCH && retries < 8);

        if (status == STATUS_INSUFFICIENT_RESOURCES) break;
        if (!NT_SUCCESS(qs)) { if (queryBuf) ExFreePoolWithTag(queryBuf, 'xfeD'); status = qs; break; }

        outEntries = (PPROCESS_ENTRY)buf;
        maxCount   = outLen / sizeof(PROCESS_ENTRY);
        count      = 0;
        cursor     = (PUCHAR)queryBuf;

        for (;;) {
            entry = (PMY_SYSTEM_PROCESS_INFO)cursor;
            if (count < maxCount) {
                ULONG i;
                ULONG nameChars;
                outEntries[count].ProcessId = (ULONG_PTR)entry->UniqueProcessId;
                if (entry->ImageName.Length > 0 && entry->ImageName.Buffer != NULL) {
                    nameChars = entry->ImageName.Length / sizeof(WCHAR);
                    if (nameChars >= 255) nameChars = 255;
                    for (i = 0; i < nameChars; i++)
                        outEntries[count].ImageName[i] = (CHAR)entry->ImageName.Buffer[i];
                    outEntries[count].ImageName[nameChars] = '\0';
                } else {
                    RtlCopyMemory(outEntries[count].ImageName, "System Idle Process", 20);
                }
                count++;
            }
            if (entry->NextEntryOffset == 0) break;
            cursor += entry->NextEntryOffset;
        }
        ExFreePoolWithTag(queryBuf, 'xfeD');
        information = count * sizeof(PROCESS_ENTRY);
        status = STATUS_SUCCESS;
        break;
    }

    // ── QUERY REGIONS ────────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_QUERY_REGS:
    {
        PQUERY_REGIONS_REQUEST req;
        HANDLE     pid;
        PEPROCESS  targetProcess = NULL;
        HANDLE     hProcess      = NULL;
        PREGION_ENTRY outEntries;
        ULONG      maxCount;
        ULONG      count;
        PVOID      addr;
        SIZE_T     retLen;
        MEMORY_BASIC_INFORMATION mbi;

        if (inLen < sizeof(QUERY_REGIONS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        req = (PQUERY_REGIONS_REQUEST)buf;
        pid = (HANDLE)(ULONG_PTR)req->ProcessId;

        status = PsLookupProcessByProcessId(pid, &targetProcess);
        if (!NT_SUCCESS(status)) break;

        status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL,
                                       (ACCESS_MASK)0x0400, *PsProcessType, KernelMode, &hProcess);
        ObDereferenceObject(targetProcess);
        if (!NT_SUCCESS(status)) break;

        outEntries = (PREGION_ENTRY)buf;
        maxCount   = outLen / sizeof(REGION_ENTRY);
        count      = 0;
        addr       = (PVOID)0x1000;

        while (count < maxCount) {
            retLen = 0;
            RtlZeroMemory(&mbi, sizeof(mbi));
            status = ZwQueryVirtualMemory(hProcess, addr, MemoryBasicInformation,
                                          &mbi, sizeof(mbi), &retLen);
            if (!NT_SUCCESS(status)) break;

            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS)) {
                outEntries[count].Base    = (ULONG_PTR)mbi.BaseAddress;
                outEntries[count].Size    = mbi.RegionSize;
                outEntries[count].Protect = mbi.Protect;
                count++;
            }
            {
                ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                if (next <= (ULONG_PTR)addr || next >= 0x00007FFFFFFFFFFF) break;
                addr = (PVOID)next;
            }
        }
        ZwClose(hProcess);
        information = count * sizeof(REGION_ENTRY);
        status = STATUS_SUCCESS;
        break;
    }

    // ── GET CR3 ──────────────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_GET_CR3:
    {
        PGET_CR3_REQUEST  req;
        GET_CR3_RESPONSE  resp;
        PEPROCESS         targetProcess = NULL;

        if (inLen < sizeof(GET_CR3_REQUEST))  { status = STATUS_BUFFER_TOO_SMALL;  break; }
        if (outLen < sizeof(GET_CR3_RESPONSE)){ status = STATUS_BUFFER_TOO_SMALL;  break; }

        req = (PGET_CR3_REQUEST)buf;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &targetProcess);
        if (!NT_SUCCESS(status)) break;

        RtlZeroMemory(&resp, sizeof(resp));
        resp.Cr3Value     = GetProcessCr3(targetProcess);
        resp.UserCr3Value = GetProcessUserCr3(targetProcess);
        ObDereferenceObject(targetProcess);

        RtlCopyMemory(buf, &resp, sizeof(resp));
        information = sizeof(GET_CR3_RESPONSE);
        status = STATUS_SUCCESS;
        KdPrint(("[MidnightSoftwareDriver] GET_CR3 pid=%llu cr3=0x%016llX user_cr3=0x%016llX\n",
                 (unsigned long long)req->ProcessId,
                 (unsigned long long)resp.Cr3Value,
                 (unsigned long long)resp.UserCr3Value));
        break;
    }

    // ── QUEUE_APC / ALLOC_MEM / FREE_MEM / ENUM_MODS / PROTECT_MEM ─────────────
    //
    // All five handlers are implemented in ioctl_handlers.c.
    // They use KeStackAttachProcess + ZwCurrentProcess() (ALLOC/FREE/ENUM/PROTECT)
    // and KeInitializeApc + KeInsertQueueApc + KeAlertThread (QUEUE_APC).
    // ─────────────────────────────────────────────────────────────────────────────
    case MidnightSoftware_MAGIC_QUEUE_APC:
        status = DHDispatch(code, buf, inLen, buf, outLen, &information);
        break;

    case MidnightSoftware_MAGIC_ALLOC_MEM:
        status = DHDispatch(code, buf, inLen, buf, outLen, &information);
        break;

    case MidnightSoftware_MAGIC_FREE_MEM:
        status = DHDispatch(code, buf, inLen, buf, outLen, &information);
        break;

    case MidnightSoftware_MAGIC_ENUM_MODS:
        status = DHDispatch(code, buf, inLen, buf, outLen, &information);
        break;

    case MidnightSoftware_MAGIC_PROTECT_MEM:
        status = DHDispatch(code, buf, inLen, buf, outLen, &information);
        break;

    // -----------------------------------------------------------------
    // MidnightSoftware_MAGIC_PROTECT_PROC
    //   Registers / unregisters the ObRegisterCallbacks guard on a PID.
    //   First call with a non-zero PID installs the callbacks global.
    //   Call with ProcessId == 0 to clear the protected PID (callbacks
    //   remain registered until DriverUnload to avoid re-registration cost).
    // -----------------------------------------------------------------
    case MidnightSoftware_MAGIC_PROTECT_PROC: {
        if (inLen < sizeof(PROTECT_PROC_REQUEST_K)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PPROTECT_PROC_REQUEST_K req = (PPROTECT_PROC_REQUEST_K)buf;
        ULONG_PTR newPid = req->ProcessId;

        // Register callbacks on first invocation with a valid PID
        if (!g_ObCallbackHandle && newPid != 0) {
            OB_CALLBACK_REGISTRATION   cbReg  = { 0 };
            OB_OPERATION_REGISTRATION  opReg  = { 0 };
            UNICODE_STRING             altStr;

            RtlInitUnicodeString(&altStr, L"321000");

            opReg.ObjectType             = PsProcessType;
            opReg.Operations             = OB_OPERATION_HANDLE_CREATE
                                         | OB_OPERATION_HANDLE_DUPLICATE;
            opReg.PreOperation           = ProcProtectPreCallback;
            opReg.PostOperation          = NULL;

            cbReg.Version                      = OB_FLT_REGISTRATION_VERSION;
            cbReg.OperationRegistrationCount   = 1;
            cbReg.RegistrationContext          = NULL;
            cbReg.Altitude                     = altStr;
            cbReg.OperationRegistration        = &opReg;

            NTSTATUS cbStatus = ObRegisterCallbacks(&cbReg, &g_ObCallbackHandle);
            if (!NT_SUCCESS(cbStatus)) {
                KdPrint(("[MidnightSoftwareDriver] ObRegisterCallbacks failed: 0x%08X\n", cbStatus));
                status = cbStatus;
                break;
            }
            KdPrint(("[MidnightSoftwareDriver] ObRegisterCallbacks installed (PID=%llu)\n",
                     (unsigned long long)newPid));
        }

        // Atomically update the guarded PID
        InterlockedExchange64(&g_ProtectedPid, (LONG64)newPid);
        KdPrint(("[MidnightSoftwareDriver] Protected PID set to %llu\n",
                 (unsigned long long)newPid));

        // -------------------------------------------------------------------
        // Register PsSetCreateProcessNotifyRoutineEx (once)
        // so g_ProtectedPid is auto-cleared when the process exits.
        // -------------------------------------------------------------------
        if (!g_ProcNotifyReg) {
            NTSTATUS notifyStatus = PsSetCreateProcessNotifyRoutineEx(
                ProcExitNotifyCallback, FALSE);
            if (NT_SUCCESS(notifyStatus)) {
                g_ProcNotifyReg = TRUE;
                KdPrint(("[MidnightSoftwareDriver] PsSetCreateProcessNotifyRoutineEx registered\n"));
            } else {
                KdPrint(("[MidnightSoftwareDriver] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n",
                         notifyStatus));
            }
        }

        // -------------------------------------------------------------------
        // Start the handle-stripping kernel thread (once, on first protect).
        // The thread runs forever until g_HandleStripStop is signalled in
        // DriverUnload, closing any external handle with PROC_DUMP_ACCESS
        // every 1 second.
        // -------------------------------------------------------------------
        if (!g_HandleStripThread && newPid != 0) {
            HANDLE hThread = NULL;
            NTSTATUS tSt = PsCreateSystemThread(
                &hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                HandleStripThread, NULL);
            if (NT_SUCCESS(tSt)) {
                ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS,
                    *PsThreadType, KernelMode,
                    (PVOID *)&g_HandleStripThread, NULL);
                ZwClose(hThread);
                KdPrint(("[MidnightSoftwareDriver] HandleStripThread started\n"));
            } else {
                KdPrint(("[MidnightSoftwareDriver] HandleStripThread start failed: 0x%08X\n", tSt));
            }
        }

        // -------------------------------------------------------------------
        // Patch EPROCESS.Protection  →  PPL WinTcb-Light (0x61)
        // This makes the kernel itself block any OpenProcess/DuplicateHandle
        // call that requests debug/read/write access, BEFORE our ObCallback
        // even fires.  Task Manager, MiniDumpWriteDump, x64dbg, Cheat Engine
        // all fail at the kernel gate – no user-mode code path circumvents it.
        //
        // 0x61 = { Type=PsProtectedTypeProtectedLight(1), Signer=WinTcb(6) }
        //      = (6 << 4) | 1
        //
        // We discover the offset once (DiscoverProtectionOffset) and cache.
        // On unprotect (newPid == 0) we restore the original value.
        // -------------------------------------------------------------------
        if (newPid != 0) {
            PEPROCESS targetProc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)newPid, &targetProc))) {

                /* Discover offset the first time */
                if (g_EprocProtectionOff == 0)
                    g_EprocProtectionOff = DiscoverProtectionOffset();

                if (g_EprocProtectionOff != 0) {
                    PUCHAR ep  = (PUCHAR)targetProc;
                    PUCHAR prot = ep + g_EprocProtectionOff;

                    /* Only patch if currently unprotected to avoid fighting with OS */
                    if (*prot == 0x00) {
                        *prot = 0x61;   /* PPL WinTcb-Light */
                        KdPrint(("[MidnightSoftwareDriver] EPROCESS.Protection patched to 0x61 (PPL WinTcb) for PID %llu\n",
                                 (unsigned long long)newPid));
                    } else {
                        KdPrint(("[MidnightSoftwareDriver] EPROCESS.Protection already 0x%02X for PID %llu, skipping\n",
                                 (ULONG)*prot, (unsigned long long)newPid));
                    }
                } else {
                    KdPrint(("[MidnightSoftwareDriver] Protection offset unknown – PPL patch skipped\n"));
                }

                ObDereferenceObject(targetProc);
            } else {
                KdPrint(("[MidnightSoftwareDriver] PsLookupProcessByProcessId(%llu) failed for PPL patch\n",
                         (unsigned long long)newPid));
            }
        }

        information = 0;
        status      = STATUS_SUCCESS;
        break;
    }

    default:
        /* Not our code – forward to the real dxgkrnl handler transparently */
        if (g_OrigDxgIoControl)
            return g_OrigDxgIoControl(DeviceObject, Irp);

        Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    KdPrint(("[MidnightSoftwareDriver] DXG hook dispatch code=0x%08X status=0x%08X info=%llu\n",
             code, status, (unsigned long long)information));

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
 * InstallDxgHook – finds dxgkrnl's DRIVER_OBJECT and swaps the
 * IRP_MJ_DEVICE_CONTROL pointer with our stub (data hook, no code patching).
 */
static NTSTATUS
InstallDxgHook(VOID)
{
    UNICODE_STRING   driverName;
    NTSTATUS         status;
    PDRIVER_DISPATCH original;

    if (InterlockedCompareExchange(&g_HookActive, 1, 0) != 0)
    {
        KdPrint(("[MidnightSoftwareDriver] DXG hook already installed\n"));
        return STATUS_SUCCESS;  /* idempotent */
    }

    RtlInitUnicodeString(&driverName, L"\\Driver\\dxgkrnl");

    status = ObReferenceObjectByName(
        &driverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID *)&g_DxgDriverObj
    );

    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&g_HookActive, 0);
        KdPrint(("[MidnightSoftwareDriver] ObReferenceObjectByName(dxgkrnl) failed: 0x%08X\n", status));
        return status;
    }

    /* Atomically swap the dispatch pointer – pure data hook */
    original = (PDRIVER_DISPATCH)InterlockedExchangePointer(
        (PVOID *)&g_DxgDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (PVOID)DxgHookedIoControl
    );
    g_OrigDxgIoControl = original;

    KdPrint(("[MidnightSoftwareDriver] DXG data-hook installed. Original dispatch: %p\n", original));
    return STATUS_SUCCESS;
}

/*
 * RemoveDxgHook – restores the original dispatch pointer and releases the
 * dxgkrnl DRIVER_OBJECT reference.
 */
static NTSTATUS
RemoveDxgHook(VOID)
{
    if (InterlockedCompareExchange(&g_HookActive, 0, 1) != 1)
    {
        KdPrint(("[MidnightSoftwareDriver] DXG hook not installed – nothing to remove\n"));
        return STATUS_NOT_FOUND;
    }

    if (g_DxgDriverObj && g_OrigDxgIoControl)
    {
        InterlockedExchangePointer(
            (PVOID *)&g_DxgDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL],
            (PVOID)g_OrigDxgIoControl
        );
        ObDereferenceObject(g_DxgDriverObj);
        g_DxgDriverObj     = NULL;
        g_OrigDxgIoControl = NULL;
    }

    KdPrint(("[MidnightSoftwareDriver] DXG data-hook removed\n"));
    return STATUS_SUCCESS;
}

// ─────────────────────────────────────────────────────────────────
// CR3 / Physical-memory helpers
// ─────────────────────────────────────────────────────────────────

// =================================================================
// Dynamic EPROCESS offset discovery + CR3 validation
// =================================================================

/*
 * DiscoverEprocessOffsets
 *
 * Called once from DriverEntry while executing in the System process
 * context (PID 4).  At this point __readcr3() returns the EXACT value
 * that the scheduler loaded into CR3 for the System process.
 *
 * Strategy:
 *   1. Read the live hardware CR3 via __readcr3().
 *   2. Walk PsInitialSystemProcess (EPROCESS) in 8-byte steps looking
 *      for a QWORD that, with low 12 bits masked, matches hwCr3.
 *   3. That offset is g_DirBaseOffset – the field the scheduler uses,
 *      regardless of what any anti-cheat thinks is the "right" offset.
 *   4. The immediately-following QWORD, if it looks like a valid CR3
 *      (page-aligned, non-zero, below 512 GB), is UserDirectoryTableBase.
 *   5. Cache g_SysCr3 and read PML4[256..259] as the kernel-space
 *      signature used later by FindRealCr3ByPml4Scan / ValidateCr3.
 *
 * Falls back to Windows 10 defaults (0x28 / 0x30) if discovery fails
 * (which should never happen on any real Windows 10+ build).
 */
static NTSTATUS
DiscoverEprocessOffsets(VOID)
{
    ULONG_PTR  hwCr3;
    PEPROCESS  sysProc;
    PUCHAR     base;
    ULONG      off;

    // __readcr3() gives the exact PML4 physical base loaded by the scheduler.
    hwCr3   = (ULONG_PTR)__readcr3() & ~0xFFFull;
    sysProc = PsInitialSystemProcess;
    base    = (PUCHAR)sysProc;

    for (off = 0x10; off <= 0x500; off += 8)
    {
        ULONG_PTR val = *(ULONG_PTR *)(base + off);
        if ((val & ~0xFFFull) == hwCr3)
        {
            ULONG_PTR uval;

            g_DirBaseOffset = off;
            g_SysCr3        = hwCr3;

            // Check the next QWORD for UserDirectoryTableBase (KPTI).
            uval = *(ULONG_PTR *)(base + off + 8);
            if ((uval & 0xFFFull) == 0 && uval != 0 && uval < 0x8000000000ull)
                g_UserDirBaseOffset = off + 8;
            else
                g_UserDirBaseOffset = 0;    // KPTI absent or will be resolved per-process

            // Cache PML4[256..259] as a 4-entry kernel-space signature.
            // All processes share kernel PML4 entries; this uniquely identifies
            // a valid PML4 page during physical memory scan.
            //
            // On systems with HVCI / VBS / Hyper-V enabled, MmCopyMemory
            // (MM_COPY_MEMORY_PHYSICAL) may fail for hypervisor-protected
            // page-table pages.  Fall back to MmMapIoSpace (which asks the
            // hypervisor to create a temporary VA mapping) when necessary.
            {
                ULONG i;
                BOOLEAN sigOk = FALSE;

                // Primary path: MmCopyMemory (no persistent PTE).
                for (i = 0; i < 4; i++)
                {
                    ULONG_PTR entry = 0;
                    ReadPhysQword(hwCr3 + (256 + i) * 8, &entry);
                    g_SysPml4Sig[i] = entry;
                    if (entry != 0) sigOk = TRUE;
                }

                // Fallback: if all 4 entries came back as 0 (MmCopyMemory
                // blocked by hypervisor), use MmMapIoSpace to map the 4 KB
                // PML4 page and read entries directly from the VA.
                if (!sigOk)
                {
                    PHYSICAL_ADDRESS pa;
                    PULONG_PTR       mapped;

                    pa.QuadPart = (LONGLONG)hwCr3;
                    mapped = (PULONG_PTR)MmMapIoSpace(pa, PAGE_SIZE, MmCached);
                    if (mapped)
                    {
                        for (i = 0; i < 4; i++)
                            g_SysPml4Sig[i] = mapped[256 + i];
                        MmUnmapIoSpace(mapped, PAGE_SIZE);
                        KdPrint(("[MidnightSoftwareDriver] PML4 sig captured via MmMapIoSpace "
                                 "(MmCopyMemory was blocked)\n"));
                    }
                    else
                    {
                        KdPrint(("[MidnightSoftwareDriver] WARNING: PML4 sig capture failed "
                                 "(both MmCopyMemory and MmMapIoSpace blocked).\n"
                                 "  ValidateCr3 will rely on min-address + Present-bit "
                                 "checks only.\n"));
                    }
                }
            }

            KdPrint(("[MidnightSoftwareDriver] EPROCESS offsets discovered: DirBase=+0x%X "
                     "UserDirBase=%s(+0x%X) CR3=0x%016llX\n",
                     g_DirBaseOffset,
                     g_UserDirBaseOffset ? "" : "absent ",
                     g_UserDirBaseOffset,
                     (unsigned long long)hwCr3));
            return STATUS_SUCCESS;
        }
    }

    // Should never reach here on any supported Windows build.
    KdPrint(("[MidnightSoftwareDriver] WARNING: dynamic offset discovery failed, "
             "falling back to 0x28/0x30\n"));
    g_SysCr3 = hwCr3;
    return STATUS_SUCCESS;   // non-fatal; fallback values already set
}

/*
 * ValidateCr3
 *
 * Quick sanity check: does <Cr3> look like a real x64 PML4 base?
 *
 * Checks performed:
 *   1. Non-zero and page-aligned.
 *   2. PML4[256] is readable and has the Present bit set (every live
 *      process must have kernel mappings).
 *   3. PML4[256..259] match the cached System-process signature.
 *      Because all processes share the kernel half of the PML4, a page
 *      with a different upper-half cannot be a valid process PML4.
 *
 * Returns FALSE if any check fails.
 */
static BOOLEAN
ValidateCr3(ULONG_PTR Cr3)
{
    ULONG     i;
    ULONG_PTR entry;

    if (Cr3 == 0 || (Cr3 & 0xFFFull) != 0)
        return FALSE;

    // Sanity: real Windows PML4 pages are NEVER allocated in the first 16 MB.
    // That region is reserved for legacy BIOS, real-mode IVT, ACPI tables, etc.
    // A value like 0x2000 here means either the anti-cheat spoofed the field or
    // DiscoverEprocessOffsets landed on the wrong EPROCESS offset.
    // Accepting it would make Cr3VirtToPhys walk BIOS memory → all reads fail.
    if (Cr3 < 0x1000000ull)
        return FALSE;

    // PML4[256] must be readable and Present.
    if (!ReadPhysQword(Cr3 + 256 * 8, &entry))
        return FALSE;
    if (!(entry & 1))
        return FALSE;

    // Signature match against System process PML4[256..259].
    // Skip if signature was not captured (discovery failed).
    if (g_SysPml4Sig[0] != 0)
    {
        for (i = 0; i < 4; i++)
        {
            ULONG_PTR sig = 0;
            if (!ReadPhysQword(Cr3 + (256 + i) * 8, &sig))
                return FALSE;
            if (sig != g_SysPml4Sig[i])
                return FALSE;
        }
    }

    return TRUE;
}

// =================================================================
// CR3 per-PID cache helpers
// =================================================================

/*
 * CacheStoreCr3 – insert or update the (Pid, Cr3, UserCr3) tuple.
 *   - If a slot with matching Pid exists it is overwritten.
 *   - If there is an empty slot (Pid==0) it is used.
 *   - If all slots are occupied the slot selected by a global round-robin
 *     counter is evicted (cheap, no need for LRU tracking).
 */
static VOID
CacheStoreCr3(ULONG_PTR Pid, ULONG_PTR Cr3, ULONG_PTR UserCr3)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0 || Cr3 == 0) return;

    KeAcquireSpinLock(&g_Cr3CacheLock, &oldIrql);

    for (i = 0; i < CR3_CACHE_CAP; i++)
    {
        if (g_Cr3Cache[i].Pid == 0 || g_Cr3Cache[i].Pid == Pid)
        {
            g_Cr3Cache[i].Pid     = Pid;
            g_Cr3Cache[i].Cr3     = Cr3;
            g_Cr3Cache[i].UserCr3 = UserCr3;
            KeReleaseSpinLock(&g_Cr3CacheLock, oldIrql);
            return;
        }
    }

    // All slots full – round-robin eviction.
    {
        ULONG slot = (ULONG)InterlockedIncrement(&g_Cr3CacheEvict) % CR3_CACHE_CAP;
        g_Cr3Cache[slot].Pid     = Pid;
        g_Cr3Cache[slot].Cr3     = Cr3;
        g_Cr3Cache[slot].UserCr3 = UserCr3;
    }

    KeReleaseSpinLock(&g_Cr3CacheLock, oldIrql);
}

/*
 * CacheLookupCr3 – look up (Cr3, UserCr3) by Pid.
 * Returns TRUE and fills the out-parameters if found, FALSE otherwise.
 * Thread-safe; acquires the spinlock for the duration of the search.
 */
static BOOLEAN
CacheLookupCr3(ULONG_PTR Pid, PULONG_PTR Cr3Out, PULONG_PTR UserCr3Out)
{
    KIRQL   oldIrql;
    ULONG   i;
    BOOLEAN found = FALSE;

    if (Pid == 0) return FALSE;

    KeAcquireSpinLock(&g_Cr3CacheLock, &oldIrql);

    for (i = 0; i < CR3_CACHE_CAP; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid)
        {
            *Cr3Out = g_Cr3Cache[i].Cr3;
            if (UserCr3Out) *UserCr3Out = g_Cr3Cache[i].UserCr3;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_Cr3CacheLock, oldIrql);
    return found;
}

/*
 * CacheInvalidatePid – remove the entry for Pid from the cache.
 * Called when ValidateCr3 fails on a cached value (process exited or
 * anti-cheat rotated the page-table base again).
 */
static VOID
CacheInvalidatePid(ULONG_PTR Pid)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_Cr3CacheLock, &oldIrql);

    for (i = 0; i < CR3_CACHE_CAP; i++)
    {
        if (g_Cr3Cache[i].Pid == Pid)
        {
            g_Cr3Cache[i].Pid     = 0;
            g_Cr3Cache[i].Cr3     = 0;
            g_Cr3Cache[i].UserCr3 = 0;
            break;
        }
    }

    KeReleaseSpinLock(&g_Cr3CacheLock, oldIrql);
}

// =================================================================
// Physical-memory PML4 scan helpers
// =================================================================

/*
 * ScanRangesForPml4 – internal: scan the physical address range [FromPhys, ToPhys)
 * looking for a 4 KB-aligned page that passes ValidateCr3 AND has at least one
 * present user-space PML4 entry (index 0..127).  Excludes the System process CR3.
 *
 * Called twice by FindRealCr3ByPml4Scan:
 *   pass 1 – fast  [0, 4 GB): PML4 pages are almost always allocated here.
 *   pass 2 – slow  [4 GB, MAX): rare fallback for fragmented high-RAM systems.
 *
 * Physical memory ranges are assumed sorted in ascending address order
 * (MmGetPhysicalMemoryRanges guarantees this).
 */
static ULONG_PTR
ScanRangesForPml4(PPHYSICAL_MEMORY_RANGE Ranges, ULONG_PTR FromPhys, ULONG_PTR ToPhys)
{
    ULONG     i;
    ULONG_PTR found = 0;

    for (i = 0; !found; i++)
    {
        ULONG_PTR rangeBase, rangeEnd, phys;

        if (Ranges[i].BaseAddress.QuadPart == 0 &&
            Ranges[i].NumberOfBytes.QuadPart == 0)
            break;    // terminator

        rangeBase = (ULONG_PTR)Ranges[i].BaseAddress.QuadPart;
        rangeEnd  = rangeBase + (ULONG_PTR)Ranges[i].NumberOfBytes.QuadPart;

        // Entirely below our window – skip
        if (rangeEnd <= FromPhys) continue;
        // Entirely above our window – stop (ranges are sorted)
        if (rangeBase >= ToPhys)  break;

        // Clamp to [FromPhys, ToPhys)
        if (rangeBase < FromPhys) rangeBase = FromPhys;
        if (rangeEnd  > ToPhys)   rangeEnd  = ToPhys;

        for (phys = (rangeBase + 0xFFFull) & ~0xFFFull;
             phys < rangeEnd;
             phys += PAGE_SIZE)
        {
            BOOLEAN hasUser;
            ULONG   j;

            if (phys == g_SysCr3)  continue;
            if (!ValidateCr3(phys)) continue;

            // Require at least one Present PML4 entry in the user half (0..127).
            // The System process has no user-space mappings, so this filter
            // excludes it even if another code path already missed g_SysCr3.
            hasUser = FALSE;
            for (j = 0; j < 128 && !hasUser; j++)
            {
                ULONG_PTR e = 0;
                if (ReadPhysQword(phys + j * 8, &e) && (e & 1))
                    hasUser = TRUE;
            }
            if (!hasUser) continue;

            found = phys;
            break;
        }
    }

    return found;
}

/*
 * FindRealCr3ByPml4Scan – last-resort: find the real PML4 base of
 * TargetProcess by scanning physical memory when EPROCESS is spoofed.
 *
 * Two-pass strategy:
 *   Pass 1 (fast)  – scans [0, 4 GB).  On almost all systems (even
 *                    machines with 64 GB RAM) the kernel allocates PML4
 *                    pages in low physical memory.  Typical scan time:
 *                    <5 ms once a cache warm-up fill has happened.
 *   Pass 2 (slow)  – scans [4 GB, ULONG_PTR_MAX).  Runs only if pass 1
 *                    found nothing.  Covers heavily-fragmented systems
 *                    where the allocator placed the PML4 in high RAM.
 *
 * The returned address is NOT stored in the cache here; callers (GetProcessCr3)
 * are responsible for caching after they validate the return value.
 */
static ULONG_PTR
FindRealCr3ByPml4Scan(PEPROCESS TargetProcess)
{
    PPHYSICAL_MEMORY_RANGE ranges;
    ULONG_PTR              found;
    // Capture identity early so TargetProcess is referenced unconditionally
    // even in release builds where KdPrint expands to nothing (avoids C4100).
    ULONG_PTR              logPid  = (ULONG_PTR)PsGetProcessId(TargetProcess);
    PVOID                  logProc = (PVOID)TargetProcess;
    UNREFERENCED_PARAMETER(logPid);
    UNREFERENCED_PARAMETER(logProc);

    if (g_SysCr3 == 0) return 0;

    ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return 0;

    // Pass 1 – fast (0 .. 4 GB)
    found = ScanRangesForPml4(ranges, 0, 0x100000000ull);

    // Pass 2 – slow (4 GB .. max), only if pass 1 came up empty.
    if (!found)
    {
        KdPrint(("[MidnightSoftwareDriver] PML4 fast scan (0-4 GB) found nothing, "
                 "trying full scan above 4 GB ...\n"));
        found = ScanRangesForPml4(ranges, 0x100000000ull, (ULONG_PTR)(-1));
    }

    ExFreePool(ranges);

    if (found)
        KdPrint(("[MidnightSoftwareDriver] PML4 scan: found CR3=0x%016llX "
                 "for process %p (pid=%llu)\n",
                 (unsigned long long)found, logProc, (unsigned long long)logPid));
    else
        KdPrint(("[MidnightSoftwareDriver] PML4 scan: no PML4 found for process %p\n",
                 logProc));

    return found;
}

/*
 * GetProcessCr3 – return the kernel DirectoryTableBase (PML4 physical base)
 *                 for <Process>.
 *
 * Lookup order (fast to slow):
 *   1. Per-PID cache       – O(32) spinlock read   ≈ 0 µs
 *   2. EPROCESS field      – single pointer deref   ≈ 0 µs  + ValidateCr3
 *   3. PML4 physical scan  – 0-4 GB pass then 4 GB+ ≈ 1-50 ms  (runs ONCE,
 *                            result stored in cache so step 1 wins every
 *                            subsequent call for the same PID)
 */
static ULONG_PTR
GetProcessCr3(PEPROCESS Process)
{
    ULONG_PTR pid    = (ULONG_PTR)PsGetProcessId(Process);
    ULONG_PTR cached = 0, dummy = 0;
    ULONG_PTR cr3;

    // 1. Cache hit (hot path – thousands of calls per second from ESP/aimbot)
    if (CacheLookupCr3(pid, &cached, &dummy))
    {
        if (ValidateCr3(cached))
            return cached;
        // Stale: process exited or AC rotated the PML4 base.
        KdPrint(("[MidnightSoftwareDriver] GetProcessCr3: cached CR3=0x%016llX stale for pid=%llu, evicting\n",
                 (unsigned long long)cached, (unsigned long long)pid));
        CacheInvalidatePid(pid);
    }

    // 2. EPROCESS->DirectoryTableBase (dynamic offset, resolved at load time)
    cr3 = *(ULONG_PTR *)((PUCHAR)Process + g_DirBaseOffset) & ~0xFFFull;

    if (ValidateCr3(cr3))
    {
        // Also read and cache the user CR3 while we have the process object.
        ULONG_PTR ucr3 = 0;
        if (g_UserDirBaseOffset)
        {
            ucr3 = *(ULONG_PTR *)((PUCHAR)Process + g_UserDirBaseOffset) & ~0xFFFull;
            if (!ValidateCr3(ucr3)) ucr3 = 0;
        }
        CacheStoreCr3(pid, cr3, ucr3);
        return cr3;
    }

    // 3. Spoofed field – last resort: scan physical memory.
    KdPrint(("[MidnightSoftwareDriver] GetProcessCr3: EPROCESS+0x%X = 0x%016llX invalid, "
             "starting PML4 scan for pid=%llu\n",
             g_DirBaseOffset, (unsigned long long)cr3, (unsigned long long)pid));

    cr3 = FindRealCr3ByPml4Scan(Process);
    if (cr3 && ValidateCr3(cr3))
    {
        CacheStoreCr3(pid, cr3, 0);
        return cr3;
    }

    KdPrint(("[MidnightSoftwareDriver] GetProcessCr3: all methods failed for pid=%llu\n",
             (unsigned long long)pid));
    return 0;
}

/*
 * GetProcessUserCr3 – return the UserDirectoryTableBase (KPTI user PML4).
 *
 * Also cache-aware: if the kernel CR3 is already cached (from GetProcessCr3)
 * we update the same cache entry with the user CR3, avoiding a second
 * spinlock acquisition / EPROCESS read on the next call.
 */
static ULONG_PTR
GetProcessUserCr3(PEPROCESS Process)
{
    ULONG_PTR pid         = (ULONG_PTR)PsGetProcessId(Process);
    ULONG_PTR dummy       = 0;
    ULONG_PTR cachedUcr3  = 0;
    ULONG_PTR val;

    // 1. Cache hit
    if (CacheLookupCr3(pid, &dummy, &cachedUcr3))
    {
        if (cachedUcr3 != 0 && ValidateCr3(cachedUcr3))
            return cachedUcr3;
        // cachedUcr3 == 0 means "KPTI absent or not yet probed" – fall through.
    }

    // 2. Offset not yet discovered – lazy probe.
    if (g_UserDirBaseOffset == 0)
    {
        ULONG probe;
        for (probe = g_DirBaseOffset + 8;
             probe <= g_DirBaseOffset + 24;
             probe += 8)
        {
            ULONG_PTR candidate = *(ULONG_PTR *)((PUCHAR)Process + probe) & ~0xFFFull;
            if (candidate != 0 && ValidateCr3(candidate) &&
                candidate != (*(ULONG_PTR *)((PUCHAR)Process + g_DirBaseOffset) & ~0xFFFull))
            {
                KdPrint(("[MidnightSoftwareDriver] GetProcessUserCr3: discovered UserDirBase at +0x%X\n",
                         probe));
                g_UserDirBaseOffset = probe;
                break;
            }
        }
        if (g_UserDirBaseOffset == 0)
            return 0;   // KPTI genuinely absent on this system
    }

    val = *(ULONG_PTR *)((PUCHAR)Process + g_UserDirBaseOffset) & ~0xFFFull;
    if (val == 0 || !ValidateCr3(val))
        return 0;

    // Update cache entry (kernel CR3 must already be cached from GetProcessCr3).
    {
        ULONG_PTR kcr3 = 0;
        if (CacheLookupCr3(pid, &kcr3, &dummy) && kcr3 != 0)
            CacheStoreCr3(pid, kcr3, val);
    }
    return val;
}

/*
 * ReadPhysQword – read 8 physical bytes at physAddr into *outValue.
 *
 * Uses MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) instead of MmMapIoSpace so
 * that no persistent system PTE mapping is created.  MmCopyMemory was
 * introduced in Windows 8.1 and is always available on Windows 10+.
 * Returns FALSE if the copy fails (page not accessible).
 */
static BOOLEAN
ReadPhysQword(ULONG_PTR physAddr, PULONG_PTR outValue)
{
    MM_COPY_ADDRESS src;
    SIZE_T          bytesCopied = 0;
    NTSTATUS        status;

    src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    status = MmCopyMemory(outValue, src, sizeof(ULONG_PTR),
                          MM_COPY_MEMORY_PHYSICAL, &bytesCopied);
    return NT_SUCCESS(status) && (bytesCopied == sizeof(ULONG_PTR));
}

/*
 * Cr3VirtToPhys – 4-level page-table walk to translate a virtual address
 *                 to its physical address using an explicit CR3 value.
 *
 * Handles:
 *   1 GB huge pages   (PDPTE with PS=1)
 *   2 MB large pages  (PDE  with PS=1)
 *   4 KB normal pages (full PML4 → PDPT → PD → PT walk)
 *
 * Returns 0 if any level is not-present or mapping fails.
 *
 * x64 page-table index layout for a virtual address:
 *   [47:39] PML4 index
 *   [38:30] PDPT index
 *   [29:21] PD   index
 *   [20:12] PT   index
 *   [11: 0] byte offset within 4 KB page
 */
static ULONG_PTR
Cr3VirtToPhys(ULONG_PTR Cr3, ULONG_PTR Va)
{
    ULONG_PTR entry  = 0;
    ULONG_PTR table;

    // ── PML4 ──────────────────────────────────────────────────────────
    table = (Cr3 & ~0xFFFull) + ((Va >> 39) & 0x1FF) * 8;
    if (!ReadPhysQword(table, &entry)) return 0;
    if (!(entry & 1)) return 0;                    // not-present

    // ── PDPT ──────────────────────────────────────────────────────────
    table = (entry & 0x000FFFFFFFFFF000ull) + ((Va >> 30) & 0x1FF) * 8;
    if (!ReadPhysQword(table, &entry)) return 0;
    if (!(entry & 1)) return 0;

    if (entry & (1ull << 7))                       // 1 GB huge page (PS=1)
        return (entry & 0x000FFFFFC0000000ull) + (Va & 0x3FFFFFFFull);

    // ── PD ────────────────────────────────────────────────────────────
    table = (entry & 0x000FFFFFFFFFF000ull) + ((Va >> 21) & 0x1FF) * 8;
    if (!ReadPhysQword(table, &entry)) return 0;
    if (!(entry & 1)) return 0;

    if (entry & (1ull << 7))                       // 2 MB large page (PS=1)
        return (entry & 0x000FFFFFFFE00000ull) + (Va & 0x1FFFFFull);

    // ── PT ────────────────────────────────────────────────────────────
    table = (entry & 0x000FFFFFFFFFF000ull) + ((Va >> 12) & 0x1FF) * 8;
    if (!ReadPhysQword(table, &entry)) return 0;
    if (!(entry & 1)) return 0;

    return (entry & 0x000FFFFFFFFFF000ull) + (Va & 0xFFFull);
}

/*
 * ReadPhysBuffer – copy <Size> bytes from physical address <PhysAddr> into
 *                  kernel-mode <Buffer>.
 *
 * Uses MmCopyMemory(MM_COPY_MEMORY_PHYSICAL): does not allocate system PTEs
 * and leaves no persistent footprint visible to anti-cheat PTE scanners.
 * Returns bytes actually copied (0 on failure).
 */
static SIZE_T
ReadPhysBuffer(ULONG_PTR PhysAddr, PVOID Buffer, SIZE_T Size)
{
    MM_COPY_ADDRESS src;
    SIZE_T          bytesCopied = 0;

    src.PhysicalAddress.QuadPart = (LONGLONG)PhysAddr;
    MmCopyMemory(Buffer, src, Size, MM_COPY_MEMORY_PHYSICAL, &bytesCopied);
    return bytesCopied;
}

/*
 * WritePhysBuffer – write <Size> bytes from <Buffer> to physical address
 *                   <PhysAddr>.
 *
 * MmMapIoSpace is restricted on Windows 10 21H2+ for normal PFN-managed RAM
 * pages (returns NULL).  Instead we use MDL PFN injection:
 *   1. Allocate an MDL sized for the pages spanned by the write.
 *   2. Manually populate the MDL's PFN array with the target physical frame(s).
 *   3. Mark the MDL as MDL_PAGES_LOCKED so MmMapLockedPagesSpecifyCache does
 *      not attempt to lock pages through a VA and accepts our PFN array as-is.
 *   4. Map into kernel VA, write, then unmap and free.
 *
 * This avoids: MmMapIoSpace (blocked for RAM), MmCopyVirtualMemory
 * (AC-monitored), KeStackAttachProcess (KTHREAD artifact).
 * Returns bytes actually written (0 on mapping failure).
 */
static SIZE_T
WritePhysBuffer(ULONG_PTR PhysAddr, PVOID Buffer, SIZE_T Size)
{
    ULONG_PTR   pageOffset = PhysAddr & 0xFFFull;
    ULONG_PTR   frameBase  = PhysAddr & ~0xFFFull;
    PFN_NUMBER  basePfn    = (PFN_NUMBER)(frameBase >> PAGE_SHIFT);
    ULONG       pages      = (ULONG)(((pageOffset + Size) + PAGE_SIZE - 1) >> PAGE_SHIFT);
    PMDL        mdl;
    PVOID       mapped;
    PPFN_NUMBER pfnArr;
    ULONG       i;

    if (Size == 0) return 0;

    /* Allocate MDL; pass NULL VA so IoAllocateMdl does not probe user memory.
     * We need MDL header + room for 'pages' PFN entries. */
    mdl = IoAllocateMdl(NULL, pages * PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl) return 0;

    /* Override ByteOffset so the returned mapped VA lands on PhysAddr,
     * and ByteCount to the actual write size.  The PFN array slot count
     * was determined by IoAllocateMdl's size argument above and is
     * consistent with ADDRESS_AND_SIZE_TO_SPAN_PAGES(pageOffset, Size). */
    mdl->ByteOffset = (ULONG)pageOffset;
    mdl->ByteCount  = (ULONG)Size;

    /* MDL_PAGES_LOCKED: tells the MM the PFNs are already valid and resident.
     * No MmProbeAndLockPages call is needed or wanted. */
    mdl->MdlFlags |= MDL_PAGES_LOCKED;

    pfnArr = MmGetMdlPfnArray(mdl);
    for (i = 0; i < pages; ++i)
        pfnArr[i] = basePfn + i;

    /* Map into kernel VA (no NX bit → NormalPagePriority | MdlMappingNoExecute
     * would be cleaner but isn't needed for a write-only mapping). */
    mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mapped)
    {
        IoFreeMdl(mdl);
        return 0;
    }

    RtlCopyMemory((PUCHAR)mapped + pageOffset, Buffer, Size);

    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);
    return Size;
}

/*
 * ReadMemoryCr3 – read <Size> bytes at virtual address <Va> in the address
 *                 space identified by <Cr3>, page by page.
 *
 * Pages that are not-present are zero-filled; the function sets
 * STATUS_PARTIAL_COPY when fewer bytes than requested could be accessed.
 */
static NTSTATUS
ReadMemoryCr3(ULONG_PTR Cr3, ULONG_PTR Va, PVOID Buffer, SIZE_T Size, PSIZE_T Copied)
{
    SIZE_T  done = 0;
    PUCHAR  dst  = (PUCHAR)Buffer;

    while (done < Size)
    {
        ULONG_PTR curVa      = Va + done;
        ULONG_PTR pageOffset = curVa & 0xFFFull;
        SIZE_T    chunk      = min(Size - done, (SIZE_T)(PAGE_SIZE - pageOffset));
        ULONG_PTR phys       = Cr3VirtToPhys(Cr3, curVa);

        if (phys == 0)
        {
            /* Not-present / translation failure – stop here, do not zero-fill.
             * Silently zero-filling and continuing would produce fake "success"
             * (the caller sees STATUS_SUCCESS + all-zero bytes) and hides
             * the real failure from diagnostics. */
            break;
        }
        else
        {
            SIZE_T didRead = ReadPhysBuffer(phys, dst + done, chunk);
            if (didRead == 0) break;    /* MmCopyMemory failed – stop */
        }
        done += chunk;
    }

    *Copied = done;
    return (done == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

/*
 * WriteMemoryCr3 – write <Size> bytes from <Buffer> to virtual address <Va>
 *                  in the address space identified by <Cr3>, page by page.
 *
 * Returns STATUS_PARTIAL_COPY if a page is not-present (write is skipped for
 * that page and the loop stops on first failure).
 */
static NTSTATUS
WriteMemoryCr3(ULONG_PTR Cr3, ULONG_PTR Va, PVOID Buffer, SIZE_T Size, PSIZE_T Copied)
{
    SIZE_T  done = 0;
    PUCHAR  src  = (PUCHAR)Buffer;

    while (done < Size)
    {
        ULONG_PTR curVa      = Va + done; //азвщазвщазвщ курва
        ULONG_PTR pageOffset = curVa & 0xFFFull;
        SIZE_T    chunk      = min(Size - done, (SIZE_T)(PAGE_SIZE - pageOffset));
        ULONG_PTR phys       = Cr3VirtToPhys(Cr3, curVa);

        if (phys == 0) break;   /* not-present – abort */

        SIZE_T didWrite = WritePhysBuffer(phys, src + done, chunk);
        if (didWrite == 0) break;
        done += chunk;
    }

    *Copied = done;
    return (done == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

/*
 * CopyFromProcess – read <Size> bytes from virtual address <SourceAddress>
 *                   in the process identified by <ProcessId> into kernel-mode
 *                   <Buffer>.
 *
 * Uses KeStackAttachProcess to run in the target process's address space,
 * then copies page-by-page under __try/__except so that any inaccessible
 * page stops the loop without crashing the system.
 *
 * This approach is reliable across all Windows 10/11 configurations
 * (KPTI on/off, VBS/HVCI on/off, Hyper-V present/absent) because it lets
 * the kernel's own page-fault handler resolve demand-zero, copy-on-write,
 * and paged-out pages.
 */
static NTSTATUS
CopyFromProcess(HANDLE ProcessId, PVOID SourceAddress, PVOID Buffer, SIZE_T Size, PSIZE_T Copied)
{
    PEPROCESS  sourceProcess = NULL;
    KAPC_STATE apcState;
    NTSTATUS   status;
    SIZE_T     done;
    ULONG_PTR  curVA;
    ULONG_PTR  pageOff;
    SIZE_T     chunk;

    *Copied = 0;
    done    = 0;
    status  = STATUS_SUCCESS;

    if (Size == 0) return STATUS_SUCCESS;

    status = PsLookupProcessByProcessId(ProcessId, &sourceProcess);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)sourceProcess, &apcState);

    while (done < Size)
    {
        curVA   = (ULONG_PTR)SourceAddress + done;
        pageOff = curVA & 0xFFFull;
        chunk   = Size - done;
        if (chunk > (SIZE_T)(PAGE_SIZE - pageOff))
            chunk = (SIZE_T)(PAGE_SIZE - pageOff);

        __try
        {
            ProbeForRead((PVOID)curVA, chunk, 1);
            RtlCopyMemory((PUCHAR)Buffer + done, (PVOID)curVA, chunk);
            done += chunk;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(sourceProcess);

    *Copied = done;
    return (done == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

/*
 * CopyToProcess – write <Size> bytes from kernel-mode <Buffer> into virtual
 *                 address <TargetAddress> in the process identified by
 *                 <ProcessId>.
 *
 * Same KeStackAttachProcess strategy as CopyFromProcess.  Demand-zero pages
 * (newly ZwAllocateVirtualMemory'd MEM_COMMIT regions) are handled correctly
 * here: the first write to each such page triggers the demand-zero soft fault,
 * the kernel maps the physical frame, and the write completes – no pre-warming
 * loop needed.
 */
static NTSTATUS
CopyToProcess(HANDLE ProcessId, PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T Copied)
{
    PEPROCESS  targetProcess = NULL;
    KAPC_STATE apcState;
    NTSTATUS   status;
    SIZE_T     done;
    ULONG_PTR  curVA;
    ULONG_PTR  pageOff;
    SIZE_T     chunk;

    *Copied = 0;
    done    = 0;
    status  = STATUS_SUCCESS;

    if (Size == 0) return STATUS_SUCCESS;

    status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

    while (done < Size)
    {
        curVA   = (ULONG_PTR)TargetAddress + done;
        pageOff = curVA & 0xFFFull;
        chunk   = Size - done;
        if (chunk > (SIZE_T)(PAGE_SIZE - pageOff))
            chunk = (SIZE_T)(PAGE_SIZE - pageOff);

        __try
        {
            ProbeForWrite((PVOID)curVA, chunk, 1);
            RtlCopyMemory((PVOID)curVA, (PUCHAR)Buffer + done, chunk);
            done += chunk;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;  /* inaccessible / read-only page – stop here */
        }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    *Copied = done;
    return (done == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

// ─────────────────────────────────────────────────────────────────
// IRP dispatch: Create / Close
// ─────────────────────────────────────────────────────────────────
static NTSTATUS
DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------
// IRP dispatch: DeviceIoControl
// Reached when \\.\DXGKrnl is our own alias (no-GPU path).
// Delegates to DxgHookedIoControl - same handler used by the data hook.
// -----------------------------------------------------------------
static NTSTATUS
DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return DxgHookedIoControl(DeviceObject, Irp);
}
// ─────────────────────────────────────────────────────────────────
// DriverUnload
// ─────────────────────────────────────────────────────────────────
static VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* Always clean up the dxgkrnl hook before the driver is gone */
    RemoveDxgHook();

    /* Stop the handle-stripping thread and wait for it to exit */
    if (g_HandleStripThread) {
        KeSetEvent(&g_HandleStripStop, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_HandleStripThread, Executive,
                              KernelMode, FALSE, NULL);
        ObDereferenceObject(g_HandleStripThread);
        g_HandleStripThread = NULL;
        KdPrint(("[MidnightSoftwareDriver] HandleStripThread stopped\n"));
    }

    /* Unregister process-exit notification */
    if (g_ProcNotifyReg) {
        PsSetCreateProcessNotifyRoutineEx(ProcExitNotifyCallback, TRUE);
        g_ProcNotifyReg = FALSE;
        KdPrint(("[MidnightSoftwareDriver] PsSetCreateProcessNotifyRoutineEx unregistered\n"));
    }

    /* Unregister ObCallbacks if we registered them */
    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
        KdPrint(("[MidnightSoftwareDriver] ObRegisterCallbacks unregistered\n"));
    }

    /* Remove the \DosDevices\DXGKrnl alias only if we created it */
    if (g_CreatedDxgLink)
    {
        IoDeleteSymbolicLink(&g_DxgKrnlLink);
        g_CreatedDxgLink = FALSE;
        KdPrint(("[MidnightSoftwareDriver] Removed \\DosDevices\\DXGKrnl symlink\n"));
    }

    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);

    KdPrint(("[MidnightSoftwareDriver] Unloaded\n"));
}

// ─────────────────────────────────────────────────────────────────
// DriverEntry
// ─────────────────────────────────────────────────────────────────
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PUNICODE_STRING devName = &g_DeviceName;  // \Device\DxgKrnl

    KdPrint(("[MidnightSoftwareDriver] DriverEntry called\n"));

    // Initialise the CR3 per-PID cache spinlock before any CR3 access.
    KeInitializeSpinLock(&g_Cr3CacheLock);
    RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));

    // Initialise the handle-strip thread stop event (non-signalled = running).
    KeInitializeEvent(&g_HandleStripStop, NotificationEvent, FALSE);

    // Discover KPROCESS->DirectoryTableBase offset dynamically.
    // Must run first, before any CR3 access, while still in System-process
    // context so __readcr3() returns the System PML4 base.
    DiscoverEprocessOffsets();

    DriverObject->DriverUnload = DriverUnload;

    // -----------------------------------------------------------------
    // Create our device object.
    // Try \Device\DxgKrnl first (matches real dxgkrnl, perfect for no-GPU).
    // If dxgkrnl.sys already claimed that name, fall back to \Device\DxgKrnlGdi.
    // -----------------------------------------------------------------
    status = IoCreateDevice(DriverObject, 0, &g_DeviceName,
                            FILE_DEVICE_MidnightSoftware, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_DeviceObject);

    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        devName = &g_DeviceNameAlt;   // \Device\DxgKrnlGdi
        status  = IoCreateDevice(DriverObject, 0, &g_DeviceNameAlt,
                                 FILE_DEVICE_MidnightSoftware, FILE_DEVICE_SECURE_OPEN,
                                 FALSE, &g_DeviceObject);
    }

    if (!NT_SUCCESS(status)) {
        KdPrint(("[MidnightSoftwareDriver] IoCreateDevice failed: 0x%08X\n", status));
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

    // -----------------------------------------------------------------
    // Create \DosDevices\DXGKrnl -> our device.
    // On modern Windows dxgkrnl.sys does NOT expose this symlink, so
    // IoCreateSymbolicLink succeeds and user-mode CreateFile(\\\\.\\DXGKrnl)
    // reaches our device regardless of whether a GPU is present.
    // If we somehow get a collision, the real dxgkrnl owns the symlink and
    // we'll rely solely on the data hook installed below.
    // -----------------------------------------------------------------
    status = IoCreateSymbolicLink(&g_DxgKrnlLink, devName);
    if (NT_SUCCESS(status))
    {
        g_CreatedDxgLink = TRUE;
        KdPrint(("[MidnightSoftwareDriver] Created \\DosDevices\\DXGKrnl -> %wZ\n", devName));
    }
    else if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        KdPrint(("[MidnightSoftwareDriver] \\DosDevices\\DXGKrnl already exists - hook-only path\n"));
    }
    else
    {
        KdPrint(("[MidnightSoftwareDriver] IoCreateSymbolicLink(DXGKrnl) failed: 0x%08X\n", status));
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    // -----------------------------------------------------------------
    // Optionally install the dxgkrnl data hook (GPU path).
    // This intercepts IRPs that reach dxgkrnl's own device node through
    // any other open handle (e.g. DirectX runtime). Not required for our
    // user-mode channel, which always goes through our own device above.
    // -----------------------------------------------------------------
    {
        NTSTATUS hookStatus = InstallDxgHook();
        if (NT_SUCCESS(hookStatus))
            KdPrint(("[MidnightSoftwareDriver] DXG data-hook installed\n"));
        else
            KdPrint(("[MidnightSoftwareDriver] DXG hook skipped (dxgkrnl absent): 0x%08X\n", hookStatus));
    }

    KdPrint(("[MidnightSoftwareDriver] Loaded - \\\\.\\DXGKrnl ready\n"));
    return STATUS_SUCCESS;
}
