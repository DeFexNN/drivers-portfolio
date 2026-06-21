/*
 * ioctl_handlers.c  -  MidnightSoftwareDriver IOCTL dispatch implementations
 *
 * Handlers for:
 *   MidnightSoftware_MAGIC_QUEUE_APC   - kernel APC + KeAlertThread
 *   MidnightSoftware_MAGIC_ALLOC_MEM   - KeStackAttachProcess + ZwAllocateVirtualMemory
 *   MidnightSoftware_MAGIC_FREE_MEM    - KeStackAttachProcess + ZwFreeVirtualMemory
 *   MidnightSoftware_MAGIC_ENUM_MODS   - KeStackAttachProcess + SEH PEB/Ldr walk
 *
 * Build: EWDK WDK 10, KMDF 1.15, x64, /kernel mode
 *
 * Rules observed throughout:
 *   - No SAL annotations (_In_, _Out_, _Inout_, etc.) on any parameter
 *     in function pointer typedefs or function declarations.  The WDK
 *     /kernel strict-C mode rejects SAL macros that expand to complex
 *     __declspec attributes when placed before pointer-to-typedef params.
 *     Use the empty IN / OUT / OPTIONAL macros (defined as nothing by
 *     the WDK base headers) or omit annotations entirely.
 *   - All local variables declared at the TOP of each block (C89 rule).
 *     The /kernel compile flag enforces this even in C11 mode.
 *   - NTKERNELAPI functions that are already in ntifs.h are NOT
 *     redeclared here to avoid C2491 (dllimport redefinition).
 *     Only symbols absent from this EWDK's ntifs.h are declared below.
 */

#include <ntifs.h>
#include <wdm.h>

/* ── IOCTL codes ────────────────────────────────────────────── */
#define CTL_MidnightSoftware(fn)  CTL_CODE(0x23u,(fn),METHOD_BUFFERED,FILE_ANY_ACCESS)
#define MidnightSoftware_MAGIC_QUEUE_APC  CTL_MidnightSoftware(0x0DE5u)
#define MidnightSoftware_MAGIC_ALLOC_MEM  CTL_MidnightSoftware(0x0DE6u)
#define MidnightSoftware_MAGIC_FREE_MEM   CTL_MidnightSoftware(0x0DE7u)
#define MidnightSoftware_MAGIC_ENUM_MODS  CTL_MidnightSoftware(0x0DE8u)
#define MidnightSoftware_MAGIC_PROTECT_MEM CTL_MidnightSoftware(0x0DE9u)

#define MidnightSoftware_MAX_MODULES 1024

/* ── Request / response structures ─────────────────────────── */
#pragma pack(push,1)
typedef struct _DH_QUEUE_APC_REQUEST {
    ULONG_PTR ProcessId;
    ULONG_PTR ThreadId;
    ULONG_PTR ShellcodeVA;
} DH_QUEUE_APC_REQUEST, *PDH_QUEUE_APC_REQUEST;

typedef struct _DH_ALLOC_MEM_REQUEST {
    ULONG_PTR ProcessId;
    ULONG_PTR PreferredBase;
    SIZE_T    Size;
    ULONG     AllocType;
    ULONG     Protect;
} DH_ALLOC_MEM_REQUEST, *PDH_ALLOC_MEM_REQUEST;

typedef struct _DH_ALLOC_MEM_RESPONSE {
    ULONG_PTR AllocatedBase;
} DH_ALLOC_MEM_RESPONSE, *PDH_ALLOC_MEM_RESPONSE;

typedef struct _DH_FREE_MEM_REQUEST {
    ULONG_PTR ProcessId;
    ULONG_PTR Address;
    SIZE_T    Size;
    ULONG     FreeType;
} DH_FREE_MEM_REQUEST, *PDH_FREE_MEM_REQUEST;

typedef struct _DH_PROTECT_MEM_REQUEST {
    ULONG_PTR ProcessId;  /* target PID */
    ULONG_PTR Address;    /* base VA of the range (page-aligned) */
    SIZE_T    Size;       /* bytes (rounded up to page by OS) */
    ULONG     NewProtect; /* PAGE_EXECUTE_READ / PAGE_READONLY / PAGE_READWRITE / etc. */
} DH_PROTECT_MEM_REQUEST, *PDH_PROTECT_MEM_REQUEST;

typedef struct _DH_ENUM_MODS_REQUEST {
    ULONG_PTR ProcessId;
} DH_ENUM_MODS_REQUEST, *PDH_ENUM_MODS_REQUEST;

typedef struct _DH_MODULE_ENTRY {
    ULONG_PTR BaseAddress;
    CHAR      ModuleName[256];
} DH_MODULE_ENTRY, *PDH_MODULE_ENTRY;
#pragma pack(pop)

/* ── APC callback typedefs (NO SAL, plain IN/OUT empty macros) ─
 *
 * IN / OUT / OPTIONAL are #define'd to nothing by the WDK base
 * headers.  They serve as documentation tokens only.  Using the
 * SAL equivalents (_In_, _Out_, etc.) inside function-pointer
 * typedef parameter lists under /kernel strict mode triggers
 * parser errors (C2143 / C2081 "name in formal parameter list
 * illegal") because the complex __declspec expansions break the
 * C declarator grammar.
 */
typedef enum _KAPC_ENVIRONMENT_DH {
    OriginalApcEnvironment_DH = 0,
    AttachedApcEnvironment_DH,
    CurrentApcEnvironment_DH,
    InsertApcEnvironment_DH
} KAPC_ENVIRONMENT_DH;

/* NormalRoutine: user-mode payload called as fn(ctx, &arg1, &arg2) */
typedef VOID (NTAPI *PKNORMAL_ROUTINE_DH)(
    IN PVOID NormalContext,
    IN OUT PVOID *SystemArgument1,
    IN OUT PVOID *SystemArgument2
);

/* KernelRoutine: fires at APC_LEVEL before NormalRoutine; frees KAPC */
typedef VOID (NTAPI *PKKERNEL_ROUTINE_DH)(
    IN PRKAPC Apc,
    IN OUT PKNORMAL_ROUTINE_DH *NormalRoutine,
    IN OUT PVOID *NormalContext,
    IN OUT PVOID *SystemArgument1,
    IN OUT PVOID *SystemArgument2
);

/* RundownRoutine: fires if thread exits before APC fires; frees KAPC */
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE_DH)(
    IN PRKAPC Apc
);

/*
 * KeInitializeApc - exported from ntoskrnl, absent from this EWDK's ntifs.h.
 * Initialises a KAPC structure for insertion via KeInsertQueueApc.
 */
NTKERNELAPI VOID KeInitializeApc(
    OUT PRKAPC                  Apc,
    IN  PKTHREAD                Thread,
    IN  KAPC_ENVIRONMENT_DH     Environment,
    IN  PKKERNEL_ROUTINE_DH     KernelRoutine,
    IN  PKRUNDOWN_ROUTINE_DH    RundownRoutine OPTIONAL,
    IN  PKNORMAL_ROUTINE_DH     NormalRoutine  OPTIONAL,
    IN  KPROCESSOR_MODE         ApcMode        OPTIONAL,
    IN  PVOID                   NormalContext  OPTIONAL
);

/*
 * KeInsertQueueApc - queues an already-initialised KAPC to its thread.
 * Declared here because ntifs.h in this EWDK build does not expose it
 * at the point where /kernel mode processes it.
 */
NTKERNELAPI BOOLEAN KeInsertQueueApc(
    IN PRKAPC    Apc,
    IN PVOID     SystemArgument1 OPTIONAL,
    IN PVOID     SystemArgument2 OPTIONAL,
    IN KPRIORITY Increment
);

/*
 * KeAlertThread - exported from ntoskrnl, absent from public headers.
 * Transitions the thread to Alert state so a pending user-mode APC fires
 * on the next kernel->user return without needing an alertable wait.
 */
NTKERNELAPI BOOLEAN KeAlertThread(
    IN PKTHREAD        Thread,
    IN KPROCESSOR_MODE AlertMode
);

/*
 * PsGetProcessPeb - exported from ntoskrnl.
 * Returns the user-mode VA of the target process's PEB.
 * Absent from this EWDK build's ntifs.h.
 */
NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

/*
 * ZwProtectVirtualMemory - changes page protection on a VA range.
 * Equivalent to NtProtectVirtualMemory; from kernel mode at PASSIVE_LEVEL
 * both travel the same code path with PreviousMode = KernelMode, bypassing
 * the user-mode access checks that ACs rely on to block ring-3 calls.
 * Not all EWDK builds declare this in ntifs.h; declare manually to be safe.
 */
NTSYSAPI NTSTATUS ZwProtectVirtualMemory(
    IN  HANDLE  ProcessHandle,
    IN OUT PVOID  *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN  ULONG   NewProtect,
    OUT PULONG  OldProtect
);


/* ================================================================
 * DH_ApcKernelRoutine
 *
 * KernelRoutine callback (APC_LEVEL, before NormalRoutine executes).
 * Sole job: free the pool-allocated KAPC.
 * Signature must match PKKERNEL_ROUTINE_DH exactly.
 * ================================================================ */
static VOID NTAPI
DH_ApcKernelRoutine(
    IN PRKAPC Apc,
    IN OUT PKNORMAL_ROUTINE_DH *NormalRoutine,
    IN OUT PVOID *NormalContext,
    IN OUT PVOID *SystemArgument1,
    IN OUT PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}

/* RundownRoutine: thread exited before APC fired. */
static VOID NTAPI
DH_ApcRundownRoutine(IN PRKAPC Apc)
{
    ExFreePool(Apc);
}


/* ================================================================
 * DHHandleQueueApc  -  MidnightSoftware_MAGIC_QUEUE_APC
 *
 * 1. PsLookupThreadByThreadId
 * 2. ExAllocatePool2(NonPagedPool) for KAPC
 * 3. KeInitializeApc (OriginalApcEnvironment, UserMode, shellcode VA)
 * 4. KeInsertQueueApc
 * 5. KeAlertThread - forces APC delivery without alertable wait
 * 6. ObDereferenceObject
 * ================================================================ */
NTSTATUS
DHHandleQueueApc(
    IN  PVOID      InputBuffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    DH_QUEUE_APC_REQUEST req;
    PETHREAD  targetThread;
    PRKAPC    apc;
    NTSTATUS  status;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputLength);

    *BytesWritten = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InputLength < sizeof(req))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&req, InputBuffer, sizeof(req));
    if (req.ThreadId == 0 || req.ShellcodeVA == 0)
        return STATUS_INVALID_PARAMETER;

    /* Step 1: TID -> PETHREAD */
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)req.ThreadId,
                                      &targetThread);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[DH] QUEUE_APC: PsLookupThreadByThreadId(%llu) 0x%08X\n",
                 (unsigned long long)req.ThreadId, status));
        return status;
    }

    /* Step 2: Allocate KAPC from NonPagedPool.
     * Lifetime: from here until DH_ApcKernelRoutine / DH_ApcRundownRoutine
     * fires.  Pool tag 'caHD' aids post-mortem via !poolfind. */
    apc = (PRKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'caHD');
    if (!apc)
    {
        ObDereferenceObject(targetThread);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Step 3: Initialise APC.
     *
     * OriginalApcEnvironment_DH: queue into the thread's home process,
     * not whatever process the calling system thread is attached to.
     *
     * NormalRoutine = ShellcodeVA: ntdll APC dispatcher calls it as
     *   shellcode(NormalContext=NULL, SystemArg1=NULL, SystemArg2=NULL).
     * On x64 this is RCX=NULL, RDX=&NULL, R8=&NULL at shellcode entry.
     * Our shellcode uses `sub rsp, 0x28` for the shadow-space ABI.
     */
    KeInitializeApc(
        apc,
        (PKTHREAD)targetThread,
        OriginalApcEnvironment_DH,
        DH_ApcKernelRoutine,
        DH_ApcRundownRoutine,
        (PKNORMAL_ROUTINE_DH)(ULONG_PTR)req.ShellcodeVA,
        UserMode,
        NULL);

    /* Step 4: Insert into user-mode APC queue.
     * Returns FALSE if thread is terminating or APC queue is disabled. */
    if (!KeInsertQueueApc(apc, NULL, NULL, 0))
    {
        KdPrint(("[DH] QUEUE_APC: KeInsertQueueApc failed TID=%llu\n",
                 (unsigned long long)req.ThreadId));
        ExFreePool(apc);
        ObDereferenceObject(targetThread);
        return STATUS_UNSUCCESSFUL;
    }

    /* Step 5: Alert the thread.
     *
     * A user-mode APC fires only when the thread is in an ALERTABLE wait
     * (SleepEx / WaitForSingleObjectEx with bAlertable=TRUE).  Game
     * threads almost never do this.  KeAlertThread sets KTHREAD.Alerted
     * and unblocks any current wait with STATUS_ALERTED, so the APC drains
     * on the next kernel->user return (interrupt return, I/O completion...).
     *
     * This replaces ring-3 NtAlertThread (needs THREAD_ALERT which AC
     * ObRegisterCallbacks strips from game threads). */
    KeAlertThread((PKTHREAD)targetThread, UserMode);

    /* Step 6 */
    ObDereferenceObject(targetThread);

    KdPrint(("[DH] QUEUE_APC OK  TID=%llu  shellcode=0x%016llX\n",
             (unsigned long long)req.ThreadId,
             (unsigned long long)req.ShellcodeVA));
    return STATUS_SUCCESS;
}


/* ================================================================
 * DHHandleAllocMem  -  MidnightSoftware_MAGIC_ALLOC_MEM
 *
 * Attaches to the target process via KeStackAttachProcess and allocates
 * MEM_PRIVATE pages using ZwAllocateVirtualMemory(ZwCurrentProcess()).
 *
 * ZwCurrentProcess() pseudo-handle (-1) resolves to the currently
 * attached PEPROCESS with zero handle table entries - invisible to
 * NtQuerySystemInformation(SystemHandleInformation) AC scans.
 * ================================================================ */
NTSTATUS
DHHandleAllocMem(
    IN  PVOID      InputBuffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    DH_ALLOC_MEM_REQUEST  req;
    DH_ALLOC_MEM_RESPONSE resp;
    PEPROCESS  targetProcess;
    KAPC_STATE apcState;
    PVOID      baseAddress;
    SIZE_T     regionSize;
    NTSTATUS   status;
    /*
     * warmPtr / warmOff: used to pre-touch every committed page so that
     * demand-zero PTEs (present=0) get physical frames assigned before
     * CopyToProcess / WriteMemoryCr3 tries to walk the page table.
     * ZwAllocateVirtualMemory with MEM_COMMIT creates demand-zero pages
     * whose PTEs say "committed" but have no physical address until first
     * access.  Cr3VirtToPhys returns 0 on present=0 entries, causing every
     * DrvWriteMem call to fail with STATUS_PARTIAL_COPY immediately.
     */
    PUCHAR     warmPtr;
    SIZE_T     warmOff;

    *BytesWritten = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InputLength  < sizeof(req))  return STATUS_BUFFER_TOO_SMALL;
    if (OutputLength < sizeof(resp)) return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&req, InputBuffer, sizeof(req));

    if (req.Size == 0 || req.Size > (SIZE_T)(512 * 1024 * 1024))
        return STATUS_INVALID_PARAMETER;

    /* Force committed pages so shellcode is immediately writable */
    if (!(req.AllocType & MEM_COMMIT))
        req.AllocType |= MEM_COMMIT;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId,
                                        &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

    baseAddress = (PVOID)(ULONG_PTR)req.PreferredBase;
    regionSize  = (SIZE_T)req.Size;

    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        (ULONG)req.AllocType,
        (ULONG)req.Protect);

    /*
     * Pre-warm: touch the first byte of every committed 4 KB page while
     * still attached.  This triggers the demand-zero fault for each page,
     * causing the memory manager to assign a real physical frame and mark
     * the PTE present=1.  Without this touch, WriteMemoryCr3 (which walks
     * the physical page tables directly) sees present=0 and returns 0 for
     * every page, making every DrvWriteMem call fail with STATUS_PARTIAL_COPY.
     *
     * Wrapped in __try/__except: if any page is inaccessible (e.g. on a
     * system with low non-paged pool), we abort cleanly rather than BSOD.
     */
    if (NT_SUCCESS(status))
    {
        warmPtr = (PUCHAR)baseAddress;
        __try
        {
            for (warmOff = 0; warmOff < regionSize; warmOff += PAGE_SIZE)
                warmPtr[warmOff] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KdPrint(("[DH] ALLOC_MEM: pre-warm fault 0x%08X at off 0x%llX – continuing\n",
                     GetExceptionCode(), (unsigned long long)warmOff));
            /* Page warming is best-effort; the allocation itself succeeded. */
        }
    }

    KeUnstackDetachProcess(&apcState);   /* always, even on failure */
    ObDereferenceObject(targetProcess);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("[DH] ALLOC_MEM: ZwAllocVA 0x%08X  pid=%llu\n",
                 status, (unsigned long long)req.ProcessId));
        return status;
    }

    RtlZeroMemory(&resp, sizeof(resp));
    resp.AllocatedBase = (ULONG_PTR)baseAddress;
    RtlCopyMemory(OutputBuffer, &resp, sizeof(resp));
    *BytesWritten = sizeof(resp);

    KdPrint(("[DH] ALLOC_MEM: pid=%llu  base=0x%016llX  size=0x%llX  prot=0x%X\n",
             (unsigned long long)req.ProcessId,
             (unsigned long long)baseAddress,
             (unsigned long long)regionSize,
             req.Protect));
    return STATUS_SUCCESS;
}


/* ================================================================
 * DHHandleFreeMem  -  MidnightSoftware_MAGIC_FREE_MEM
 * ================================================================ */
NTSTATUS
DHHandleFreeMem(
    IN  PVOID      InputBuffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    DH_FREE_MEM_REQUEST req;
    PEPROCESS  targetProcess;
    KAPC_STATE apcState;
    PVOID      baseAddress;
    SIZE_T     regionSize;
    NTSTATUS   status;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputLength);

    *BytesWritten = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InputLength < sizeof(req))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&req, InputBuffer, sizeof(req));
    if (req.Address == 0)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId,
                                        &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

    baseAddress = (PVOID)(ULONG_PTR)req.Address;
    regionSize  = (SIZE_T)req.Size;

    status = ZwFreeVirtualMemory(
        ZwCurrentProcess(),
        &baseAddress,
        &regionSize,
        (ULONG)req.FreeType);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    if (NT_SUCCESS(status))
        KdPrint(("[DH] FREE_MEM: pid=%llu  addr=0x%016llX\n",
                 (unsigned long long)req.ProcessId,
                 (unsigned long long)req.Address));
    return status;
}


/* ================================================================
 * DHHandleProtectMem  -  MidnightSoftware_MAGIC_PROTECT_MEM
 *
 * Changes the page protection of a VA range in the target process.
 * Uses KeStackAttachProcess + ZwProtectVirtualMemory(ZwCurrentProcess())
 * with a kernel-mode pseudo-handle so that no user-mode
 * PROCESS_VM_OPERATION right is required and ObRegisterCallbacks
 * AC stripping is bypassed.
 *
 * Why this matters (UC consensus):
 *   Allocating the DLL image as PAGE_EXECUTE_READWRITE is the #1
 *   heuristic AC scanners (EAC, Vanguard) use to detect manual mappers.
 *   Legitimate MEM_PRIVATE memory almost never has W+X simultaneously.
 *   The correct pattern is:
 *     1. Allocate as PAGE_READWRITE.
 *     2. Write the fixed-up image sections.
 *     3. Call PROTECT_MEM once per section with the section's proper
 *        protection (.text -> PAGE_EXECUTE_READ, .rdata -> PAGE_READONLY,
 *        .data/.bss -> PAGE_READWRITE).
 *   This makes the mapped DLL indistinguishable in the VAD tree from a
 *   normally loaded module (each section has the correct protection).
 * ================================================================ */
NTSTATUS
DHHandleProtectMem(
    IN  PVOID      InputBuffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    DH_PROTECT_MEM_REQUEST req;
    PEPROCESS  targetProcess;
    KAPC_STATE apcState;
    PVOID      baseAddress;
    SIZE_T     regionSize;
    ULONG      oldProtect;
    NTSTATUS   status;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputLength);

    *BytesWritten = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InputLength < sizeof(req))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&req, InputBuffer, sizeof(req));
    if (req.Address == 0 || req.Size == 0)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId,
                                        &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

    baseAddress = (PVOID)(ULONG_PTR)req.Address;
    regionSize  = (SIZE_T)req.Size;
    oldProtect  = 0;

    status = ZwProtectVirtualMemory(
        ZwCurrentProcess(),
        &baseAddress,
        &regionSize,
        (ULONG)req.NewProtect,
        &oldProtect);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    if (NT_SUCCESS(status))
        KdPrint(("[DH] PROTECT_MEM: pid=%llu  addr=0x%016llX  size=0x%llX"
                 "  new=0x%X  old=0x%X\n",
                 (unsigned long long)req.ProcessId,
                 (unsigned long long)req.Address,
                 (unsigned long long)req.Size,
                 req.NewProtect, oldProtect));
    else
        KdPrint(("[DH] PROTECT_MEM: ZwProtectVA 0x%08X  pid=%llu  addr=0x%016llX\n",
                 status,
                 (unsigned long long)req.ProcessId,
                 (unsigned long long)req.Address));
    return status;
}


/* ================================================================
 * DHHandleEnumMods  -  MidnightSoftware_MAGIC_ENUM_MODS
 *
 * Walks PEB->Ldr->InLoadOrderModuleList while attached to the
 * target process.  Full SEH wraps every user-space dereference.
 *
 * BSOD safety: PEB/LDR pages are user-mode paged VA.  A paged-out
 * pointer accessed from kernel context raises STATUS_ACCESS_VIOLATION
 * as a structured exception.  Without __try/__except this propagates
 * to KeBugCheckEx (BSOD).
 *
 * C89 rule: ALL locals declared at the top of the enclosing block,
 * before ANY statements.  Mixed declaration-and-code is rejected by
 * the WDK /kernel compiler even under /std:c11.
 *
 * x64 offsets (stable, all Win10 builds):
 *   PEB     +0x18  PPEB_LDR_DATA Ldr
 *   LDR     +0x10  LIST_ENTRY InLoadOrderModuleList (Flink)
 *   ENTRY   +0x00  LIST_ENTRY.Flink -> next entry
 *   ENTRY   +0x30  PVOID DllBase
 *   ENTRY   +0x58  USHORT BaseDllName.Length
 *   ENTRY   +0x60  PWSTR  BaseDllName.Buffer
 * ================================================================ */
NTSTATUS
DHHandleEnumMods(
    IN  PVOID      InputBuffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    DH_ENUM_MODS_REQUEST req;
    PEPROCESS    targetProcess;
    KAPC_STATE   apcState;
    PPEB         pebVA;
    PDH_MODULE_ENTRY outEntries;
    ULONG        maxEntries;
    ULONG        count;
    NTSTATUS     status;
    /* All inner walk variables declared here to satisfy C89 */
    ULONG_PTR    ldrAddr;
    ULONG_PTR    listHeadVA;
    ULONG_PTR    flink;
    ULONG_PTR    entryVA;
    ULONG_PTR    dllBase;
    ULONG_PTR    nameBuf;
    ULONG_PTR    nextFlink;
    USHORT       nameLen;
    ULONG        nChars;
    ULONG        i;
    ULONG        iteration;
    PWCHAR       wName;

    *BytesWritten = 0;
    count         = 0;
    status        = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (InputLength < sizeof(req))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&req, InputBuffer, sizeof(req));
    if (req.ProcessId == 0)
        return STATUS_INVALID_PARAMETER;

    maxEntries = OutputLength / (ULONG)sizeof(DH_MODULE_ENTRY);
    if (maxEntries == 0)
        return STATUS_BUFFER_TOO_SMALL;

    outEntries = (PDH_MODULE_ENTRY)OutputBuffer;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId,
                                        &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    /* PsGetProcessPeb returns the PEB VA from EPROCESS without attaching */
    pebVA = PsGetProcessPeb(targetProcess);
    if (pebVA == NULL)
    {
        ObDereferenceObject(targetProcess);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess((PKPROCESS)targetProcess, &apcState);

    ldrAddr    = 0;
    listHeadVA = 0;
    flink      = 0;
    iteration  = 0;

    __try
    {
        /* PEB->Ldr at offset 0x18 */
        ProbeForRead((PVOID)((ULONG_PTR)pebVA + 0x18),
                     sizeof(ULONG_PTR), sizeof(ULONG_PTR));
        ldrAddr = *(ULONG_PTR *)((ULONG_PTR)pebVA + 0x18);

        if (ldrAddr == 0)
        {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        /* InLoadOrderModuleList.Flink at LDR+0x10 */
        listHeadVA = ldrAddr + 0x10;
        ProbeForRead((PVOID)listHeadVA, sizeof(ULONG_PTR), sizeof(ULONG_PTR));
        flink = *(ULONG_PTR *)listHeadVA;

        while (flink != 0           &&
               flink != listHeadVA  &&
               count < maxEntries   &&
               iteration < 2048)
        {
            ++iteration;

            entryVA  = flink;
            dllBase  = 0;
            nameLen  = 0;
            nameBuf  = 0;
            nChars   = 0;

            /* Validate the entire relevant range of the LDR entry */
            ProbeForRead((PVOID)entryVA, 0x68, sizeof(ULONG_PTR));

            dllBase = *(ULONG_PTR *)(entryVA + 0x30);
            nameLen = *(USHORT    *)(entryVA + 0x58);
            nameBuf = *(ULONG_PTR *)(entryVA + 0x60);

            if (dllBase != 0 && nameLen > 0 &&
                nameLen <= 512 && nameBuf != 0)
            {
                nChars = (ULONG)(nameLen / sizeof(WCHAR));
                if (nChars > 255) nChars = 255;

                ProbeForRead((PVOID)nameBuf, nameLen, sizeof(WCHAR));

                wName = (PWCHAR)nameBuf;
                RtlZeroMemory(outEntries[count].ModuleName,
                              sizeof(outEntries[count].ModuleName));

                for (i = 0; i < nChars; ++i)
                {
                    WCHAR wc = wName[i];
                    outEntries[count].ModuleName[i] =
                        (wc < 0x80) ? (CHAR)wc : '?';
                }

                outEntries[count].BaseAddress = dllBase;
                ++count;
            }

            /* Advance Flink (InLoadOrderLinks at entry+0x00) */
            ProbeForRead((PVOID)entryVA, sizeof(ULONG_PTR), sizeof(ULONG_PTR));
            nextFlink = *(ULONG_PTR *)entryVA;
            if (nextFlink == flink) break;
            flink = nextFlink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /*
         * User-space pointer invalid: page swapped out, guard page,
         * freed region, or corrupted PEB.  Return partial results.
         */
        KdPrint(("[DH] ENUM_MODS: SEH 0x%08X after %lu entries  pid=%llu\n",
                 GetExceptionCode(), count,
                 (unsigned long long)req.ProcessId));
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    *BytesWritten = (ULONG_PTR)(count * sizeof(DH_MODULE_ENTRY));

    KdPrint(("[DH] ENUM_MODS: pid=%llu  modules=%lu\n",
             (unsigned long long)req.ProcessId, count));
    return status;
}


/* ================================================================
 * DHDispatch  -  router called from DxgHookedIoControl
 *
 * Called in place of the inline case blocks for:
 *   MidnightSoftware_MAGIC_QUEUE_APC, ALLOC_MEM, FREE_MEM, ENUM_MODS
 * ================================================================ */
NTSTATUS
DHDispatch(
    IN  ULONG      IoctlCode,
    IN  PVOID      Buffer,
    IN  ULONG      InputLength,
    OUT PVOID      OutputBuffer,
    IN  ULONG      OutputLength,
    OUT PULONG_PTR BytesWritten)
{
    switch (IoctlCode)
    {
        case MidnightSoftware_MAGIC_QUEUE_APC:
            return DHHandleQueueApc(Buffer, InputLength,
                                    OutputBuffer, OutputLength, BytesWritten);
        case MidnightSoftware_MAGIC_ALLOC_MEM:
            return DHHandleAllocMem(Buffer, InputLength,
                                    OutputBuffer, OutputLength, BytesWritten);
        case MidnightSoftware_MAGIC_FREE_MEM:
            return DHHandleFreeMem(Buffer, InputLength,
                                   OutputBuffer, OutputLength, BytesWritten);
        case MidnightSoftware_MAGIC_PROTECT_MEM:
            return DHHandleProtectMem(Buffer, InputLength,
                                      OutputBuffer, OutputLength, BytesWritten);
        case MidnightSoftware_MAGIC_ENUM_MODS:
            return DHHandleEnumMods(Buffer, InputLength,
                                    OutputBuffer, OutputLength, BytesWritten);
        default:
            *BytesWritten = 0;
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}
