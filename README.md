# 🛡️ Drivers Portfolio — Kernel Security Engineering Suite

A production-grade Windows kernel driver ecosystem for privileged memory access,
process protection, DSE bypass, manual mapping, and secure loader architecture.
Built with WDK/MSVC, protected with VMProtect, and authenticated via Firebase.

> *"The line between a driver and a rootkit is the intent of its author."*

---

## Philosophy

This portfolio demonstrates **defense-in-depth at every layer** — from kernel memory
primitives that actively avoid anti-cheat detection patterns, to user-mode loaders
with IAT-hiding, runtime API resolution, and compile-time string obfuscation.

Every design decision is intentional:
- **No `KeStackAttachProcess`** — leaves artifacts in `KTHREAD.ApcState` that anti-cheats scan for
- **CR3-based physical page walks** — bypasses VAD-based detection of `MmMapIoSpace`
- **Data hooks, not code hooks** — `InterlockedExchangePointer` on dxgkrnl dispatch table, not inline patches
- **No plaintext API names** — all Win32/d3d11/BCrypt imports resolved at runtime with XOR-encrypted strings
- **Fresh AES key per build** — embedded payloads re-encrypted by `encrypt_bins.ps1`, keys never committed

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  driver_loader.exe  (VMProtect-protected, ImGui + D3D11 GUI)    │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ Auth UI  │  │  DSE     │  │  Driver Load │  │  Payload    │ │
│  │ Firebase │  │  Bypass  │  │  via SCM     │  │  Launch +   │ │
│  │ key check│  │ kvc.sys  │  │  Create/Start│  │  Protection │ │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └──────┬──────┘ │
│       │              │              │                  │        │
│  ┌────┴──────────────┴──────────────┴──────────────────┴──────┐ │
│  │  lazy_api.hpp  ·  embedded.hpp  ·  string_obf.hpp          │ │
│  │  Runtime API resolution  ·  AES-256 decryption  ·  OBF     │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
        │                                    │
   SCM Load                            Manual Map
        │                                    │
┌───────┴────────┐              ┌─────────────┴──────────────────┐
│ MidnightSoftware │              │  driver_manual_mapper.exe      │
│ Driver.sys      │              │                                │
│                 │              │  PE Parser → Relocations →     │
│ • CR3 page walk│              │  Remote IAT → Kernel APC →     │
│ • Physical mem  │              │  PEB Ldr Link → TLS Init       │
│ • dxgkrnl hook  │              │                                │
│ • Process prot. │              │  3160 lines of academic-grade  │
│ • PPL patching  │              │  manual mapping logic          │
│ • Handle strip  │              └────────────────────────────────┘
└─────────────────┘
```

---

## Code Examples

### CR3-Based Physical Memory Read (Kernel)

```c
// Walk x64 4-level page tables to translate virtual → physical, then 
// MmCopyMemory(MM_COPY_MEMORY_PHYSICAL). No KeStackAttachProcess.
NTSTATUS ReadMemoryCr3(UINT64 cr3, UINT64 va, PVOID buffer, SIZE_T size) {
    // PML4 → PDPT → PD → PT
    UINT64 phys = cr3 & ~0xFFF;
    for (int level = 4; level > 0; level--) {
        phys = ReadPhysicalQword(phys + PML4E_OFFSET(va, level));
        if (!(phys & 1)) return STATUS_UNSUCCESSFUL;  // not present
        if (level > 1 && (phys & (1 << 7))) break;     // huge page
    }
    return MmCopyMemory(buffer, phys + PAGE_OFFSET(va), size,
                        MM_COPY_MEMORY_PHYSICAL, &copied);
}
```

### dxgkrnl Pointer Swap (Kernel)

```c
// No code patching — pure data-hook via InterlockedExchangePointer.
// Non-magic IOCTLs forwarded transparently to the original handler.
old_dispatch = InterlockedExchangePointer(
    (PVOID*)&dxg_device->StackSize,
    MidnightSoftwareDispatch);

// Dispatch: check magic code, if not ours, forward:
if (IoControlCode != MidnightSoftware_MAGIC_ECHO && old_dispatch)
    return old_dispatch(DeviceObject, Irp);
```

### Compile-Time String Obfuscation (C++20)

```cpp
// Unique XOR key per literal, Xorshift32 from __TIME__ + __COUNTER__.
// Volatile reads defeat compiler constant folding.
consteval auto encrypt(const char* s, size_t n, uint32_t key) {
    obfuscated_string result{};
    for (size_t i = 0; i < n; i++) {
        key = xorshift32(key);
        result.data[i] = static_cast<char>(s[i] ^ (key & 0xFF));
    }
    return result;
}
#define OBF(str) ([]() { \
    constexpr auto enc = encrypt(str, sizeof(str)-1, __COUNTER__ ^ hash(__TIME__)); \
    return enc.decrypt(); \
}())
```

### Remote EAT-Based Import Resolution (Manual Mapper)

```cpp
// Resolve imports by walking target process's loaded module exports.
// Handles forwarded exports recursively, API set names, and per-boot ASLR.
FARPROC GetRemoteProcAddress(HANDLE driver, DWORD pid, HMODULE_P remoteBase,
                              const char* dllName, const char* funcName) {
    // Walk EAT → check name RVA → handle forward → resolve API set → return RVA
    IMAGE_EXPORT_DIRECTORY eat = ReadRemote<IMAGE_EXPORT_DIRECTORY>(...);
    for (DWORD i = 0; i < eat.NumberOfNames; i++) {
        // ... name comparison, ordinal lookup, forward handling
    }
}
```

### AES-256-CBC Runtime Decryption with IAT Hiding

```cpp
// BCrypt DLL loaded at runtime. Every export name is OBF-encrypted.
// Key split into 3 XOR parts — impossible to extract from static analysis.
auto init_bcrypt() -> bool {
    auto bcrypt_dll = OBF("bcrypt.dll");
    auto open_algo  = OBF("BCryptOpenAlgorithmProvider");
    // ... resolve via LazyAPI, reconstruct key, decrypt embedded resources
}
```

---

## IOCTL Reference (MidnightSoftware Driver)

| Code | Function | Mechanism |
|------|----------|-----------|
| `0x0DEF` | Echo | Round-trip IOCTL validation |
| `0x0DE0` | Read Memory | CR3 physical page-table walk |
| `0x0DE1` | Write Memory | CR3 physical page-table walk |
| `0x0DE2` | Enum Processes | `ZwQuerySystemInformation` |
| `0x0DE3` | Query VAD | `ZwQueryVirtualMemory` (kernel handle) |
| `0x0DE4` | Get CR3 | `PsGetProcessId` → read `DirectoryTableBase` |
| `0x0DE5` | Queue APC | `KeInitializeApc` + `KeInsertQueueApc` |
| `0x0DE6` | Alloc Memory | `KeStackAttachProcess` + `ZwAllocateVirtualMemory` |
| `0x0DE7` | Free Memory | Kernel-mode `ZwFreeVirtualMemory` |
| `0x0DE8` | Enum Modules | PEB Ldr walk with `__try/__except` |
| `0x0DE9` | Protect Memory | Per-section page attribute modification |
| `0x0DEA` | Protect Process | `ObRegisterCallbacks` + PPL patching |

---

## Defense Layers (Loader)

```
Build Time:  encrypt_bins.ps1 → fresh AES-256 key, split into 3 XOR parts
Compile Time: string_obf.hpp → consteval XOR per literal, volatile reads
Link Time:      VMProtect → mutation + ultra virtualization markers
Load Time:      lazy_api.hpp → all Win32/D3D11/BCrypt resolved at runtime
Auth Time:      Firebase REST → key validation, HWID binding, expiry check
Bypass Time:    dse_bypass.hpp → standard (g_CiOptions) + safe (SeCiCallbacks)
Runtime:        embedded.hpp → AES-256-CBC decryption in process memory
Post-Load:      ObRegisterCallbacks + PPL + handle stripping → payload guarded
```

---

## Security Notes

This project exists for **educational and research purposes**. The kernel-level
techniques demonstrated — CR3 page-table walking, dxgkrnl dispatch hooking,
DSE bypass via kernel memory patching, and ObRegisterCallbacks process protection
— require deep understanding of the Windows kernel and should only be studied in
isolated, authorized environments.

---

*"Understand the kernel. Control the machine. Protect what matters."*
