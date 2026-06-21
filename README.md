# Kernel Drivers & Loader Portfolio

This repository contains a curated set of kernel tooling and a protected loader demonstrating practical, secure, and auditable approaches to kernel-user integration. The materials are organized to help hiring teams quickly assess systems-level capabilities, security-aware engineering practices, and design choices.

TL;DR for recruiters

- Ideal role: Senior Windows Systems / Kernel Engineer, Security Tooling Engineer, or Platform Architect.
- Core strengths demonstrated: IOCTL API design, IRQL-safe kernel code, secure loader flows, and build/protection integration.

What to look for (high-level)

- Versioned IOCTL surface and type-safe user<->kernel contracts
- Defensive kernel-side validation and explicit IRQL handling
- Secure, atomic embedded extraction with cleanup and memory scrubbing
- Simple but effective cryptographic hygiene (constant-time primitives, HMAC-like verifications)
- Modular, auditable components (UI, Auth, Embedded, Installer/Mapper)

Tech stack & skills

- Languages: C++17 (MSVC), C (kernel idioms), C# (supporting tooling)
- Kernel/Platform: Windows Driver Kit (WDK), IOCTLs, IRQL, DMA primitives
- Tooling & Debug: Visual Studio, WinDbg/kd, IDA/Ghidra, symbol publishing, optional Git LFS
- UI & UX: Direct3D11, ImGui (operator feedback surface)

Detailed technical callouts (what to read first)

1) IOCTL request + kernel handler (versioning, validation, IRQL notes)

```cpp
// user -> kernel request
struct IOCTL_READ_REQ {
    uint32_t version;    // api version, allows evolution
    uint64_t address;    // virtual address to read
    uint32_t size;       // number of bytes requested
};

// kernel handler (pseudocode)
NTSTATUS HandleRead(IRP* Irp) {
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE; // require PASSIVE for safe ops
    IOCTL_READ_REQ req; // copied from user
    if (req.version != SUPPORTED) return STATUS_NOT_SUPPORTED;
    if (req.size == 0 || req.size > MAX_SAFE_READ) return STATUS_INVALID_PARAMETER;
    if (!IsValidPtr(req.address)) return STATUS_INVALID_PARAMETER;
    // perform read using safe routines and copy to user buffer
}
```

Why it matters

- Versioning prevents breaking changes when API evolves.
- IRQL guard prevents unsafe memory operations at DISPATCH_LEVEL or higher.
- Explicit validation of size/address prevents kernel crashes and reduces exploit surface.

2) Constant-time MAC verification (auth path)

```c
uint8_t diff = 0;
for (int i = 0; i < MAC_LEN; ++i)
    diff |= (blk_mac[i] ^ expected_mac[i]);
if (diff != 0) return AUTH_FAIL;
```

Why it matters

- Eliminates timing side-channels in MAC verification, a low-cost defense appropriate for local IPC scenarios.
- Easy to audit and verify in code reviews and tests.

3) Secure extraction and ephemeral payload lifecycle

```cpp
std::string tmp = CreateTempFilePath();
WriteFile(tmp, embeddedPayload);
SetFileHidden(tmp);
// Use payload
SecureZeroMemory(payloadBuffer, payloadSize);
DeleteFile(tmp);
```

What this gives

- Atomic presence: payload is briefly on disk under a temp name and promptly removed.
- Memory scrubbing reduces risk of secret leakage through memory analysis or core dumps.

4) DMA-aware read helper (abstraction and safety)

```cpp
bool DmaReadPhysical(PhysicalAddr paddr, void* out, size_t size) {
    if (size > DMA_MAX) return false;
    // map pages, copy, unmap — with careful error handling
    return true;
}
```

Why abstract it

- Encapsulates platform-specific DMA details behind a bounded, testable API.
- Reduces duplication and centralizes error handling and resource cleanup.

5) Logging & telemetry (minimal but useful)

```cpp
LOG_INFO("auth: session ok uid=%s", userId.c_str());
LOG_WARN("driver: read request size=%u from addr=0x%llx", size, addr);
```

Why proper logs matter

- Provide context for post-mortem debugging without dumping secrets.
- Make audits and incident response feasible.

Where to start in the repo

- MidnightSoftwareDriver/src — IOCTL table, command handlers, IRQL-aware routines
- driver_loader/src/auth.hpp — authentication flow, MAC checks, retry logic
- driver_loader/src/embedded.hpp — extraction, tmp file lifecycle, cleanup semantics
- driver_manual_mapper — compact loader example for PE/relocation/import handling

How to evaluate quickly (recommended checklist)

1. Read IOCTL definitions and ensure each kernel handler authoritatively validates inputs.
2. Check IRQL boundaries and memory pool choices (PagedPool vs NonPagedPool) for each operation.
3. Verify that secrets are zeroed and temporary files removed in all exit paths.
4. Inspect logging for sufficient context without leaking secrets.
5. Confirm build outputs include symbols to enable WinDbg post-mortem.

What this demonstrates to hiring teams

- Practical knowledge of Windows internals and safe kernel programming patterns
- Security-aware engineering: simple mitigations with high ROI (constant-time ops, secure wiping)
- Emphasis on auditability, maintainability, and testability — not just throwing code together

Responsible use and legal note

These projects target lab and research environments. They are not intended to provide operational instructions for bypassing protections. Use only with explicit authorization.

Next steps for a reviewer

- Request a short guided code tour (I can provide an annotated walkthrough of the IOCTL table and auth flow).
- Ask for specific unit tests or debugging traces for any handler you want deeper insight into.

Contact

- GitHub: https://github.com/DeFexNN

---

If you'd like, I will commit and push this updated README (with Co-authored-by) now.