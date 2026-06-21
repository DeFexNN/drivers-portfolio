# drivers-portfolio

A systems-level monorepo for kernel drivers, loaders, and mapping utilities. Demonstrates secure loader design, kernel-user IPC, manual mapping, and defensive low-level engineering.

Tech stack

- C/C++ (MSVC) — driver and loader core. Used for direct Windows API and kernel interaction.
- Windows Driver Kit (WDK) — build/debug drivers, KMDF patterns.
- Visual Studio solutions (.sln / .vcxproj) — standardized build targets and configs.
- PowerShell/batch scripts — packaging, signing, and test install helpers.

Purpose & where to look

- driver_loader/: user-mode loader with staged integrity checks, authentication, and optional VMProtect-protected payloads.
- MidnightSoftwareDriver/: kernel driver exposing IOCTLs for memory primitives and a secure handshake via shared memory + MAC.
- driver_manual_mapper/: manual mapping example — relocation, import resolution, and kernel context initialization.

Interesting code patterns

- Constant-time MAC comparisons and careful size-checked IOCTL dispatching to minimize attack surface.
- Manual-mapper separates mapping, relocation, and execution phases clearly and documents required IRQL/context assumptions.
- Defensive pointer checks and explicit validation of user-supplied buffers to prevent accidental kernel faults.

Build & test

1. Install Visual Studio + WDK (matching target OS SDK).
2. Open the provided solution and build x64 Release.
3. Use test-signing or a test-signed driver for kernel load; manual mapper can run without installing a service for lab work.

Security notes

- Remove embedded secrets before publishing; rotate keys and move binaries to releases or LFS.
- Use only in controlled labs. Kernel tools can crash systems or bypass protections when misused.