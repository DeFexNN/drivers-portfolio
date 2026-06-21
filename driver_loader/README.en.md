# driver_loader.vmp.exe — Secure Kernel Driver Loader (English)

Summary

A hardened, authenticated loader that stages embedded driver artifacts, performs secure extraction, and installs a kernel-mode driver with defensive controls and logging. Built as a testable, auditable component for systems and security engineering.

Employer-facing highlights

- Authentication-first launch with ImGui status UI and clear telemetry for operator feedback.
- Atomic extraction & cleanup of embedded resources — minimal disk exposure of secrets or binaries.
- Clear separation of responsibilities: UI, auth, embedded manager, and kernel installer (kvc).
- Designed for audit and testing: modular interfaces and deterministic error handling.

Technical stack

- C++17, MSVC, Windows API, D3D11 (for UI surface), VMProtect integration
- Practices: constant-time primitives, secure zeroing, input validation, least-privilege assumptions

Build & run

- Requirements: Windows 10/11 x64, Visual Studio + WDK, Administrator privileges
- Build: use build.bat (release) or debug.bat (debug)
- Run elevated and follow on-screen UI

Responsible use

Intended for controlled lab testing and engineering reviews. Do not use to circumvent protections on systems without authorization.