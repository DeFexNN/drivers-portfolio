# Kernel Drivers & Loader Portfolio (English)

This repository collects kernel tooling and authenticated loader projects that demonstrate production-grade systems engineering, secure loader design, and kernel-user integration patterns. It is intended for engineering reviewers and hiring teams.

Highlights

- Secure loader architecture with authenticated launch, secure embedded extraction, and audit-friendly logging.
- Compact, hardened kernel driver exposing a minimal IOCTL surface with input validation and IRQL-aware memory handling.
- Educational manual-mapper illustrating PE parsing, relocations, and import resolution for driver development.

Tech stack

- C++ (expert), Windows WDK, Win32 API, D3D11 (lightweight UI), VMProtect-aware build flows
- Tooling: Visual Studio, WinDbg, Git, optional Git LFS

How to evaluate

1. Review IOCTL definitions and kernel-side validations.
2. Inspect auth and embedded modules to verify secure secret handling and cleanup.
3. Check module boundaries and logging for auditability.

Responsible use

Designed for lab and research environments. Do not use to bypass security controls or on systems without explicit authorization.
