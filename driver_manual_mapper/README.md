# Driver Manual Mapper

Description

A small manual-mapping utility intended to load unsigned drivers into kernel memory without using the standard service-install path. Useful for testing and driver development in controlled environments.

Core features

- Manual-mapping approach: map driver sections and resolve imports
- Optional relocation and cleanup primitives
- Simple CLI/automation via build script

Technologies & tools

- C++ (native user-mode), Windows API
- Build: Visual Studio (MSVC)

Build & usage

1. Build with `build.bat` using Visual Studio / MSVC.
2. Run as Administrator to perform mapping operations.
3. Use only in lab/test machines (test-signing or secure boot may block behavior).

Security & legal

Manual-mapping drivers can bypass OS protections and should be used only for development and research on machines you control. Do not use on production systems or to circumvent security controls.