# MidnightSoftwareDriver (Kernel Driver)

Description

MidnightSoftwareDriver is a kernel-mode driver used alongside the loader and DMA payloads. It provides low-level primitives for memory access, driver-user communication, and secure handshake channels.

Core features

- Kernel-user IPC primitives (named device, IOCTLs)
- Support for DMA/driver-assisted memory access
- Minimal footprint and residency in kernel memory
- Integration points for loader and SDK

Technologies & tools

- C/C++ (Windows Kernel Mode)
- Windows Driver Kit (WDK)
- IOCTL-based communication, named device interfaces
- Build with Visual Studio and WDK

Build & usage

1. Requirements: Windows WDK, Visual Studio (MSVC), Administrator privileges.
2. Open the driver project in Visual Studio and build the appropriate configuration (x64).
3. Use the driver_loader to install and load this driver; direct user-mode loading requires signed driver or test-signing enabled.

Security & responsibility

This driver runs in kernel mode — incorrect usage can crash the system. Use only in controlled lab environments and with explicit permission. Do not deploy to production machines without appropriate code signing and security review.