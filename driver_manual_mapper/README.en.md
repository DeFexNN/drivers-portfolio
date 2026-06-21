# Driver Manual Mapper — Educational Tool (English)

Overview

A concise manual-mapping utility that demonstrates core loader concepts for PE-based kernel images: parsing headers, applying relocations, resolving imports, and safe rollback.

Highlights

- Clear, testable implementation of PE parsing and relocations.
- Import resolution emulation for symbol binding without service-install flows.
- Rollback and cleanup semantics to minimize system impact on failure.

Why this is useful

Useful as a development/test harness when iterating on driver code and edge-case handling. Shows ability to reason about binary formats and loader logic.

Build & run

- Requirements: Visual Studio (MSVC)
- Build: run build.bat
- Run with Administrator privileges for mapping operations

Responsible use

Educational and lab-only. Do not use to bypass system protections on unauthorized machines.