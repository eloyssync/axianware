# AXIANWARE

A lightweight, multi-threaded PE (Portable Executable) analysis utility and binary modification toolkit written in native C++ and Win32 API. Built for deep static inspection, security triage, and rapid patch staging.

---
<img width="1123" height="729" alt="image" src="https://github.com/user-attachments/assets/ef39d2b7-dcc0-44fd-8ec9-95f56125ca4b" />

### Core Features

* **PE Header & Security Audit:** Parses DOS/NT headers, detects target architecture (x86 / x64), validates PE CheckSums, and audits mitigation flags (ASLR, DEP/NX, CFG, SafeSEH).
* **Section Entropy Analysis:** Calculates Shannon entropy per section to instantly spot packed, obfuscated, or encrypted data (>7.2 threshold indicators).
* **Import Table (IAT) Inspection:** Scans imported DLLs/APIs and flags sensitive routines (virtual memory management, thread context manipulation, process enumeration).
* **Async Pattern Scanning (AOB):** Non-blocking background worker threads for fast byte-pattern matching with wildcard (`??`) support.
* **Crypto & Anti-Analysis Detection:** Scans for known cryptographic constants (AES, MD5, SHA-256, Base64 tables) and anti-debugging/VM indicators.
* **Disassembly & Patch Staging:** Interactive code preview, quick control-flow edits (NOP out, force `RET 0xC3`, invert `Jcc`), and automatic PE CheckSum recalculation upon saving.
* **Export & Generation Pipeline:**
  * C++ In-Memory Suspended Process Loader templates
  * MinHook inline trampoline DLL templates
  * x64dbg patch files (`.1337`)
  * Cheat Engine Auto Assembler scripts

---

### Target Architecture & Scope

| Component Category | Target Description / Scope |
| :--- | :--- |
| **PE Headers** | DOS Header, File Header, Optional Header (PE32 / PE32+) |
| **Mitigation Flags** | Dynamic Base (ASLR), NX Compat (DEP), CFG, SafeSEH |
| **Memory Analysis** | Section Raw/Virtual offsets, Shannon Entropy, IAT Risk Levels |
| **Supported Formats** | Executables (`.exe`), Dynamic Link Libraries (`.dll`), System Drivers (`.sys`) |

---

### Building & Prerequisites

**Prerequisites:**
* **OS:** Windows 10 / Windows 11 (x64)
* **Compiler / IDE:** Visual Studio 2022 (MSVC) with C++17 support
* **Dependencies:** None (Pure Win32 API, `comctl32`, `msftedit`)

**Build Steps:**
```cmd
git clone https://github.com/eloyssync/axianware.git
cd axianware
Open AXIANWARE.sln in Visual Studio.

Select Release and x64.

Press Ctrl + Shift + B to compile. The binary will be generated in x64\Release\.

Operational Workflow
Initialization: Launch the utility and load the target file via File -> Open Binary (Ctrl+O).

Automated Triage: Review the section layout, Shannon entropy distribution, and flagged APIs in the main report.

Deep Inspection: Use the Analysis menu to inspect exports/imports, launch async string extraction, or run AOB searches.

Patch Staging: Toggle mitigation flags (e.g., clear ASLR) or stage instruction patches (NOP, RET, Jcc inversion) in the staging buffer.

Commit Changes: Save the modified binary via File -> Save Patched Binary As... (Ctrl+S) with automatic PE CheckSum recalculation.

Disclaimer
Notice: This software is provided strictly for educational, security auditing, and research purposes. The author (eloyssync) assumes no liability and is not responsible for any misuse, unintended modifications, system damage, or copyright infringements caused by this tool. Use entirely at your own risk.

License
Distributed under the MIT License. See LICENSE for more information.
