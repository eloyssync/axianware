# AXIANWARE

AXIANWARE is a lightweight, multi-threaded PE (Portable Executable) analysis utility and reverse engineering helper written in native C++ and Win32 API. Designed for deep binary structure inspection, import table auditing, security mitigation analysis, and generating shell/patch templates without bloat or background telemetry.

## ⚠️ Antivirus & False Positive Warning

When compiling or downloading the pre-built `axianware.exe` binary, certain security software or heuristic cloud engines (such as Microsoft Defender or CrowdStrike) may flag it as a generic threat or Trojan (e.g., *Wacatac.B!ml*). 

**This is a 100% false positive.** 

### Why does this happen?
AXIANWARE is a low-level reverse engineering tool that interacts directly with Windows internals, parses PE headers, manipulates virtual memory protections (`VirtualProtectEx`), writes process memory (`WriteProcessMemory`), and generates memory injection/patch templates. Because these Windows API functions are frequently utilized by malware loaders, security heuristics automatically trigger an alert on unknown, unpackaged binaries that use them.

- **Source Code Transparency:** The project is fully open-source. You can review every line of code in `AXIANWARE.cpp`.
- **VirusTotal Report:** You can inspect the analysis results for the compiled binary on [VirusTotal](https://www.virustotal.com/gui/file/d5cd1746175695d54f556ceb0955c5fb4ab108e1e683737ec83610ba7e8f3515).
- **Build from Source:** If you do not trust pre-compiled binaries, you are strongly encouraged to clone the repository and compile the source code yourself using MSVC.

---

## Key Features

- **PE Header & Security Audit:** Parses DOS/NT headers, identifies target architecture (x86 / x64), validates PE CheckSums, and audits critical security mitigations (ASLR, DEP/NX, Control Flow Guard, SafeSEH).
- **Section Entropy Analysis:** Calculates Shannon entropy across binary sections to instantly spot packed, obfuscated, or encrypted regions (>7.2 threshold indicators).
- **Import Table (IAT) Inspection:** Scans imported DLLs and automatically flags high-risk or sensitive system APIs (memory allocation, process injection, anti-debugging).
- **Async Pattern Scanning (AOB):** Non-blocking background worker threads for fast byte-pattern and wildcard scanning.
- **Crypto & Anti-Analysis Signatures:** Built-in pattern detection for common cryptographic constants (AES, MD5, SHA-256, Base64) and anti-debug/anti-VM traits.
- **Disassembly & Patch Staging:** Interactive code preview, conditional jump (`Jcc`) inversion, and staging binary modifications with automatic PE CheckSum recalculation upon saving.
- **Code & Script Generation:** Instantly exports ready-to-use templates for:
  - C++ In-Memory Suspended Process Loaders
  - MinHook Inline Hook DLLs
  - x64dbg Patch Files (`.1337`)
  - Cheat Engine Auto Assembler Scripts

---

## Target Architecture & System Scope

| Component Category | Target Description / Scope |
| :--- | :--- |
| **PE Headers** | DOS Header, File Header, Optional Header (PE32 / PE32+) |
| **Mitigation Flags** | Dynamic Base (ASLR), NX Compat (DEP), CFG, SafeSEH |
| **Memory Analysis** | Section Raw/Virtual offsets, Shannon Entropy, IAT Risk Levels |
| **Supported Formats** | Executables (`.exe`), Dynamic Link Libraries (`.dll`), System Drivers (`.sys`) |

---

## Installation & Requirements

### Prerequisites
- **Operating System:** Windows 10 / Windows 11 (x64)
- **Compiler / Toolchain:** MSVC (Visual Studio) with C++17 support
- **System Libraries:** Win32 API, Common Controls (`comctl32`), RichEdit (`msftedit`)

### Clone & Build
```bash
git clone https://github.com/eloyssync/AXIANWARE.git
cd AXIANWARE
Open the project solution in Visual Studio and compile as a native Win32 Desktop Application (Release / x64).

Operational Workflow
Initialization: Launch the utility and open a target PE binary via File -> Open Binary (Ctrl+O).

Analysis: Review the automated breakdown of sections, security mitigations, IAT risks, and crypto signatures in the main interface grid.

Exploration & Disassembly: Use the analysis menu to inspect the entry point, extract strings asynchronously, or scan for AOB patterns.

Patch Staging: Apply modifications (such as NOP sleds, forced returns, or inverted jumps) directly to the memory buffer.

Commit Changes: Use File -> Save Patched Binary As (Ctrl+S) to write the modified binary to disk with a fully recalculated PE CheckSum.

Security & Reliability Disclaimer
Disclaimer: This software is provided strictly for educational, auditing, and research purposes only. The author (eloyssync) assumes no liability and is not responsible for any misuse, illegal activities, system damage, data loss, or copyright infringements caused by this program. Use entirely at your own risk.

Repository & Links
GitHub Profile: github.com/eloyssync

Repository: github.com/eloyssync/AXIANWARE

License
This project is licensed under the MIT License. See the LICENSE file for complete details.

Developed by eloyssync.