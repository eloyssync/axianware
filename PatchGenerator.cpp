#include "PatchGenerator.h"

#include <iomanip>
#include <sstream>

namespace axianware {

namespace {

std::wstring HexDumpBytes(const uint8_t* data, size_t length, const wchar_t* separator = L" ") {
    std::wstringstream ss;
    ss << std::hex << std::uppercase << std::setfill(L'0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
        if (i + 1 < length) {
            ss << separator;
        }
    }
    return ss.str();
}

bool StageWordBits(const uint8_t* image, size_t fileSize, DWORD offset, WORD clearMask, WORD setMask,
                   StagedPatchManager& patches) {
    if (!image || static_cast<size_t>(offset) + sizeof(WORD) > fileSize) {
        return false;
    }
    const WORD original = *reinterpret_cast<const WORD*>(image + offset);
    const WORD patched = static_cast<WORD>((original & static_cast<WORD>(~clearMask)) | setMask);
    const auto* origBytes = reinterpret_cast<const uint8_t*>(&original);
    const auto* newBytes = reinterpret_cast<const uint8_t*>(&patched);
    return patches.AddRange(offset, origBytes, newBytes, sizeof(WORD), fileSize);
}

bool StageDwordBits(const uint8_t* image, size_t fileSize, DWORD offset, DWORD clearMask, DWORD setMask,
                    StagedPatchManager& patches) {
    if (!image || static_cast<size_t>(offset) + sizeof(DWORD) > fileSize) {
        return false;
    }
    const DWORD original = *reinterpret_cast<const DWORD*>(image + offset);
    const DWORD patched = (original & ~clearMask) | setMask;
    const auto* origBytes = reinterpret_cast<const uint8_t*>(&original);
    const auto* newBytes = reinterpret_cast<const uint8_t*>(&patched);
    return patches.AddRange(offset, origBytes, newBytes, sizeof(DWORD), fileSize);
}

}  // namespace

std::wstring PatchGenerator::FileNameFromPath(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

std::wstring PatchGenerator::Generate1337Patch(const std::wstring& targetPath,
                                               const PEAnalysisReport& report,
                                               const StagedPatchManager& patches) {
    std::wstringstream ss;
    ss << L">" << FileNameFromPath(targetPath) << L"\r\n";

    const auto diff = patches.ComputeDiff();
    if (diff.empty()) {
        ss << L"; No staged patches. Example (RVA of first Jcc-style edit):\r\n";
        ss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8)
           << report.entryPointRva << L":90->90\r\n";
        return ss.str();
    }

    // x64dbg .1337 uses module-relative RVA, not raw file offset.
    for (const auto& entry : diff) {
        DWORD rva = FileOffsetToRva(entry.fileOffset, report.sections);
        if (rva == 0) {
            rva = entry.fileOffset;
        }
        ss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8) << rva << L":"
           << std::setw(2) << static_cast<int>(entry.original) << L"->"
           << std::setw(2) << static_cast<int>(entry.patched) << L"\r\n";
    }
    return ss.str();
}

std::wstring PatchGenerator::GenerateInlineHookDllTemplate(const PEAnalysisReport& report, DWORD targetRva) {
    std::wstringstream ss;
    const wchar_t* arch = report.is64Bit ? L"x64" : L"x86";

    ss << L"// ============================================================================ \r\n";
    ss << L"// AXIANWARE — local debug trampoline template (" << arch << L")\r\n";
    ss << L"// Target RVA: 0x" << std::hex << std::uppercase << targetRva << L"\r\n";
    ss << L"// For in-process analysis of a module you loaded yourself. Calls through to\r\n";
    ss << L"// the original bytes after logging. Not an injector and not a stealth hook.\r\n";
    ss << L"// ============================================================================ \r\n\r\n";
    ss << L"#define WIN32_LEAN_AND_MEAN\r\n";
    ss << L"#include <windows.h>\r\n";
    ss << L"#include <cstdint>\r\n";
    ss << L"#include <cstring>\r\n\r\n";
    ss << L"#ifndef AXW_LOG\r\n";
    ss << L"#  define AXW_LOG(fmt, ...) OutputDebugStringA(\"AXIANWARE: \" fmt)\r\n";
    ss << L"#endif\r\n\r\n";
    ss << L"namespace {\r\n";
    ss << L"constexpr std::uintptr_t kTargetRva = 0x" << std::hex << std::uppercase << targetRva << L";\r\n";
    if (report.is64Bit) {
        ss << L"constexpr std::size_t kStolen = 12; // mov rax, imm64; jmp rax\r\n";
    } else {
        ss << L"constexpr std::size_t kStolen = 5;  // jmp rel32\r\n";
    }
    ss << L"alignas(16) unsigned char g_original[32]{};\r\n";
    ss << L"void* g_target = nullptr;\r\n";
    ss << L"void* g_trampoline = nullptr;\r\n\r\n";
    ss << L"using TargetFn = void (*)();\r\n\r\n";
    ss << L"void HookThunk() {\r\n";
    ss << L"    AXW_LOG(\"hook hit\\n\");\r\n";
    ss << L"    if (g_trampoline) {\r\n";
    ss << L"        reinterpret_cast<TargetFn>(g_trampoline)();\r\n";
    ss << L"    }\r\n";
    ss << L"}\r\n\r\n";
    ss << L"bool InstallLocalTrampoline() {\r\n";
    ss << L"    auto* base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));\r\n";
    ss << L"    g_target = base + kTargetRva;\r\n";
    ss << L"    std::memcpy(g_original, g_target, kStolen);\r\n\r\n";
    ss << L"    g_trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\r\n";
    ss << L"    if (!g_trampoline) return false;\r\n";
    ss << L"    auto* tr = static_cast<std::uint8_t*>(g_trampoline);\r\n";
    ss << L"    std::memcpy(tr, g_original, kStolen);\r\n";
    if (report.is64Bit) {
        ss << L"    tr[kStolen + 0] = 0x48; tr[kStolen + 1] = 0xB8; // mov rax, abs\r\n";
        ss << L"    const std::uint64_t back = reinterpret_cast<std::uint64_t>(g_target) + kStolen;\r\n";
        ss << L"    std::memcpy(tr + kStolen + 2, &back, 8);\r\n";
        ss << L"    tr[kStolen + 10] = 0xFF; tr[kStolen + 11] = 0xE0; // jmp rax\r\n\r\n";
        ss << L"    unsigned char patch[12] = { 0x48, 0xB8 };\r\n";
        ss << L"    const std::uint64_t dest = reinterpret_cast<std::uint64_t>(&HookThunk);\r\n";
        ss << L"    std::memcpy(patch + 2, &dest, 8);\r\n";
        ss << L"    patch[10] = 0xFF; patch[11] = 0xE0;\r\n";
    } else {
        ss << L"    tr[kStolen] = 0xE9;\r\n";
        ss << L"    const std::int32_t back = static_cast<std::int32_t>(\r\n";
        ss << L"        reinterpret_cast<std::uint8_t*>(g_target) + kStolen - (tr + kStolen + 5));\r\n";
        ss << L"    std::memcpy(tr + kStolen + 1, &back, 4);\r\n\r\n";
        ss << L"    unsigned char patch[5] = { 0xE9 };\r\n";
        ss << L"    const std::int32_t rel = static_cast<std::int32_t>(\r\n";
        ss << L"        reinterpret_cast<std::uint8_t*>(&HookThunk) -\r\n";
        ss << L"        (static_cast<std::uint8_t*>(g_target) + 5));\r\n";
        ss << L"    std::memcpy(patch + 1, &rel, 4);\r\n";
    }
    ss << L"    DWORD oldProtect = 0;\r\n";
    ss << L"    if (!VirtualProtect(g_target, kStolen, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;\r\n";
    ss << L"    std::memcpy(g_target, patch, sizeof(patch));\r\n";
    ss << L"    VirtualProtect(g_target, kStolen, oldProtect, &oldProtect);\r\n";
    ss << L"    FlushInstructionCache(GetCurrentProcess(), g_target, kStolen);\r\n";
    ss << L"    return true;\r\n";
    ss << L"}\r\n";
    ss << L"}  // namespace\r\n\r\n";
    ss << L"BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {\r\n";
    ss << L"    if (reason == DLL_PROCESS_ATTACH) {\r\n";
    ss << L"        DisableThreadLibraryCalls(module);\r\n";
    ss << L"        InstallLocalTrampoline();\r\n";
    ss << L"    }\r\n";
    ss << L"    return TRUE;\r\n";
    ss << L"}\r\n";
    return ss.str();
}

std::wstring PatchGenerator::GenerateCheatEngineScript(const std::wstring& targetPath,
                                                       const PEAnalysisReport& report,
                                                       DWORD rva,
                                                       const uint8_t* originalBytes,
                                                       const uint8_t* patchBytes,
                                                       size_t length) {
    std::wstringstream ss;
    const std::wstring moduleName = FileNameFromPath(targetPath);
    const std::wstring safeName = moduleName.empty() ? L"target.exe" : moduleName;

    ss << L"[ENABLE]\r\n";
    ss << L"// AXIANWARE CE script — RVA 0x" << std::hex << std::uppercase << rva;
    ss << L" (" << (report.is64Bit ? L"PE32+" : L"PE32") << L")\r\n";
    ss << L"define(targetAddr, \"" << safeName << L"\"+0x" << std::hex << std::uppercase << rva << L")\r\n";
    ss << L"targetAddr:\r\n";
    ss << L"  db ";
    if (patchBytes && length > 0) {
        ss << HexDumpBytes(patchBytes, length);
    } else {
        ss << L"90 90";
    }
    ss << L"\r\n\r\n";
    ss << L"[DISABLE]\r\n";
    ss << L"targetAddr:\r\n";
    ss << L"  db ";
    if (originalBytes && length > 0) {
        ss << HexDumpBytes(originalBytes, length);
    } else {
        ss << L"// restore original bytes here";
    }
    ss << L"\r\n";
    return ss.str();
}

bool PatchGenerator::StageDisableDynamicBase(const uint8_t* image, size_t fileSize,
                                             const PEAnalysisReport& report,
                                             StagedPatchManager& patches) {
    if (!image || report.dllCharacteristicsOffset == 0) {
        return false;
    }
    // Clear DYNAMIC_BASE and HIGH_ENTROPY_VA in DllCharacteristics (Optional Header).
    const WORD clearMask = static_cast<WORD>(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                             IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
    return StageWordBits(image, fileSize, report.dllCharacteristicsOffset, clearMask, 0, patches);
}

bool PatchGenerator::StageSectionReadWrite(const uint8_t* image, size_t fileSize,
                                           const PEAnalysisReport& report,
                                           WORD sectionIndex, bool writable,
                                           StagedPatchManager& patches) {
    if (!image || sectionIndex >= report.sections.size()) {
        return false;
    }
    const SectionInfo& sec = report.sections[sectionIndex];
    const DWORD charOff = sec.headerFileOffset + 36;  // IMAGE_SECTION_HEADER.Characteristics
    DWORD setMask = IMAGE_SCN_MEM_READ;
    DWORD clearMask = 0;
    if (writable) {
        setMask |= IMAGE_SCN_MEM_WRITE;
    } else {
        clearMask = IMAGE_SCN_MEM_WRITE;
    }
    return StageDwordBits(image, fileSize, charOff, clearMask, setMask, patches);
}

bool PatchGenerator::RecalculateAndWriteCheckSum(uint8_t* image, size_t fileSize,
                                                 const PEAnalysisReport& report) {
    if (!image || report.checkSumOffset == 0 ||
        static_cast<size_t>(report.checkSumOffset) + sizeof(DWORD) > fileSize) {
        return false;
    }
    const DWORD checksum = CalculatePECheckSum(image, fileSize, report.checkSumOffset);
    *reinterpret_cast<DWORD*>(image + report.checkSumOffset) = checksum;
    return true;
}

}  // namespace axianware
