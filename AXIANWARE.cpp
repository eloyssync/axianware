#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
std::wstring Generate1337PatchText(const std::wstring& targetExePath);
#include <filesystem>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstdint>
#include <cmath>
#include <chrono>
#include <algorithm>
#include <unordered_map>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>
#include <__msvc_filebuf.hpp>

#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#define WM_APP_ASYNC_STATUS      (WM_APP + 101)
#define WM_APP_AOB_COMPLETE      (WM_APP + 102)
#define WM_APP_STRINGS_COMPLETE  (WM_APP + 103)
#define WM_APP_CRYPTO_COMPLETE   (WM_APP + 104)

#define IDC_MAIN_LISTVIEW        1001
#define IDC_MAIN_RICHEDIT        1002
#define IDC_MAIN_STATUSBAR       1003
#define IDC_SEARCH_EDIT          1004
#define IDC_SEARCH_BTN           1005

#define IDM_FILE_OPEN            2001
#define IDM_FILE_SAVE_AS         2002
#define IDM_FILE_HEXVIEW         2003
#define IDM_FILE_EXIT            2004

#define IDM_ANALYSIS_SUMMARY     2101
#define IDM_ANALYSIS_IMPORTS     2102
#define IDM_ANALYSIS_STRINGS     2103
#define IDM_ANALYSIS_DISASM_EP   2104
#define IDM_ANALYSIS_CRYPTO_SCAN 2105

#define IDM_PATCH_NOP_PROLOGUE   3001
#define IDM_PATCH_RET_PROLOGUE   3002
#define IDM_PATCH_JMP_SHORT      3003
#define IDM_PATCH_INVERT_JUMP    3004
#define IDM_PATCH_GEN_LOADER     3005
#define IDM_PATCH_GEN_MINHOOK    3006
#define IDM_PATCH_GEN_X64DBG     3007
#define IDM_PATCH_GEN_CHEATENG   3008

#define IDM_HELP_ABOUT           4001

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) : m_handle(h) {}
    ~ScopedHandle() { Close(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    void Close() {
        if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE Get() const { return m_handle; }
    bool IsValid() const { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }

private:
    HANDLE m_handle;
};

class MemoryMappedFile {
public:
    MemoryMappedFile() = default;
    ~MemoryMappedFile() { Close(); }

    bool Open(const std::wstring& filePath, bool writeAccess = false) {
        Close();
        DWORD access = writeAccess ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
        DWORD share = writeAccess ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE);
        DWORD flProtect = writeAccess ? PAGE_READWRITE : PAGE_READONLY;
        DWORD mapAccess = writeAccess ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ;

        m_hFile = ScopedHandle(CreateFileW(filePath.c_str(), access, share, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!m_hFile.IsValid()) return false;

        LARGE_INTEGER size;
        if (!GetFileSizeEx(m_hFile.Get(), &size) || size.QuadPart == 0) {
            Close();
            return false;
        }
        m_fileSize = static_cast<size_t>(size.QuadPart);

        m_hMapping = ScopedHandle(CreateFileMappingW(m_hFile.Get(), nullptr, flProtect, 0, 0, nullptr));
        if (!m_hMapping.IsValid()) {
            Close();
            return false;
        }

        m_pBase = MapViewOfFile(m_hMapping.Get(), mapAccess, 0, 0, 0);
        return m_pBase != nullptr;
    }

    void Close() {
        if (m_pBase) {
            UnmapViewOfFile(m_pBase);
            m_pBase = nullptr;
        }
        m_hMapping.Close();
        m_hFile.Close();
        m_fileSize = 0;
    }

    const uint8_t* Data() const { return static_cast<const uint8_t*>(m_pBase); }
    size_t Size() const { return m_fileSize; }
    bool IsOpen() const { return m_pBase != nullptr; }

private:
    ScopedHandle m_hFile;
    ScopedHandle m_hMapping;
    LPVOID m_pBase = nullptr;
    size_t m_fileSize = 0;
};

enum class ApiRisk { Normal, MemoryAlloc, ProcessInject, ThreadControl, AntiDebug, Suspicious };

struct ApiMeta {
    ApiRisk risk;
    const wchar_t* category;
};

const std::unordered_map<std::string, ApiMeta> g_SensitiveApiMap = {
    { "VirtualAlloc",          { ApiRisk::MemoryAlloc,   L"Memory Allocation / RWX" } },
    { "VirtualAllocEx",        { ApiRisk::ProcessInject, L"Remote Memory Allocation" } },
    { "VirtualProtect",        { ApiRisk::MemoryAlloc,   L"Memory Protection Modification" } },
    { "VirtualProtectEx",      { ApiRisk::ProcessInject, L"Remote Memory Protection Mod" } },
    { "WriteProcessMemory",    { ApiRisk::ProcessInject, L"Process Memory Modification" } },
    { "ReadProcessMemory",     { ApiRisk::ProcessInject, L"Process Memory Read" } },
    { "CreateRemoteThread",    { ApiRisk::ProcessInject, L"Remote Thread Execution" } },
    { "NtCreateThreadEx",      { ApiRisk::ProcessInject, L"Native Remote Thread Exec" } },
    { "QueueUserAPC",          { ApiRisk::ProcessInject, L"APC Injection" } },
    { "SetThreadContext",      { ApiRisk::ThreadControl, L"Thread Context Hijacking" } },
    { "GetThreadContext",      { ApiRisk::ThreadControl, L"Thread Context Query" } },
    { "OpenProcess",           { ApiRisk::Suspicious,    L"Process Handle Acquisition" } },
    { "IsDebuggerPresent",     { ApiRisk::AntiDebug,     L"PEB Anti-Debugging" } },
    { "CheckRemoteDebuggerPresent", { ApiRisk::AntiDebug, L"Remote Debugger Check" } },
    { "NtQueryInformationProcess",  { ApiRisk::AntiDebug, L"Process Info Anti-Debug" } }
};

struct SectionInfo {
    std::string name;
    DWORD virtualAddress = 0;
    DWORD virtualSize = 0;
    DWORD rawDataOffset = 0;
    DWORD rawDataSize = 0;
    DWORD characteristics = 0;
    double entropy = 0.0;
    bool isSuspiciousEntropy = false;
};

struct ExportInfo {
    std::string name;
    WORD ordinal = 0;
    DWORD rva = 0;
    DWORD fileOffset = 0;
};

struct ImportFunction {
    std::string name;
    WORD ordinal = 0;
    bool isOrdinal = false;
    ApiRisk risk = ApiRisk::Normal;
    std::wstring category;
};

struct ImportModule {
    std::string dllName;
    std::vector<ImportFunction> functions;
    size_t sensitiveCount = 0;
};

struct SecurityFlags {
    bool aslr = false;
    bool highEntropyVA = false;
    bool dep = false;
    bool safeSEH = false;
    bool controlFlowGuard = false;
    bool noIsolation = false;
};

struct ExtractedString {
    size_t offset = 0;
    DWORD rva = 0;
    std::wstring text;
    bool isUnicode = false;
    std::string sectionName;
};

struct CryptoDetection {
    std::wstring name;
    std::wstring type;
    size_t offset;
    DWORD rva;
    std::string sectionName;
};

struct PatternByte {
    uint8_t value;
    bool isWildcard;
};

struct PEAnalysisReport {
    bool is64Bit = false;
    WORD machine = 0;
    DWORD entryPointRva = 0;
    DWORD entryPointOffset = 0;
    ULONGLONG imageBase = 0;
    DWORD sizeOfImage = 0;
    DWORD checkSumOffset = 0;
    DWORD originalCheckSum = 0;
    SecurityFlags security;
    std::vector<SectionInfo> sections;
    std::vector<ExportInfo> exports;
    std::vector<ImportModule> imports;
    std::vector<ExtractedString> strings;
    std::vector<CryptoDetection> cryptoDetections;
    double overallEntropy = 0.0;
    bool isPatched = false;
};

HWND g_hWndMain = nullptr;
HWND g_hListView = nullptr;
HWND g_hRichEdit = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hSearchEdit = nullptr;
HWND g_hSearchBtn = nullptr;
HMODULE g_hMsftedit = nullptr;

std::wstring g_currentFilePath;
PEAnalysisReport g_report;

std::map<DWORD, std::pair<uint8_t, uint8_t>> g_stagedPatches;

DWORD RvaToFileOffset(DWORD rva, const std::vector<SectionInfo>& sections, size_t fileSize) {
    for (const auto& sec : sections) {
        DWORD secSize = sec.virtualSize ? sec.virtualSize : sec.rawDataSize;
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + secSize) {
            DWORD offset = sec.rawDataOffset + (rva - sec.virtualAddress);
            if (offset < fileSize) return offset;
        }
    }
    return 0;
}

DWORD FileOffsetToRva(DWORD offset, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        if (offset >= sec.rawDataOffset && offset < sec.rawDataOffset + sec.rawDataSize) {
            return sec.virtualAddress + (offset - sec.rawDataOffset);
        }
    }
    return 0;
}

std::string GetSectionNameByOffset(DWORD offset, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        if (offset >= sec.rawDataOffset && offset < sec.rawDataOffset + sec.rawDataSize) {
            return sec.name;
        }
    }
    return "Header";
}

double CalculateShannonEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    size_t byteCounts[256] = { 0 };
    for (size_t i = 0; i < size; ++i) byteCounts[data[i]]++;

    double entropy = 0.0;
    double dSize = static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / dSize;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }
    return entropy;
}

DWORD CalculatePECheckSum(const uint8_t* base, size_t fileSize, DWORD checkSumFieldOffset) {
    uint64_t checksum = 0;
    size_t dwords = fileSize / 4;
    const uint32_t* pDwords = reinterpret_cast<const uint32_t*>(base);

    for (size_t i = 0; i < dwords; ++i) {
        if (i * 4 == checkSumFieldOffset) continue; 
        checksum += pDwords[i];
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    size_t remainder = fileSize % 4;
    if (remainder > 0) {
        uint32_t lastDword = 0;
        memcpy(&lastDword, base + (dwords * 4), remainder);
        checksum += lastDword;
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = checksum + (checksum >> 16);
    checksum = checksum & 0xFFFF;
    checksum += fileSize;

    return static_cast<DWORD>(checksum);
}

std::vector<PatternByte> ParseAOBPattern(const std::wstring& patternStr) {
    std::vector<PatternByte> result;
    std::wstringstream ss(patternStr);
    std::wstring token;
    while (ss >> token) {
        if (token == L"?" || token == L"??") {
            result.push_back({ 0x00, true });
        }
        else {
            wchar_t* endPtr = nullptr;
            auto val = static_cast<uint8_t>(wcstoul(token.c_str(), &endPtr, 16));
            result.push_back({ val, false });
        }
    }
    return result;
}

std::vector<size_t> ScanBinaryAOB(const uint8_t* data, size_t dataSize, const std::vector<PatternByte>& pattern) {
    std::vector<size_t> matches;
    if (pattern.empty() || dataSize < pattern.size()) return matches;

    size_t patLen = pattern.size();
    for (size_t i = 0; i <= dataSize - patLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < patLen; ++j) {
            if (!pattern[j].isWildcard && data[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) {
            matches.push_back(i);
            if (matches.size() >= 1000) break;
        }
    }
    return matches;
}


struct CryptoSignature {
    const wchar_t* name;
    const wchar_t* category;
    std::wstring pattern;
};

const std::vector<CryptoSignature> g_CryptoAndAntiSignatures = {
    
    { L"AES S-Box", L"Crypto [AES]", L"63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76" },
    { L"AES Inverse S-Box", L"Crypto [AES]", L"52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB" },
    { L"MD5 Init Constants", L"Crypto [MD5]", L"01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10" },
    { L"SHA-256 Constants", L"Crypto [SHA256]", L"6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A" },
    { L"Base64 Alphabet Table", L"Crypto [Encoding]", L"41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50" },

    
    { L"PEB.BeingDebugged (x86)", L"Anti-Debug", L"64 A1 30 00 00 00 8A 40 02" },
    { L"PEB.BeingDebugged (x64)", L"Anti-Debug", L"65 48 8B 04 25 60 00 00 00 0F B6 40 02" },
    { L"PEB.NtGlobalFlag (x86)", L"Anti-Debug", L"64 A1 30 00 00 00 8B 40 68" },
    { L"PEB.NtGlobalFlag (x64)", L"Anti-Debug", L"65 48 8B 04 25 60 00 00 00 8B 40 BC" },
    { L"RDTSC Timing Check", L"Anti-VM/Debug", L"0F 31 ?? ?? ?? ?? 0F 31" },
    { L"CPUID Hypervisor Detection", L"Anti-VM", L"B8 01 00 00 00 0F A2 ?? ?? ?? 01" }
};

void ScanCryptoAndAntiSignatures(const uint8_t* data, size_t size, const std::vector<SectionInfo>& sections, std::vector<CryptoDetection>& outDetections) {
    outDetections.clear();
    for (const auto& sig : g_CryptoAndAntiSignatures) {
        auto pat = ParseAOBPattern(sig.pattern);
        auto matches = ScanBinaryAOB(data, size, pat);
        for (size_t offset : matches) {
            CryptoDetection cd;
            cd.name = sig.name;
            cd.type = sig.category;
            cd.offset = offset;
            cd.rva = FileOffsetToRva(static_cast<DWORD>(offset), sections);
            cd.sectionName = GetSectionNameByOffset(static_cast<DWORD>(offset), sections);
            outDetections.push_back(cd);
        }
    }
}

struct DecodedInsn {
    size_t length;
    std::wstring text;
    std::wstring bytesHex;
    bool isJump;
    bool isConditionalJump;
    uint8_t invertOpcode;
    size_t invertOpcodeOffset;
};

DecodedInsn FullDecodeInstruction(const uint8_t* code, size_t maxLen, ULONGLONG currentAddr, bool is64Bit) {
    if (maxLen == 0) return { 1, L"db ??", L"??", false, false, 0, 0 };

    size_t idx = 0;
    bool hasRex = false;
    uint8_t rex = 0;

    if (is64Bit && (code[idx] >= 0x40 && code[idx] <= 0x4F)) {
        hasRex = true;
        rex = code[idx++];
        if (idx >= maxLen) return { 1, L"rex prefix", L"40", false, false, 0, 0 };
    }

    uint8_t op = code[idx++];
    std::wstringstream disasm;
    size_t insnLen = idx;
    bool isJmp = false;
    bool isCondJmp = false;
    uint8_t invertOp = 0;
    size_t invertOffset = (hasRex ? 1 : 0);

    if (op >= 0x70 && op <= 0x7F) {
        isJmp = true;
        isCondJmp = true;
        invertOp = (op % 2 == 0) ? (op + 1) : (op - 1); // JZ (74) <-> JNZ (75), etc.

        const wchar_t* jccNames[] = {
            L"jo", L"jno", L"jb", L"jnb", L"jz", L"jnz", L"jbe", L"ja",
            L"js", L"jns", L"jp", L"jnp", L"jl", L"jge", L"jle", L"jg"
        };
        if (idx < maxLen) {
            int8_t rel = static_cast<int8_t>(code[idx++]);
            insnLen = idx;
            ULONGLONG target = currentAddr + insnLen + rel;
            disasm << jccNames[op - 0x70] << L" short 0x" << std::hex << target;
        }
        else {
            disasm << jccNames[op - 0x70] << L" short ...";
        }
    }
    else if (op == 0x0F && idx < maxLen && (code[idx] >= 0x80 && code[idx] <= 0x8F)) {
        uint8_t op2 = code[idx++];
        isJmp = true;
        isCondJmp = true;
        invertOp = (op2 % 2 == 0) ? (op2 + 1) : (op2 - 1);
        invertOffset = (hasRex ? 2 : 1);

        const wchar_t* jccNames[] = {
            L"jo", L"jno", L"jb", L"jnb", L"jz", L"jnz", L"jbe", L"ja",
            L"js", L"jns", L"jp", L"jnp", L"jl", L"jge", L"jle", L"jg"
        };
        if (idx + 4 <= maxLen) {
            int32_t rel = *reinterpret_cast<const int32_t*>(code + idx);
            idx += 4;
            insnLen = idx;
            ULONGLONG target = currentAddr + insnLen + rel;
            disasm << jccNames[op2 - 0x80] << L" near 0x" << std::hex << target;
        }
        else {
            disasm << jccNames[op2 - 0x80] << L" near ...";
        }
    }
    else {
        switch (op) {
        case 0x90:
            disasm << L"nop";
            break;
        case 0xC3:
            disasm << L"ret";
            break;
        case 0xCC:
            disasm << L"int 3";
            break;
        case 0xEB: {
            isJmp = true;
            if (idx < maxLen) {
                int8_t rel = static_cast<int8_t>(code[idx++]);
                insnLen = idx;
                disasm << L"jmp short 0x" << std::hex << (currentAddr + insnLen + rel);
            }
            else disasm << L"jmp short ...";
            break;
        }
        case 0xE9: {
            isJmp = true;
            if (idx + 4 <= maxLen) {
                int32_t rel = *reinterpret_cast<const int32_t*>(code + idx);
                idx += 4;
                insnLen = idx;
                disasm << L"jmp 0x" << std::hex << (currentAddr + insnLen + rel);
            }
            else disasm << L"jmp ...";
            break;
        }
        case 0xE8: {
            if (idx + 4 <= maxLen) {
                int32_t rel = *reinterpret_cast<const int32_t*>(code + idx);
                idx += 4;
                insnLen = idx;
                disasm << L"call 0x" << std::hex << (currentAddr + insnLen + rel);
            }
            else disasm << L"call ...";
            break;
        }
        case 0x85: case 0x84: {
            if (idx < maxLen) {
                uint8_t modrm = code[idx++];
                insnLen = idx;
                if (modrm == 0xC0) disasm << L"test eax, eax";
                else if (modrm == 0xC9) disasm << L"test ecx, ecx";
                else disasm << L"test reg, reg";
            }
            else disasm << L"test ...";
            break;
        }
        case 0x31: case 0x33: {
            if (idx < maxLen) {
                uint8_t modrm = code[idx++];
                insnLen = idx;
                if (modrm == 0xC0) disasm << L"xor eax, eax";
                else if (modrm == 0xDB) disasm << L"xor ebx, ebx";
                else if (modrm == 0xC9) disasm << L"xor ecx, ecx";
                else disasm << L"xor reg, reg";
            }
            else disasm << L"xor ...";
            break;
        }
        case 0x8B: {
            if (idx < maxLen) {
                uint8_t modrm = code[idx++];
                insnLen = idx;
                if (is64Bit && (modrm & 0xC7) == 0x05 && idx + 4 <= maxLen) { 
                    int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                    idx += 4;
                    insnLen = idx;
                    disasm << L"mov reg, [rip + 0x" << std::hex << (currentAddr + insnLen + disp) << L"]";
                }
                else if (modrm == 0xEC) {
                    disasm << (is64Bit ? L"mov rbp, rsp" : L"mov ebp, esp");
                }
                else {
                    disasm << L"mov reg, [modrm]";
                }
            }
            else disasm << L"mov ...";
            break;
        }
        case 0x8D: {
            if (idx < maxLen) {
                uint8_t modrm = code[idx++];
                insnLen = idx;
                if (is64Bit && (modrm & 0xC7) == 0x05 && idx + 4 <= maxLen) {
                    int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                    idx += 4;
                    insnLen = idx;
                    disasm << L"lea reg, [rip + 0x" << std::hex << (currentAddr + insnLen + disp) << L"]";
                }
                else {
                    disasm << L"lea reg, [modrm]";
                }
            }
            else disasm << L"lea ...";
            break;
        }
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: {
            const wchar_t* r[] = { L"rax/eax", L"rcx/ecx", L"rdx/edx", L"rbx/ebx", L"rsp/esp", L"rbp/ebp", L"rsi/esi", L"rdi/edi" };
            disasm << L"push " << r[op - 0x50];
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            const wchar_t* r[] = { L"rax/eax", L"rcx/ecx", L"rdx/edx", L"rbx/ebx", L"rsp/esp", L"rbp/ebp", L"rsi/esi", L"rdi/edi" };
            disasm << L"pop " << r[op - 0x58];
            break;
        }
        default:
            disasm << L"db 0x" << std::hex << std::setw(2) << std::setfill(L'0') << (int)op;
            insnLen = 1;
            break;
        }
    }

    std::wstringstream hexStr;
    for (size_t b = 0; b < insnLen; ++b) {
        hexStr << std::hex << std::setw(2) << std::setfill(L'0') << (int)code[b] << L" ";
    }

    return { insnLen, disasm.str(), hexStr.str(), isJmp, isCondJmp, invertOp, invertOffset };
}

bool ParsePEBinary(const uint8_t* base, size_t fileSize, PEAnalysisReport& outReport) {
    outReport = PEAnalysisReport{};
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dosHeader->e_lfanew <= 0 || static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > fileSize) return false;

    const auto* ntSignature = reinterpret_cast<const DWORD*>(base + dosHeader->e_lfanew);
    if (*ntSignature != IMAGE_NT_SIGNATURE) return false;

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + dosHeader->e_lfanew + sizeof(DWORD));
    outReport.machine = fileHeader->Machine;

    const uint8_t* optHeaderPtr = base + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* optCommon = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optHeaderPtr);

    const IMAGE_DATA_DIRECTORY* dataDirs = nullptr;
    const IMAGE_SECTION_HEADER* sectionHeaders = nullptr;
    WORD dllCharacteristics = 0;

    if (optCommon->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (static_cast<size_t>(dosHeader->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) > fileSize) return false;
        outReport.is64Bit = true;
        const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optHeaderPtr);
        outReport.entryPointRva = opt64->AddressOfEntryPoint;
        outReport.imageBase = opt64->ImageBase;
        outReport.sizeOfImage = opt64->SizeOfImage;
        outReport.originalCheckSum = opt64->CheckSum;
        outReport.checkSumOffset = static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt64->CheckSum) - base);
        dllCharacteristics = opt64->DllCharacteristics;
        dataDirs = opt64->DataDirectory;
        sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(optHeaderPtr + fileHeader->SizeOfOptionalHeader);
    }
    else if (optCommon->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (static_cast<size_t>(dosHeader->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) > fileSize) return false;
        outReport.is64Bit = false;
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optHeaderPtr);
        outReport.entryPointRva = opt32->AddressOfEntryPoint;
        outReport.imageBase = opt32->ImageBase;
        outReport.sizeOfImage = opt32->SizeOfImage;
        outReport.originalCheckSum = opt32->CheckSum;
        outReport.checkSumOffset = static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt32->CheckSum) - base);
        dllCharacteristics = opt32->DllCharacteristics;
        dataDirs = opt32->DataDirectory;
        sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(optHeaderPtr + fileHeader->SizeOfOptionalHeader);
    }
    else {
        return false;
    }

    outReport.security.aslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    outReport.security.highEntropyVA = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    outReport.security.dep = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    outReport.security.safeSEH = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
    outReport.security.controlFlowGuard = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    outReport.security.noIsolation = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0;

    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const auto& sec = sectionHeaders[i];
        char nameBuf[9] = { 0 };
        memcpy(nameBuf, sec.Name, 8);

        SectionInfo sInfo;
        sInfo.name = nameBuf;
        sInfo.virtualAddress = sec.VirtualAddress;
        sInfo.virtualSize = sec.Misc.VirtualSize;
        sInfo.rawDataOffset = sec.PointerToRawData;
        sInfo.rawDataSize = sec.SizeOfRawData;
        sInfo.characteristics = sec.Characteristics;

        if (sInfo.rawDataOffset < fileSize && sInfo.rawDataSize > 0) {
            size_t validRawSize = std::min<size_t>(sInfo.rawDataSize, fileSize - sInfo.rawDataOffset);
            sInfo.entropy = CalculateShannonEntropy(base + sInfo.rawDataOffset, validRawSize);
            sInfo.isSuspiciousEntropy = (sInfo.entropy > 7.2);
        }
        outReport.sections.push_back(sInfo);
    }

    outReport.entryPointOffset = RvaToFileOffset(outReport.entryPointRva, outReport.sections, fileSize);
    outReport.overallEntropy = CalculateShannonEntropy(base, fileSize);

    const auto& importDir = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
        DWORD impOff = RvaToFileOffset(importDir.VirtualAddress, outReport.sections, fileSize);
        if (impOff) {
            const auto* impDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + impOff);
            while (impDesc->Characteristics != 0 || impDesc->Name != 0) {
                DWORD modNameOff = RvaToFileOffset(impDesc->Name, outReport.sections, fileSize);
                if (modNameOff && modNameOff < fileSize) {
                    ImportModule mod;
                    mod.dllName = reinterpret_cast<const char*>(base + modNameOff);
                    DWORD thunkRva = impDesc->OriginalFirstThunk ? impDesc->OriginalFirstThunk : impDesc->FirstThunk;
                    DWORD thunkOff = RvaToFileOffset(thunkRva, outReport.sections, fileSize);

                    if (thunkOff) {
                        if (outReport.is64Bit) {
                            const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(base + thunkOff);
                            while (thunk->u1.AddressOfData != 0) {
                                ImportFunction ifn;
                                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                                    ifn.isOrdinal = true;
                                    ifn.ordinal = static_cast<WORD>(IMAGE_ORDINAL64(thunk->u1.Ordinal));
                                }
                                else {
                                    DWORD ibnOff = RvaToFileOffset(static_cast<DWORD>(thunk->u1.AddressOfData), outReport.sections, fileSize);
                                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= fileSize) {
                                        const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + ibnOff);
                                        ifn.name = reinterpret_cast<const char*>(ibn->Name);
                                    }
                                }
                                auto it = g_SensitiveApiMap.find(ifn.name);
                                if (it != g_SensitiveApiMap.end()) {
                                    ifn.risk = it->second.risk;
                                    ifn.category = it->second.category;
                                    mod.sensitiveCount++;
                                }
                                mod.functions.push_back(ifn);
                                thunk++;
                            }
                        }
                        else {
                            const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(base + thunkOff);
                            while (thunk->u1.AddressOfData != 0) {
                                ImportFunction ifn;
                                if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
                                    ifn.isOrdinal = true;
                                    ifn.ordinal = static_cast<WORD>(IMAGE_ORDINAL32(thunk->u1.Ordinal));
                                }
                                else {
                                    DWORD ibnOff = RvaToFileOffset(thunk->u1.AddressOfData, outReport.sections, fileSize);
                                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= fileSize) {
                                        const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + ibnOff);
                                        ifn.name = reinterpret_cast<const char*>(ibn->Name);
                                    }
                                }
                                auto it = g_SensitiveApiMap.find(ifn.name);
                                if (it != g_SensitiveApiMap.end()) {
                                    ifn.risk = it->second.risk;
                                    ifn.category = it->second.category;
                                    mod.sensitiveCount++;
                                }
                                mod.functions.push_back(ifn);
                                thunk++;
                            }
                        }
                    }
                    outReport.imports.push_back(mod);
                }
                impDesc++;
            }
        }
    }
    return true;
}

void RichEditClear(HWND hRichEdit) {
    SetWindowTextW(hRichEdit, L"");
}

void RichEditAppend(HWND hRichEdit, const std::wstring& text, COLORREF color = RGB(220, 220, 220), bool bold = false) {
    CHARRANGE cr;
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessageW(hRichEdit, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&cr));

    CHARFORMAT2W cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BOLD | CFM_FACE | CFM_SIZE;
    cf.crTextColor = color;
    cf.dwEffects = bold ? CFE_BOLD : 0;
    cf.yHeight = 190;
    wcscpy_s(cf.szFaceName, L"Consolas");

    SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&cf));
    SendMessageW(hRichEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(hRichEdit, WM_VSCROLL, SB_BOTTOM, 0);
}

std::wstring GenerateMemoryLoaderCode(const std::wstring& targetExePath, DWORD rvaOffset, const std::vector<uint8_t>& patchBytes) {
    std::wstringstream ss;

    // Находим последний слэш в пути и берём только имя файла
    size_t lastSlash = targetExePath.find_last_of(L"\\/");
    std::wstring exeName = (lastSlash == std::wstring::npos) ? targetExePath : targetExePath.substr(lastSlash + 1);

    ss << L"// ====================================================\r\n";

    ss << L"// ============================================================================\r\n";
    ss << L"// IN-MEMORY SUSPENDED PROCESS LOADER (AXIANWARE)\r\n";
    ss << L"// Target: " << exeName << L" | Target RVA: 0x" << std::hex << std::uppercase << rvaOffset << L"\r\n";
    ss << L"// ============================================================================\r\n\r\n";
    ss << L"#include <windows.h>\r\n#include <iostream>\r\n#include <vector>\r\n\r\n";
    ss << L"int main() {\r\n";
    ss << L"    STARTUPINFOW si = { sizeof(si) };\r\n    PROCESS_INFORMATION pi = { 0 };\r\n";
    ss << L"    if (!CreateProcessW(L\"" << exeName << L"\", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {\r\n";
    ss << L"        std::wcout << L\"[-] Failed to spawn process! Error: \" << GetLastError() << std::endl;\r\n        return 1;\r\n    }\r\n\r\n";
    ss << L"    DWORD_PTR targetAddr = 0x" << std::hex << g_report.imageBase << L" + 0x" << rvaOffset << L";\r\n";
    ss << L"    std::vector<uint8_t> patch = { ";
    for (size_t i = 0; i < patchBytes.size(); ++i) {
        ss << L"0x" << std::hex << std::setw(2) << std::setfill(L'0') << (int)patchBytes[i];
        if (i + 1 < patchBytes.size()) ss << L", ";
    }
    ss << L" };\r\n\r\n";
    ss << L"    DWORD oldProt = 0;\r\n    VirtualProtectEx(pi.hProcess, (LPVOID)targetAddr, patch.size(), PAGE_EXECUTE_READWRITE, &oldProt);\r\n";
    ss << L"    WriteProcessMemory(pi.hProcess, (LPVOID)targetAddr, patch.data(), patch.size(), nullptr);\r\n";
    ss << L"    VirtualProtectEx(pi.hProcess, (LPVOID)targetAddr, patch.size(), oldProt, &oldProt);\r\n";
    ss << L"    ResumeThread(pi.hThread);\r\n    CloseHandle(pi.hThread);\r\n    CloseHandle(pi.hProcess);\r\n";
    ss << L"    return 0;\r\n}\r\n";
    return ss.str();
}

std::wstring GenerateMinHookDllCode(DWORD rvaOffset) {
    std::wstringstream ss;
    ss << L"// ============================================================================\r\n";
    ss << L"// MINHOOK INLINE HOOK DLL TEMPLATE (AXIANWARE)\r\n";
    ss << L"// Target RVA: 0x" << std::hex << std::uppercase << rvaOffset << L"\r\n";
    ss << L"// ============================================================================\r\n\r\n";
    ss << L"#include <windows.h>\r\n#include \"MinHook.h\"\r\n\r\n";
    ss << L"typedef BOOL(WINAPI* tTargetFunc)();\r\n";
    ss << L"tTargetFunc oTargetFunc = nullptr;\r\n\r\n";
    ss << L"BOOL WINAPI hkTargetFunc() {\r\n";
    ss << L"    // Custom hook logic / payload here\r\n";
    ss << L"    return TRUE; // Bypass original check\r\n";
    ss << L"}\r\n\r\n";
    ss << L"DWORD WINAPI InitHookThread(LPVOID) {\r\n";
    ss << L"    if (MH_Initialize() != MH_OK) return 1;\r\n";
    ss << L"    uintptr_t base = (uintptr_t)GetModuleHandleW(nullptr);\r\n";
    ss << L"    void* target = (void*)(base + 0x" << std::hex << rvaOffset << L");\r\n";
    ss << L"    MH_CreateHook(target, &hkTargetFunc, reinterpret_cast<LPVOID*>(&oTargetFunc));\r\n";
    ss << L"    MH_EnableHook(target);\r\n";
    ss << L"    return 0;\r\n";
    ss << L"}\r\n\r\n";
    ss << L"BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {\r\n";
    ss << L"    if (reason == DLL_PROCESS_ATTACH) {\r\n";
    ss << L"        DisableThreadLibraryCalls(hMod);\r\n";
    ss << L"        CreateThread(nullptr, 0, InitHookThread, nullptr, 0, nullptr);\r\n";
    ss << L"    }\r\n";
    ss << L"    return TRUE;\r\n";
    ss << L"}\r\n";
    return ss.str();
}

std::wstring GenerateMemoryLoaderCode(const std::wstring& targetExePath, DWORD rvaOffset, const std::vector<uint8_t>& patchBytes) {
    std::wstringstream ss;

    // Находим последний слэш в пути и берём только имя файла
    size_t lastSlash = targetExePath.find_last_of(L"\\/");
    std::wstring exeName = (lastSlash == std::wstring::npos) ? targetExePath : targetExePath.substr(lastSlash + 1);

    ss << L"// ====================================================\r\n";

    if (g_stagedPatches.empty()) {
        ss << L"00001000:74->75\r\n";
    }
    else {
        for (const auto& kv : g_stagedPatches) {
            ss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8) << kv.first << L":"
                << std::setw(2) << (int)kv.second.first << L"->"
                << std::setw(2) << (int)kv.second.second << L"\r\n";
        }
    }
    return ss.str();
}

std::wstring GenerateCheatEngineScript(DWORD rvaOffset, const std::vector<uint8_t>& patchBytes) {
    std::wstringstream ss;
    ss << L"[ENABLE]\r\n";
    ss << L"// Allocating and applying patch at RVA 0x" << std::hex << std::uppercase << rvaOffset << L"\r\n";
    ss << L"define(targetAddr, \"target.exe\"+0x" << std::hex << rvaOffset << L")\r\n";
    ss << L"targetAddr:\r\n  db ";
    for (size_t i = 0; i < patchBytes.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)patchBytes[i] << L" ";
    }
    ss << L"\r\n\r\n[DISABLE]\r\n";
    ss << L"targetAddr:\r\n  // Restore original bytes\r\n";
    return ss.str();
}


void RenderSummaryReport(HWND hRichEdit, const std::wstring& filePath, const PEAnalysisReport& rep) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"================================================================================\r\n", RGB(0, 150, 255), true);
    RichEditAppend(hRichEdit, L"                     AXIANWARE                       \r\n", RGB(0, 255, 200), true);
    RichEditAppend(hRichEdit, L"================================================================================\r\n\r\n", RGB(0, 150, 255), true);

    RichEditAppend(hRichEdit, L"[+] File Path:       ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, filePath + L"\r\n", RGB(255, 255, 255));

    RichEditAppend(hRichEdit, L"[+] Architecture:    ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, rep.is64Bit ? L"AMD64 / x64 (PE32+)\r\n" : L"i386 / x86 (PE32)\r\n", RGB(255, 255, 255));

    std::wstringstream ep;
    ep << L"0x" << std::hex << std::uppercase << rep.entryPointRva << L" (File Raw Offset: 0x" << rep.entryPointOffset << L")\r\n";
    RichEditAppend(hRichEdit, L"[+] Entry Point:     ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, ep.str(), RGB(255, 255, 255));

    std::wstringstream chk;
    chk << L"0x" << std::hex << std::uppercase << rep.originalCheckSum << L"\r\n";
    RichEditAppend(hRichEdit, L"[+] PE CheckSum:     ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, chk.str(), RGB(255, 255, 255));

    std::wstringstream ent;
    ent << std::fixed << std::setprecision(4) << rep.overallEntropy;
    RichEditAppend(hRichEdit, L"[+] Total Entropy:   ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, ent.str() + (rep.overallEntropy > 7.2 ? L" [ALERT: Packed / Encrypted]\r\n\r\n" : L" [Normal]\r\n\r\n"),
        rep.overallEntropy > 7.2 ? RGB(255, 80, 80) : RGB(100, 255, 100));

    RichEditAppend(hRichEdit, L"--- [ SECURITY MITIGATIONS AUDIT ] --------------------------------------------\r\n", RGB(100, 200, 255), true);
    RichEditAppend(hRichEdit, L"  [*] ASLR (Dynamic Base):            ", RGB(200, 200, 200));
    RichEditAppend(hRichEdit, rep.security.aslr ? L"ENABLED\r\n" : L"DISABLED\r\n", rep.security.aslr ? RGB(100, 255, 100) : RGB(255, 80, 80), true);

    RichEditAppend(hRichEdit, L"  [*] DEP / NX (Data Execution Prev): ", RGB(200, 200, 200));
    RichEditAppend(hRichEdit, rep.security.dep ? L"ENABLED\r\n" : L"DISABLED\r\n", rep.security.dep ? RGB(100, 255, 100) : RGB(255, 80, 80), true);

    RichEditAppend(hRichEdit, L"  [*] Control Flow Guard (CFG):       ", RGB(200, 200, 200));
    RichEditAppend(hRichEdit, rep.security.controlFlowGuard ? L"ENABLED\r\n" : L"DISABLED\r\n", rep.security.controlFlowGuard ? RGB(100, 255, 100) : RGB(160, 160, 160));

    RichEditAppend(hRichEdit, L"  [*] SafeSEH Mitigation:             ", RGB(200, 200, 200));
    RichEditAppend(hRichEdit, rep.security.safeSEH ? L"ENABLED / N/A (x64)\r\n\r\n" : L"DISABLED / NO SEH\r\n\r\n", rep.security.safeSEH ? RGB(100, 255, 100) : RGB(255, 180, 80));

    RichEditAppend(hRichEdit, L"--- [ SECTION ENTROPY TABLE ] -------------------------------------------------\r\n", RGB(100, 200, 255), true);
    for (const auto& sec : rep.sections) {
        std::wstringstream ss;
        ss << L"  " << std::left << std::setw(8) << std::wstring(sec.name.begin(), sec.name.end())
            << L" | VirtAddr: 0x" << std::hex << std::setw(8) << sec.virtualAddress
            << L" | RawOffset: 0x" << std::hex << std::setw(8) << sec.rawDataOffset
            << L" | Entropy: " << std::fixed << std::setprecision(4) << sec.entropy;
        if (sec.isSuspiciousEntropy) ss << L" [PACKED / OBFUSCATED]";
        ss << L"\r\n";
        RichEditAppend(hRichEdit, ss.str(), sec.isSuspiciousEntropy ? RGB(255, 80, 80) : RGB(200, 200, 200), sec.isSuspiciousEntropy);
    }
}

void RenderDisassemblyView(HWND hRichEdit, const uint8_t* base, size_t fileSize, DWORD targetOffset, DWORD targetRva, size_t instructionCount = 36) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"================================================================================\r\n", RGB(0, 150, 255), true);
    RichEditAppend(hRichEdit, L"             INTERACTIVE DISASSEMBLY & CODE PATCHING VIEW                       \r\n", RGB(0, 255, 200), true);
    RichEditAppend(hRichEdit, L"================================================================================\r\n\r\n", RGB(0, 150, 255), true);

    if (targetOffset >= fileSize) {
        RichEditAppend(hRichEdit, L"[-] Error: Target offset is outside valid file boundaries.\r\n", RGB(255, 80, 80));
        return;
    }

    size_t currOffset = targetOffset;
    ULONGLONG currRva = targetRva;

    for (size_t i = 0; i < instructionCount && currOffset < fileSize; ++i) {
        size_t bytesLeft = fileSize - currOffset;
        DecodedInsn insn = FullDecodeInstruction(base + currOffset, bytesLeft, currRva, g_report.is64Bit);

        std::wstringstream ss;
        ss << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << currRva
            << L" (Raw: 0x" << std::setw(8) << currOffset << L")  "
            << std::left << std::setw(18) << std::setfill(L' ') << insn.bytesHex
            << L"  " << insn.text;

        if (insn.isConditionalJump) {
            ss << L"  [Can Invert Jcc]";
        }
        ss << L"\r\n";

        RichEditAppend(hRichEdit, ss.str(), insn.isConditionalJump ? RGB(255, 180, 80) : ((i == 0) ? RGB(255, 255, 0) : RGB(200, 220, 255)));
        currOffset += insn.length;
        currRva += insn.length;
    }
}

void UpdateListViewItems(HWND hListView, const PEAnalysisReport& rep) {
    ListView_DeleteAllItems(hListView);
    LVITEMW item;
    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_TEXT;

    int idx = 0;
    auto AddRow = [&](const std::wstring& cat, const std::wstring& name, const std::wstring& val, const std::wstring& extra) {
        item.iItem = idx;
        item.pszText = const_cast<LPWSTR>(cat.c_str());
        ListView_InsertItem(hListView, &item);
        ListView_SetItemText(hListView, idx, 1, const_cast<LPWSTR>(name.c_str()));
        ListView_SetItemText(hListView, idx, 2, const_cast<LPWSTR>(val.c_str()));
        ListView_SetItemText(hListView, idx, 3, const_cast<LPWSTR>(extra.c_str()));
        idx++;
        };

    for (const auto& sec : rep.sections) {
        std::wstringstream val, extra;
        val << L"RVA: 0x" << std::hex << sec.virtualAddress << L" | Raw: 0x" << sec.rawDataOffset;
        extra << L"Entropy: " << std::fixed << std::setprecision(2) << sec.entropy << (sec.isSuspiciousEntropy ? L" [HIGH]" : L"");
        AddRow(L"Section", std::wstring(sec.name.begin(), sec.name.end()), val.str(), extra.str());
    }

    for (const auto& imp : rep.imports) {
        std::wstring alert = imp.sensitiveCount > 0 ? (L"ALERT: " + std::to_wstring(imp.sensitiveCount) + L" High Risk API") : L"Normal";
        AddRow(L"Import DLL", std::wstring(imp.dllName.begin(), imp.dllName.end()),
            std::to_wstring(imp.functions.size()) + L" Functions", alert);
    }

    for (const auto& cd : rep.cryptoDetections) {
        std::wstringstream val;
        val << L"Raw: 0x" << std::hex << cd.offset << L" | RVA: 0x" << cd.rva;
        AddRow(cd.type, cd.name, val.str(), L"Sec: " + std::wstring(cd.sectionName.begin(), cd.sectionName.end()));
    }
}

void UpdateStatusBar(HWND hStatusBar, const std::wstring& status, const PEAnalysisReport& rep) {
    SendMessageW(hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(status.c_str()));
    std::wstring arch = rep.is64Bit ? L"x64 (PE32+)" : L"x86 (PE32)";
    SendMessageW(hStatusBar, SB_SETTEXT, 1, reinterpret_cast<LPARAM>(arch.c_str()));

    std::wstringstream ent;
    ent << L"Entropy: " << std::fixed << std::setprecision(2) << rep.overallEntropy;
    SendMessageW(hStatusBar, SB_SETTEXT, 2, reinterpret_cast<LPARAM>(ent.str().c_str()));

    std::wstring patch = rep.isPatched ? (L"MODIFIED (" + std::to_wstring(g_stagedPatches.size()) + L" B)") : L"CLEAN";
    SendMessageW(hStatusBar, SB_SETTEXT, 3, reinterpret_cast<LPARAM>(patch.c_str()));
}

void AsyncSearchPatternThread(HWND hWnd, std::wstring filePath, std::wstring patternStr) {
    SendMessageW(g_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Scanning pattern in background..."));

    MemoryMappedFile mmf;
    if (!mmf.Open(filePath)) {
        PostMessageW(hWnd, WM_APP_ASYNC_STATUS, 0, reinterpret_cast<LPARAM>(new std::wstring(L"Failed to open file for pattern scan")));
        return;
    }

    auto pattern = ParseAOBPattern(patternStr);
    auto matches = ScanBinaryAOB(mmf.Data(), mmf.Size(), pattern);

    auto* pMatches = new std::vector<size_t>(std::move(matches));
    PostMessageW(hWnd, WM_APP_AOB_COMPLETE, 0, reinterpret_cast<LPARAM>(pMatches));
}

void AsyncStringExtractThread(HWND hWnd, std::wstring filePath) {
    SendMessageW(g_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Extracting strings in background..."));

    MemoryMappedFile mmf;
    if (!mmf.Open(filePath)) return;

    auto* pStrings = new std::vector<ExtractedString>();
    const uint8_t* data = mmf.Data();
    size_t size = mmf.Size();

    std::string currAscii;
    size_t asciiStart = 0;
    for (size_t i = 0; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c <= 126) {
            if (currAscii.empty()) asciiStart = i;
            currAscii += c;
        }
        else {
            if (currAscii.length() >= 4) {
                ExtractedString es;
                es.offset = asciiStart;
                es.rva = FileOffsetToRva(static_cast<DWORD>(asciiStart), g_report.sections);
                es.text = std::wstring(currAscii.begin(), currAscii.end());
                es.isUnicode = false;
                es.sectionName = GetSectionNameByOffset(static_cast<DWORD>(asciiStart), g_report.sections);
                pStrings->push_back(es);
            }
            currAscii.clear();
        }
    }

    PostMessageW(hWnd, WM_APP_STRINGS_COMPLETE, 0, reinterpret_cast<LPARAM>(pStrings));
}

void AsyncCryptoScanThread(HWND hWnd, std::wstring filePath) {
    SendMessageW(g_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Auditing Crypto & Anti-Analysis signatures..."));

    MemoryMappedFile mmf;
    if (!mmf.Open(filePath)) return;

    auto* pDetections = new std::vector<CryptoDetection>();
    ScanCryptoAndAntiSignatures(mmf.Data(), mmf.Size(), g_report.sections, *pDetections);

    PostMessageW(hWnd, WM_APP_CRYPTO_COMPLETE, 0, reinterpret_cast<LPARAM>(pDetections));
}

bool SavePatchedBinaryFile(const std::wstring& srcPath, const std::wstring& dstPath) {
    MemoryMappedFile srcMmf;
    if (!srcMmf.Open(srcPath)) return false;

    std::vector<uint8_t> fileBuffer(srcMmf.Data(), srcMmf.Data() + srcMmf.Size());
    srcMmf.Close();

    for (const auto& p : g_stagedPatches) {
        if (p.first < fileBuffer.size()) {
            fileBuffer[p.first] = p.second.second;
        }
    }

    if (g_report.checkSumOffset > 0 && g_report.checkSumOffset + sizeof(DWORD) <= fileBuffer.size()) {
        DWORD newChecksum = CalculatePECheckSum(fileBuffer.data(), fileBuffer.size(), g_report.checkSumOffset);
        *reinterpret_cast<DWORD*>(fileBuffer.data() + g_report.checkSumOffset) = newChecksum;
    }

    ScopedHandle hOut(CreateFileW(dstPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hOut.IsValid()) return false;

    DWORD written = 0;
    BOOL bSuccess = WriteFile(hOut.Get(), fileBuffer.data(), static_cast<DWORD>(fileBuffer.size()), &written, nullptr);
    return (bSuccess && written == fileBuffer.size());
}

void OnFileOpen(HWND hWnd) {
    wchar_t szFile[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"PE Executables (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        g_currentFilePath = szFile;
        g_stagedPatches.clear();

        MemoryMappedFile mmf;
        if (!mmf.Open(g_currentFilePath)) {
            MessageBoxW(hWnd, L"Failed to map target file.", L"File Error", MB_ICONERROR);
            return;
        }

        if (!ParsePEBinary(mmf.Data(), mmf.Size(), g_report)) {
            MessageBoxW(hWnd, L"Invalid Portable Executable (PE) binary header.", L"Parser Error", MB_ICONERROR);
            return;
        }

        UpdateListViewItems(g_hListView, g_report);
        RenderSummaryReport(g_hRichEdit, g_currentFilePath, g_report);
        UpdateStatusBar(g_hStatusBar, L"Binary Loaded Successfully", g_report);

        std::thread(AsyncCryptoScanThread, hWnd, g_currentFilePath).detach();
    }
}

void OnFileSaveAs(HWND hWnd) {
    if (g_currentFilePath.empty()) {
        MessageBoxW(hWnd, L"No active binary file loaded.", L"Save Error", MB_ICONWARNING);
        return;
    }

    wchar_t szOut[MAX_PATH] = { 0 };
    wcscpy_s(szOut, g_currentFilePath.c_str());

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"Executable Files (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szOut;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileNameW(&ofn)) {
        if (SavePatchedBinaryFile(g_currentFilePath, szOut)) {
            MessageBoxW(hWnd, L"Patched binary saved with recalculated PE CheckSum!", L"Saved", MB_ICONINFORMATION);
            UpdateStatusBar(g_hStatusBar, L"Binary Saved with Updated CheckSum", g_report);
        }
        else {
            MessageBoxW(hWnd, L"Failed to write patched binary to disk.", L"Error", MB_ICONERROR);
        }
    }
}

void OnInvertJumpAtTarget(HWND hWnd) {
    if (g_currentFilePath.empty()) return;

    MemoryMappedFile mmf;
    if (!mmf.Open(g_currentFilePath)) return;

    DWORD targetOffset = g_report.entryPointOffset;
    DecodedInsn insn = FullDecodeInstruction(mmf.Data() + targetOffset, mmf.Size() - targetOffset, g_report.entryPointRva, g_report.is64Bit);

    if (insn.isConditionalJump && insn.invertOpcode != 0) {
        DWORD patchOff = targetOffset + static_cast<DWORD>(insn.invertOpcodeOffset);
        uint8_t origByte = mmf.Data()[patchOff];
        g_stagedPatches[patchOff] = { origByte, insn.invertOpcode };
        g_report.isPatched = true;

        UpdateStatusBar(g_hStatusBar, L"Conditional Jump Inverted (Staged)", g_report);
        MessageBoxW(hWnd, L"Conditional Jump inverted in memory buffer!\nUse 'File -> Save Patched Binary As' to write changes.", L"Patch Staged", MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(hWnd, L"Instruction at current target is not an invertible conditional jump.", L"Info", MB_ICONINFORMATION);
    }
}


LRESULT CALLBACK MainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HMENU hMenuBar = CreateMenu();
        HMENU hMenuFile = CreatePopupMenu();
        AppendMenuW(hMenuFile, MF_STRING, IDM_FILE_OPEN, L"&Open Binary...\tCtrl+O");
        AppendMenuW(hMenuFile, MF_STRING, IDM_FILE_SAVE_AS, L"&Save Patched Binary As...\tCtrl+S");
        AppendMenuW(hMenuFile, MF_STRING, IDM_FILE_HEXVIEW, L"&Hex Viewer\tCtrl+H");
        AppendMenuW(hMenuFile, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenuFile, MF_STRING, IDM_FILE_EXIT, L"E&xit");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuFile), L"&File");

        HMENU hMenuAnalysis = CreatePopupMenu();
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_SUMMARY, L"&PE Headers & Security Info");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_IMPORTS, L"&Imported APIs (IAT)");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_STRINGS, L"&Extract Strings (Async)");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_CRYPTO_SCAN, L"&Crypto & Anti-Analysis Audit");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_DISASM_EP, L"&Disassemble Entry Point");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuAnalysis), L"&Analysis");

        HMENU hMenuPatch = CreatePopupMenu();
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_NOP_PROLOGUE, L"NOP Out Target (0x90 0x90)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_RET_PROLOGUE, L"Force Return (RET / 0xC3)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_INVERT_JUMP, L"Invert Conditional Jump (Jcc)");
        AppendMenuW(hMenuPatch, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_LOADER, L"&Generate In-Memory Loader (C++)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_MINHOOK, L"&Generate MinHook DLL Template");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_X64DBG, L"&Generate x64dbg Patch (.1337)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_CHEATENG, L"&Generate Cheat Engine Script");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuPatch), L"&Patch & Toolkit");

        HMENU hMenuHelp = CreatePopupMenu();
        AppendMenuW(hMenuHelp, MF_STRING, IDM_HELP_ABOUT, L"&About AXIANWARE...");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuHelp), L"&Help");

        SetMenu(hWnd, hMenuBar);


        g_hSearchEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"E8 ?? ?? ?? ?? 85 C0",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            5, 5, 340, 26, hWnd, reinterpret_cast<HMENU>(IDC_SEARCH_EDIT),
            GetModuleHandleW(nullptr), nullptr
        );

        g_hSearchBtn = CreateWindowExW(
            0, L"BUTTON", L"Find AOB",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            350, 5, 90, 26, hWnd, reinterpret_cast<HMENU>(IDC_SEARCH_BTN),
            GetModuleHandleW(nullptr), nullptr
        );

        g_hListView = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            0, 36, 440, 560, hWnd, reinterpret_cast<HMENU>(IDC_MAIN_LISTVIEW),
            GetModuleHandleW(nullptr), nullptr
        );
        ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        LVCOLUMNW lvc;
        ZeroMemory(&lvc, sizeof(lvc));
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        const wchar_t* headers[] = { L"Category", L"Name / Symbol", L"Address / Offset", L"Entropy & Attributes" };
        int widths[] = { 110, 140, 150, 120 };
        for (int i = 0; i < 4; ++i) {
            lvc.iSubItem = i;
            lvc.pszText = const_cast<LPWSTR>(headers[i]);
            lvc.cx = widths[i];
            ListView_InsertColumn(g_hListView, i, &lvc);
        }


        g_hRichEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            440, 0, 600, 600, hWnd, reinterpret_cast<HMENU>(IDC_MAIN_RICHEDIT),
            GetModuleHandleW(nullptr), nullptr
        );
        SendMessageW(g_hRichEdit, EM_SETBKGNDCOLOR, 0, RGB(20, 22, 26));


        g_hStatusBar = CreateWindowExW(
            0, STATUSCLASSNAMEW, nullptr,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hWnd, reinterpret_cast<HMENU>(IDC_MAIN_STATUSBAR),
            GetModuleHandleW(nullptr), nullptr
        );

        int statWidths[] = { 350, 500, 680, -1 };
        SendMessageW(g_hStatusBar, SB_SETPARTS, 4, reinterpret_cast<LPARAM>(statWidths));
        SendMessageW(g_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Ready"));
        return 0;
    }

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        SendMessageW(g_hStatusBar, WM_SIZE, wParam, lParam);
        RECT rcStatus;
        GetWindowRect(g_hStatusBar, &rcStatus);
        int statH = rcStatus.bottom - rcStatus.top;
        int clientH = height - statH;

        int calcW = width * 38 / 100;
        int ListWidth = (calcW > 360) ? calcW : 360;

        MoveWindow(g_hSearchBtn, ListWidth - 90, 5, 85, 26, TRUE);
        MoveWindow(g_hListView, 0, 36, ListWidth, clientH - 36, TRUE);
        MoveWindow(g_hRichEdit, ListWidth, 0, width - ListWidth, clientH, TRUE);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        auto* minMax = reinterpret_cast<MINMAXINFO*>(lParam);
        minMax->ptMinTrackSize.x = 850;
        minMax->ptMinTrackSize.y = 520;
        return 0;
    }

                         
    case WM_APP_AOB_COMPLETE: {
        std::unique_ptr<std::vector<size_t>> matches(reinterpret_cast<std::vector<size_t>*>(lParam));
        ListView_DeleteAllItems(g_hListView);
        LVITEMW item;
        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_TEXT;

        for (size_t i = 0; i < matches->size(); ++i) {
            size_t off = (*matches)[i];
            DWORD rva = FileOffsetToRva(static_cast<DWORD>(off), g_report.sections);
            std::string sec = GetSectionNameByOffset(static_cast<DWORD>(off), g_report.sections);

            std::wstringstream name, val, extra;
            name << L"Match #" << (i + 1);
            val << L"Raw: 0x" << std::hex << off << L" | RVA: 0x" << rva;
            extra << L"Sec: " << std::wstring(sec.begin(), sec.end());

            item.iItem = static_cast<int>(i);
            item.pszText = const_cast<LPWSTR>(L"AOB Match");
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, static_cast<int>(i), 1, const_cast<LPWSTR>(name.str().c_str()));
            ListView_SetItemText(g_hListView, static_cast<int>(i), 2, const_cast<LPWSTR>(val.str().c_str()));
            ListView_SetItemText(g_hListView, static_cast<int>(i), 3, const_cast<LPWSTR>(extra.str().c_str()));
        }
        UpdateStatusBar(g_hStatusBar, L"Found " + std::to_wstring(matches->size()) + L" AOB matches (Async)", g_report);
        return 0;
    }

    case WM_APP_STRINGS_COMPLETE: {
        std::unique_ptr<std::vector<ExtractedString>> pStrings(reinterpret_cast<std::vector<ExtractedString>*>(lParam));
        g_report.strings = std::move(*pStrings);

        RichEditClear(g_hRichEdit);
        RichEditAppend(g_hRichEdit, L"================================================================================\r\n", RGB(0, 150, 255), true);
        RichEditAppend(g_hRichEdit, L"                   ASYNC EXTRACTED STRINGS REFERENCES                           \r\n", RGB(0, 255, 200), true);
        RichEditAppend(g_hRichEdit, L"================================================================================\r\n\r\n", RGB(0, 150, 255), true);

        for (size_t i = 0; i < std::min<size_t>(g_report.strings.size(), 1200); ++i) {
            const auto& s = g_report.strings[i];
            std::wstringstream ss;
            ss << L"[" << (s.isUnicode ? L"UTF-16" : L"ASCII ") << L" 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << s.offset
                << L" | RVA: 0x" << std::setw(8) << s.rva << L"] " << s.text << L"\r\n";
            RichEditAppend(g_hRichEdit, ss.str(), s.isUnicode ? RGB(255, 215, 120) : RGB(180, 220, 255));
        }
        UpdateStatusBar(g_hStatusBar, L"Strings Extraction Complete", g_report);
        return 0;
    }

    case WM_APP_CRYPTO_COMPLETE: {
        std::unique_ptr<std::vector<CryptoDetection>> pDet(reinterpret_cast<std::vector<CryptoDetection>*>(lParam));
        g_report.cryptoDetections = std::move(*pDet);
        UpdateListViewItems(g_hListView, g_report);
        UpdateStatusBar(g_hStatusBar, L"Crypto & Anti-Analysis Audit Complete", g_report);
        return 0;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_SEARCH_BTN) {
            wchar_t patBuf[512] = { 0 };
            GetWindowTextW(g_hSearchEdit, patBuf, 512);
            std::thread(AsyncSearchPatternThread, hWnd, g_currentFilePath, std::wstring(patBuf)).detach();
            return 0;
        }

        switch (LOWORD(wParam)) {
        case IDM_FILE_OPEN:
            OnFileOpen(hWnd);
            break;
        case IDM_FILE_SAVE_AS:
            OnFileSaveAs(hWnd);
            break;
        case IDM_FILE_HEXVIEW: {
            MemoryMappedFile mmf;
            if (mmf.Open(g_currentFilePath)) {
                RichEditClear(g_hRichEdit);
                RichEditAppend(g_hRichEdit, L"=== RAW HEX MEMORY DUMP ===\r\n\r\n", RGB(0, 150, 255), true);
                std::wstringstream ss;
                size_t limit = std::min<size_t>(mmf.Size(), 4096);
                for (size_t i = 0; i < limit; i += 16) {
                    ss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8) << i << L"    ";
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < limit) ss << std::setw(2) << static_cast<int>(mmf.Data()[i + j]) << L" ";
                        else ss << L"   ";
                    }
                    ss << L"\r\n";
                }
                RichEditAppend(g_hRichEdit, ss.str(), RGB(0, 255, 128));
                UpdateStatusBar(g_hStatusBar, L"Hex View Active", g_report);
            }
            break;
        }
        case IDM_ANALYSIS_SUMMARY:
            RenderSummaryReport(g_hRichEdit, g_currentFilePath, g_report);
            break;
        case IDM_ANALYSIS_STRINGS:
            std::thread(AsyncStringExtractThread, hWnd, g_currentFilePath).detach();
            break;
        case IDM_ANALYSIS_CRYPTO_SCAN:
            std::thread(AsyncCryptoScanThread, hWnd, g_currentFilePath).detach();
            break;
        case IDM_ANALYSIS_DISASM_EP: {
            MemoryMappedFile mmf;
            if (mmf.Open(g_currentFilePath)) {
                RenderDisassemblyView(g_hRichEdit, mmf.Data(), mmf.Size(), g_report.entryPointOffset, g_report.entryPointRva);
                UpdateStatusBar(g_hStatusBar, L"Disassembly Active", g_report);
            }
            break;
        }
        case IDM_PATCH_NOP_PROLOGUE: {
            g_stagedPatches[g_report.entryPointOffset] = { 0, 0x90 };
            g_stagedPatches[g_report.entryPointOffset + 1] = { 0, 0x90 };
            g_report.isPatched = true;
            UpdateStatusBar(g_hStatusBar, L"NOP Sled Staged (Use Save As to apply)", g_report);
            MessageBoxW(hWnd, L"NOP sled staged in memory. Save binary to commit!", L"Staged", MB_ICONINFORMATION);
            break;
        }
        case IDM_PATCH_RET_PROLOGUE: {
            g_stagedPatches[g_report.entryPointOffset] = { 0, 0xC3 };
            g_report.isPatched = true;
            UpdateStatusBar(g_hStatusBar, L"RET Staged (Use Save As to apply)", g_report);
            MessageBoxW(hWnd, L"RET staged in memory. Save binary to commit!", L"Staged", MB_ICONINFORMATION);
            break;
        }
        case IDM_PATCH_INVERT_JUMP:
            OnInvertJumpAtTarget(hWnd);
            break;
        case IDM_PATCH_GEN_LOADER: {
            std::wstring code = GenerateMemoryLoaderCode(g_currentFilePath, g_report.entryPointRva, { 0x90, 0x90 });
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(220, 220, 220));
            break;
        }
        case IDM_PATCH_GEN_MINHOOK: {
            std::wstring code = GenerateMinHookDllCode(g_report.entryPointRva);
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(220, 220, 220));
            break;
        }
        case IDM_PATCH_GEN_X64DBG: {
            std::wstring code = Generate1337PatchText(g_currentFilePath);
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(100, 255, 100));
            break;
        }
        case IDM_PATCH_GEN_CHEATENG: {
            std::wstring code = GenerateCheatEngineScript(g_report.entryPointRva, { 0x90, 0x90 });
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(255, 215, 120));
            break;
        }
        case IDM_HELP_ABOUT:
            MessageBoxW(hWnd, L"AXIANWARE v2026.08.29\n created by eloyssync.", L"About", MB_ICONINFORMATION);
            break;
        case IDM_FILE_EXIT:
            PostMessageW(hWnd, WM_CLOSE, 0, 0);
            break;
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    g_hMsftedit = LoadLibraryW(L"msftedit.dll");
    if (!g_hMsftedit) return 1;

    const wchar_t CLASS_NAME[] = L"PEInspectorSuiteWindowClass";
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = MainWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassExW(&wc)) {
        FreeLibrary(g_hMsftedit);
        return 1;
    }

    g_hWndMain = CreateWindowExW(
        0, CLASS_NAME, L"AXIANWARE",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1140, 740,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWndMain) {
        FreeLibrary(g_hMsftedit);
        return 1;
    }

    ShowWindow(g_hWndMain, nCmdShow);
    UpdateWindow(g_hWndMain);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FreeLibrary(g_hMsftedit);
    return static_cast<int>(msg.wParam);
}