#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winnt.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace axianware {

// ---------------------------------------------------------------------------
// RAII Win32 handle
// ---------------------------------------------------------------------------
class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept;
    ~ScopedHandle();

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept;
    ScopedHandle& operator=(ScopedHandle&& other) noexcept;

    void Close() noexcept;
    [[nodiscard]] HANDLE Get() const noexcept;
    [[nodiscard]] bool IsValid() const noexcept;
    HANDLE Release() noexcept;

private:
    HANDLE m_handle;
};

// ---------------------------------------------------------------------------
// Memory-mapped PE / blob with optional write access
// ---------------------------------------------------------------------------
class MemoryMappedFile {
public:
    MemoryMappedFile() = default;
    ~MemoryMappedFile();

    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;
    MemoryMappedFile(MemoryMappedFile&&) noexcept;
    MemoryMappedFile& operator=(MemoryMappedFile&&) noexcept;

    [[nodiscard]] bool Open(const std::wstring& filePath, bool writeAccess = false);
    void Close() noexcept;

    [[nodiscard]] const uint8_t* Data() const noexcept;
    [[nodiscard]] uint8_t* WritableData() noexcept;
    [[nodiscard]] size_t Size() const noexcept;
    [[nodiscard]] bool IsOpen() const noexcept;
    [[nodiscard]] bool IsWritable() const noexcept;

    [[nodiscard]] bool Read(size_t offset, void* destination, size_t length) const;
    [[nodiscard]] bool Write(size_t offset, const void* source, size_t length);
    [[nodiscard]] bool BoundsCheck(size_t offset, size_t length) const noexcept;

private:
    ScopedHandle m_file;
    ScopedHandle m_mapping;
    LPVOID m_base = nullptr;
    size_t m_fileSize = 0;
    bool m_writable = false;
};

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------
enum class ApiRisk {
    Normal,
    MemoryAlloc,
    ProcessInject,
    ThreadControl,
    AntiDebug,
    Crypto,
    Suspicious
};

struct ApiMeta {
    ApiRisk risk;
    const wchar_t* category;
};

struct SectionInfo {
    std::string name;
    DWORD virtualAddress = 0;
    DWORD virtualSize = 0;
    DWORD rawDataOffset = 0;
    DWORD rawDataSize = 0;
    DWORD characteristics = 0;
    WORD sectionIndex = 0;
    DWORD headerFileOffset = 0;
    double entropy = 0.0;
    bool isSuspiciousEntropy = false;
};

struct ExportInfo {
    std::string name;
    WORD ordinal = 0;
    DWORD rva = 0;
    DWORD fileOffset = 0;
    bool isForwarded = false;
    std::string forwarder;
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

struct SecurityMitigations {
    bool aslr = false;
    bool highEntropyVA = false;
    bool dep = false;
    bool safeSEH = false;
    bool controlFlowGuard = false;
    bool noIsolation = false;
    WORD dllCharacteristics = 0;
};

struct OverlayInfo {
    bool present = false;
    DWORD offset = 0;
    DWORD size = 0;
    double entropy = 0.0;
};

struct RichHeaderEntry {
    WORD productId = 0;
    WORD buildNumber = 0;
    DWORD count = 0;
    std::wstring productName;
};

struct RichHeaderInfo {
    bool present = false;
    DWORD xorKey = 0;
    DWORD dansOffset = 0;
    DWORD richOffset = 0;
    std::vector<RichHeaderEntry> entries;
};

struct TlsCallbackInfo {
    ULONGLONG va = 0;
    DWORD rva = 0;
    DWORD fileOffset = 0;
};

struct TlsDirectoryInfo {
    bool present = false;
    ULONGLONG startAddressOfRawData = 0;
    ULONGLONG endAddressOfRawData = 0;
    ULONGLONG addressOfIndex = 0;
    ULONGLONG addressOfCallBacks = 0;
    DWORD sizeOfZeroFill = 0;
    DWORD characteristics = 0;
    std::vector<TlsCallbackInfo> callbacks;
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
    size_t offset = 0;
    DWORD rva = 0;
    std::string sectionName;
};

struct PEAnalysisReport {
    bool is64Bit = false;
    WORD machine = 0;
    WORD numberOfSections = 0;
    DWORD entryPointRva = 0;
    DWORD entryPointOffset = 0;
    ULONGLONG imageBase = 0;
    DWORD sizeOfImage = 0;
    DWORD sizeOfHeaders = 0;
    DWORD sectionAlignment = 0;
    DWORD fileAlignment = 0;
    LONG eLfanew = 0;
    DWORD ntHeadersOffset = 0;
    DWORD optionalHeaderOffset = 0;
    DWORD sectionTableOffset = 0;
    DWORD checkSumOffset = 0;
    DWORD dllCharacteristicsOffset = 0;
    DWORD originalCheckSum = 0;
    DWORD computedCheckSum = 0;
    bool checksumMatches = false;
    SecurityMitigations security;
    OverlayInfo overlay;
    RichHeaderInfo richHeader;
    TlsDirectoryInfo tls;
    std::vector<SectionInfo> sections;
    std::vector<ExportInfo> exports;
    std::vector<ImportModule> imports;
    std::vector<ExtractedString> strings;
    std::vector<CryptoDetection> cryptoDetections;
    double overallEntropy = 0.0;
    bool isPatched = false;
};

struct StagedPatch {
    DWORD fileOffset = 0;
    uint8_t original = 0;
    uint8_t patched = 0;
};

struct PatchDiffEntry {
    DWORD fileOffset = 0;
    uint8_t original = 0;
    uint8_t patched = 0;
};

// ---------------------------------------------------------------------------
// Staged in-memory PE edits with bounds checks, rollback, and checksum
// ---------------------------------------------------------------------------
class StagedPatchManager {
public:
    void Clear() noexcept;
    [[nodiscard]] bool Empty() const noexcept;
    [[nodiscard]] size_t Count() const noexcept;

    [[nodiscard]] bool Add(DWORD fileOffset, uint8_t original, uint8_t patched, size_t fileSize);
    [[nodiscard]] bool AddRange(DWORD fileOffset, const uint8_t* original, const uint8_t* patched,
                                size_t length, size_t fileSize);

    void RollbackLast();
    void RollbackAll() noexcept;

    [[nodiscard]] std::vector<PatchDiffEntry> ComputeDiff() const;
    [[nodiscard]] bool ApplyToBuffer(uint8_t* buffer, size_t fileSize) const;
    [[nodiscard]] bool ApplyToMapping(MemoryMappedFile& mapping) const;

    [[nodiscard]] const std::map<DWORD, StagedPatch>& Patches() const noexcept { return m_patches; }

private:
    std::map<DWORD, StagedPatch> m_patches;
    std::vector<DWORD> m_order;
};

// ---------------------------------------------------------------------------
// PE helpers
// ---------------------------------------------------------------------------
[[nodiscard]] DWORD RvaToFileOffset(DWORD rva, const std::vector<SectionInfo>& sections, size_t fileSize);
[[nodiscard]] DWORD FileOffsetToRva(DWORD offset, const std::vector<SectionInfo>& sections);
[[nodiscard]] std::string GetSectionNameByOffset(DWORD offset, const std::vector<SectionInfo>& sections);
[[nodiscard]] const SectionInfo* FindSectionByName(const std::vector<SectionInfo>& sections, std::string_view name);

[[nodiscard]] double CalculateShannonEntropy(const uint8_t* data, size_t size);
[[nodiscard]] DWORD CalculatePECheckSum(const uint8_t* base, size_t fileSize, DWORD checkSumFieldOffset);

[[nodiscard]] std::wstring Utf8ToWide(std::string_view text);
[[nodiscard]] std::string WideToUtf8(std::wstring_view text);
[[nodiscard]] std::wstring HexByte(uint8_t value);
[[nodiscard]] std::wstring HexDword(DWORD value);
[[nodiscard]] std::wstring HexQword(ULONGLONG value);

[[nodiscard]] const std::map<std::string, ApiMeta>& SensitiveApiMap();
[[nodiscard]] ApiMeta LookupApiMeta(std::string_view apiName);

}  // namespace axianware
