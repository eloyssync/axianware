#include "Core.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace axianware {

ScopedHandle::ScopedHandle(HANDLE handle) noexcept : m_handle(handle) {}

ScopedHandle::~ScopedHandle() {
    Close();
}

ScopedHandle::ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
    other.m_handle = INVALID_HANDLE_VALUE;
}

ScopedHandle& ScopedHandle::operator=(ScopedHandle&& other) noexcept {
    if (this != &other) {
        Close();
        m_handle = other.m_handle;
        other.m_handle = INVALID_HANDLE_VALUE;
    }
    return *this;
}

void ScopedHandle::Close() noexcept {
    if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

HANDLE ScopedHandle::Get() const noexcept {
    return m_handle;
}

bool ScopedHandle::IsValid() const noexcept {
    return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
}

HANDLE ScopedHandle::Release() noexcept {
    HANDLE h = m_handle;
    m_handle = INVALID_HANDLE_VALUE;
    return h;
}

MemoryMappedFile::~MemoryMappedFile() {
    Close();
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept
    : m_file(std::move(other.m_file)),
      m_mapping(std::move(other.m_mapping)),
      m_base(other.m_base),
      m_fileSize(other.m_fileSize),
      m_writable(other.m_writable) {
    other.m_base = nullptr;
    other.m_fileSize = 0;
    other.m_writable = false;
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        Close();
        m_file = std::move(other.m_file);
        m_mapping = std::move(other.m_mapping);
        m_base = other.m_base;
        m_fileSize = other.m_fileSize;
        m_writable = other.m_writable;
        other.m_base = nullptr;
        other.m_fileSize = 0;
        other.m_writable = false;
    }
    return *this;
}

bool MemoryMappedFile::Open(const std::wstring& filePath, bool writeAccess) {
    Close();

    const DWORD access = writeAccess ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
    const DWORD share = writeAccess ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE);
    const DWORD protect = writeAccess ? PAGE_READWRITE : PAGE_READONLY;
    const DWORD mapAccess = writeAccess ? FILE_MAP_WRITE : FILE_MAP_READ;

    m_file = ScopedHandle(CreateFileW(filePath.c_str(), access, share, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!m_file.IsValid()) {
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(m_file.Get(), &size) || size.QuadPart <= 0) {
        Close();
        return false;
    }
    m_fileSize = static_cast<size_t>(size.QuadPart);

    m_mapping = ScopedHandle(CreateFileMappingW(m_file.Get(), nullptr, protect, 0, 0, nullptr));
    if (!m_mapping.IsValid()) {
        Close();
        return false;
    }

    m_base = MapViewOfFile(m_mapping.Get(), mapAccess, 0, 0, 0);
    if (!m_base) {
        Close();
        return false;
    }

    m_writable = writeAccess;
    return true;
}

void MemoryMappedFile::Close() noexcept {
    if (m_base) {
        UnmapViewOfFile(m_base);
        m_base = nullptr;
    }
    m_mapping.Close();
    m_file.Close();
    m_fileSize = 0;
    m_writable = false;
}

const uint8_t* MemoryMappedFile::Data() const noexcept {
    return static_cast<const uint8_t*>(m_base);
}

uint8_t* MemoryMappedFile::WritableData() noexcept {
    return m_writable ? static_cast<uint8_t*>(m_base) : nullptr;
}

size_t MemoryMappedFile::Size() const noexcept {
    return m_fileSize;
}

bool MemoryMappedFile::IsOpen() const noexcept {
    return m_base != nullptr;
}

bool MemoryMappedFile::IsWritable() const noexcept {
    return m_writable && m_base != nullptr;
}

bool MemoryMappedFile::BoundsCheck(size_t offset, size_t length) const noexcept {
    if (!m_base) {
        return false;
    }
    if (length == 0) {
        return offset <= m_fileSize;
    }
    return offset < m_fileSize && length <= m_fileSize - offset;
}

bool MemoryMappedFile::Read(size_t offset, void* destination, size_t length) const {
    if (!destination || !BoundsCheck(offset, length)) {
        return false;
    }
    std::memcpy(destination, Data() + offset, length);
    return true;
}

bool MemoryMappedFile::Write(size_t offset, const void* source, size_t length) {
    uint8_t* dest = WritableData();
    if (!dest || !source || !BoundsCheck(offset, length)) {
        return false;
    }
    std::memcpy(dest + offset, source, length);
    return true;
}

void StagedPatchManager::Clear() noexcept {
    m_patches.clear();
    m_order.clear();
}

bool StagedPatchManager::Empty() const noexcept {
    return m_patches.empty();
}

size_t StagedPatchManager::Count() const noexcept {
    return m_patches.size();
}

bool StagedPatchManager::Add(DWORD fileOffset, uint8_t original, uint8_t patched, size_t fileSize) {
    if (static_cast<size_t>(fileOffset) >= fileSize) {
        return false;
    }
    if (m_patches.find(fileOffset) == m_patches.end()) {
        m_order.push_back(fileOffset);
    }
    m_patches[fileOffset] = StagedPatch{fileOffset, original, patched};
    return true;
}

bool StagedPatchManager::AddRange(DWORD fileOffset, const uint8_t* original, const uint8_t* patched,
                                  size_t length, size_t fileSize) {
    if (!original || !patched || length == 0) {
        return false;
    }
    if (static_cast<size_t>(fileOffset) >= fileSize || length > fileSize - fileOffset) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        if (!Add(fileOffset + static_cast<DWORD>(i), original[i], patched[i], fileSize)) {
            return false;
        }
    }
    return true;
}

void StagedPatchManager::RollbackLast() {
    if (m_order.empty()) {
        return;
    }
    const DWORD last = m_order.back();
    m_order.pop_back();
    m_patches.erase(last);
}

void StagedPatchManager::RollbackAll() noexcept {
    Clear();
}

std::vector<PatchDiffEntry> StagedPatchManager::ComputeDiff() const {
    std::vector<PatchDiffEntry> diff;
    diff.reserve(m_patches.size());
    for (const auto& [offset, patch] : m_patches) {
        if (patch.original != patch.patched) {
            diff.push_back(PatchDiffEntry{offset, patch.original, patch.patched});
        }
    }
    return diff;
}

bool StagedPatchManager::ApplyToBuffer(uint8_t* buffer, size_t fileSize) const {
    if (!buffer) {
        return false;
    }
    for (const auto& [offset, patch] : m_patches) {
        if (static_cast<size_t>(offset) >= fileSize) {
            return false;
        }
        buffer[offset] = patch.patched;
    }
    return true;
}

bool StagedPatchManager::ApplyToMapping(MemoryMappedFile& mapping) const {
    uint8_t* dest = mapping.WritableData();
    if (!dest) {
        return false;
    }
    return ApplyToBuffer(dest, mapping.Size());
}

DWORD RvaToFileOffset(DWORD rva, const std::vector<SectionInfo>& sections, size_t fileSize) {
    for (const auto& sec : sections) {
        const DWORD secSize = sec.virtualSize ? sec.virtualSize : sec.rawDataSize;
        if (secSize == 0) {
            continue;
        }
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + secSize) {
            const DWORD delta = rva - sec.virtualAddress;
            if (delta >= sec.rawDataSize) {
                return 0;
            }
            const DWORD offset = sec.rawDataOffset + delta;
            if (static_cast<size_t>(offset) < fileSize) {
                return offset;
            }
        }
    }
    return 0;
}

DWORD FileOffsetToRva(DWORD offset, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        if (sec.rawDataSize == 0) {
            continue;
        }
        if (offset >= sec.rawDataOffset && offset < sec.rawDataOffset + sec.rawDataSize) {
            return sec.virtualAddress + (offset - sec.rawDataOffset);
        }
    }
    return 0;
}

std::string GetSectionNameByOffset(DWORD offset, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        if (sec.rawDataSize == 0) {
            continue;
        }
        if (offset >= sec.rawDataOffset && offset < sec.rawDataOffset + sec.rawDataSize) {
            return sec.name;
        }
    }
    return "Header";
}

const SectionInfo* FindSectionByName(const std::vector<SectionInfo>& sections, std::string_view name) {
    for (const auto& sec : sections) {
        if (sec.name == name) {
            return &sec;
        }
    }
    return nullptr;
}

double CalculateShannonEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }

    size_t counts[256] = {};
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    const double dSize = static_cast<double>(size);
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0) {
            continue;
        }
        const double p = static_cast<double>(counts[i]) / dSize;
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}

DWORD CalculatePECheckSum(const uint8_t* base, size_t fileSize, DWORD checkSumFieldOffset) {
    if (!base || fileSize == 0) {
        return 0;
    }

    uint32_t sum = 0;
    size_t i = 0;
    const size_t cs = static_cast<size_t>(checkSumFieldOffset);

    auto fold = [](uint32_t value) -> uint32_t {
        value = (value & 0xFFFFu) + (value >> 16);
        value = (value & 0xFFFFu) + (value >> 16);
        return value;
    };

    while (i + 1 < fileSize) {
        if (i >= cs && i < cs + sizeof(DWORD)) {
            i = cs + sizeof(DWORD);
            continue;
        }
        const uint16_t word = static_cast<uint16_t>(base[i] | (static_cast<uint16_t>(base[i + 1]) << 8));
        sum += word;
        sum = fold(sum);
        i += 2;
    }

    if (i < fileSize && !(i >= cs && i < cs + sizeof(DWORD))) {
        sum += base[i];
        sum = fold(sum);
    }

    sum = fold(sum);
    sum += static_cast<uint32_t>(fileSize);
    return static_cast<DWORD>(sum);
}

std::wstring Utf8ToWide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return std::wstring(text.begin(), text.end());
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed);
    return out;
}

std::string WideToUtf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring HexByte(uint8_t value) {
    std::wstringstream ss;
    ss << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << static_cast<int>(value);
    return ss.str();
}

std::wstring HexDword(DWORD value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << value;
    return ss.str();
}

std::wstring HexQword(ULONGLONG value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << std::setw(16) << std::setfill(L'0') << value;
    return ss.str();
}

const std::map<std::string, ApiMeta>& SensitiveApiMap() {
    static const std::map<std::string, ApiMeta> kMap = {
        {"VirtualAlloc", {ApiRisk::MemoryAlloc, L"Memory Allocation / RWX"}},
        {"VirtualAllocEx", {ApiRisk::ProcessInject, L"Remote Memory Allocation"}},
        {"VirtualProtect", {ApiRisk::MemoryAlloc, L"Memory Protection Modification"}},
        {"VirtualProtectEx", {ApiRisk::ProcessInject, L"Remote Memory Protection"}},
        {"NtProtectVirtualMemory", {ApiRisk::MemoryAlloc, L"Native Memory Protection"}},
        {"WriteProcessMemory", {ApiRisk::ProcessInject, L"Process Memory Write"}},
        {"ReadProcessMemory", {ApiRisk::ProcessInject, L"Process Memory Read"}},
        {"CreateRemoteThread", {ApiRisk::ProcessInject, L"Remote Thread Execution"}},
        {"CreateRemoteThreadEx", {ApiRisk::ProcessInject, L"Remote Thread Execution"}},
        {"NtCreateThreadEx", {ApiRisk::ProcessInject, L"Native Remote Thread"}},
        {"QueueUserAPC", {ApiRisk::ProcessInject, L"APC Injection"}},
        {"NtQueueApcThread", {ApiRisk::ProcessInject, L"Native APC Injection"}},
        {"SetThreadContext", {ApiRisk::ThreadControl, L"Thread Context Write"}},
        {"GetThreadContext", {ApiRisk::ThreadControl, L"Thread Context Query"}},
        {"NtSetContextThread", {ApiRisk::ThreadControl, L"Native Thread Context"}},
        {"OpenProcess", {ApiRisk::Suspicious, L"Process Handle Acquisition"}},
        {"NtOpenProcess", {ApiRisk::Suspicious, L"Native Process Open"}},
        {"IsDebuggerPresent", {ApiRisk::AntiDebug, L"PEB Anti-Debugging"}},
        {"CheckRemoteDebuggerPresent", {ApiRisk::AntiDebug, L"Remote Debugger Check"}},
        {"NtQueryInformationProcess", {ApiRisk::AntiDebug, L"Process Info Anti-Debug"}},
        {"OutputDebugStringA", {ApiRisk::AntiDebug, L"Debugger Timing / Output"}},
        {"OutputDebugStringW", {ApiRisk::AntiDebug, L"Debugger Timing / Output"}},
        {"CryptEncrypt", {ApiRisk::Crypto, L"Windows Crypto API"}},
        {"CryptDecrypt", {ApiRisk::Crypto, L"Windows Crypto API"}},
        {"BCryptEncrypt", {ApiRisk::Crypto, L"CNG Encrypt"}},
        {"BCryptDecrypt", {ApiRisk::Crypto, L"CNG Decrypt"}},
        {"WinExec", {ApiRisk::Suspicious, L"Process Execution"}},
        {"ShellExecuteA", {ApiRisk::Suspicious, L"Shell Execution"}},
        {"ShellExecuteW", {ApiRisk::Suspicious, L"Shell Execution"}},
        {"CreateProcessA", {ApiRisk::Suspicious, L"Process Creation"}},
        {"CreateProcessW", {ApiRisk::Suspicious, L"Process Creation"}},
        {"LoadLibraryA", {ApiRisk::Suspicious, L"Dynamic Module Load"}},
        {"LoadLibraryW", {ApiRisk::Suspicious, L"Dynamic Module Load"}},
        {"GetProcAddress", {ApiRisk::Suspicious, L"Dynamic Export Resolve"}},
    };
    return kMap;
}

ApiMeta LookupApiMeta(std::string_view apiName) {
    const auto& map = SensitiveApiMap();
    const auto it = map.find(std::string(apiName));
    if (it == map.end()) {
        return ApiMeta{ApiRisk::Normal, L"Normal"};
    }
    return it->second;
}

}  // namespace axianware
