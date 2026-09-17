#include "AnalysisEngine.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>

namespace axianware {

namespace {

struct CryptoSignature {
    const wchar_t* name;
    const wchar_t* category;
    const wchar_t* pattern;
};

const CryptoSignature kCryptoAndAntiSignatures[] = {
    {L"AES S-Box", L"Crypto [AES]", L"63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"},
    {L"AES Inverse S-Box", L"Crypto [AES]", L"52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB"},
    {L"MD5 Init Constants", L"Crypto [MD5]", L"01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"},
    {L"SHA-256 H0 Constants", L"Crypto [SHA256]", L"6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A"},
    {L"SHA-256 K Constants", L"Crypto [SHA256]", L"42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5"},
    {L"Base64 Alphabet Table", L"Crypto [Encoding]", L"41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A"},
    {L"PEB.BeingDebugged (x86)", L"Anti-Debug", L"64 A1 30 00 00 00 8A 40 02"},
    {L"PEB.BeingDebugged (x64)", L"Anti-Debug", L"65 48 8B 04 25 60 00 00 00 0F B6 40 02"},
    {L"PEB.NtGlobalFlag (x86)", L"Anti-Debug", L"64 A1 30 00 00 00 8B 40 68"},
    {L"PEB.NtGlobalFlag (x64)", L"Anti-Debug", L"65 48 8B 04 25 60 00 00 00 8B 40 BC"},
    {L"RDTSC Timing Check", L"Anti-VM/Debug", L"0F 31 ?? ?? ?? ?? 0F 31"},
    {L"CPUID Hypervisor Leaf", L"Anti-VM", L"B8 01 00 00 00 0F A2"},
};

bool MatchAt(const uint8_t* data, size_t dataSize, size_t index, const std::vector<PatternByte>& pattern) {
    const size_t patLen = pattern.size();
    if (index + patLen > dataSize) {
        return false;
    }
    for (size_t j = 0; j < patLen; ++j) {
        if (!pattern[j].isWildcard && data[index + j] != pattern[j].value) {
            return false;
        }
    }
    return true;
}

bool IsPrintableAscii(uint8_t c) {
    return c >= 32 && c <= 126;
}

bool IsPrintableUtf16Char(wchar_t ch) {
    return ch >= 32 && ch <= 126;
}

}  // namespace

std::vector<PatternByte> AnalysisEngine::ParseAobPattern(std::wstring_view pattern) {
    std::vector<PatternByte> result;
    size_t i = 0;
    const size_t n = pattern.size();
    while (i < n) {
        while (i < n && (pattern[i] == L' ' || pattern[i] == L'\t' || pattern[i] == L'\r' || pattern[i] == L'\n')) {
            ++i;
        }
        if (i >= n) {
            break;
        }
        if (pattern[i] == L'?') {
            result.push_back(PatternByte{0, true});
            ++i;
            if (i < n && pattern[i] == L'?') {
                ++i;
            }
            continue;
        }
        if (i + 1 >= n) {
            break;
        }
        wchar_t token[3] = {pattern[i], pattern[i + 1], 0};
        wchar_t* endPtr = nullptr;
        const unsigned long value = wcstoul(token, &endPtr, 16);
        result.push_back(PatternByte{static_cast<uint8_t>(value), false});
        i += 2;
    }
    return result;
}

std::vector<size_t> AnalysisEngine::ScanAob(const uint8_t* data, size_t dataSize,
                                            const std::vector<PatternByte>& pattern,
                                            size_t maxMatches, unsigned threadCount) {
    std::vector<size_t> matches;
    if (!data || pattern.empty() || dataSize < pattern.size()) {
        return matches;
    }

    unsigned workers = threadCount;
    if (workers == 0) {
        workers = std::max(1u, std::thread::hardware_concurrency());
    }
    workers = std::min(workers, 16u);
    if (dataSize < 64 * 1024) {
        workers = 1;
    }

    const size_t patLen = pattern.size();
    const size_t last = dataSize - patLen;
    std::mutex mutex;
    std::atomic<size_t> found{0};

    auto scanRange = [&](size_t begin, size_t endInclusive) {
        std::vector<size_t> local;
        for (size_t i = begin; i <= endInclusive; ++i) {
            if (found.load(std::memory_order_relaxed) >= maxMatches) {
                break;
            }
            if (MatchAt(data, dataSize, i, pattern)) {
                local.push_back(i);
                found.fetch_add(1, std::memory_order_relaxed);
            }
        }
        if (!local.empty()) {
            std::lock_guard<std::mutex> lock(mutex);
            matches.insert(matches.end(), local.begin(), local.end());
        }
    };

    if (workers == 1) {
        scanRange(0, last);
        std::sort(matches.begin(), matches.end());
        if (matches.size() > maxMatches) {
            matches.resize(maxMatches);
        }
        return matches;
    }

    const size_t span = last + 1;
    const size_t chunk = (span + workers - 1) / workers;
    std::vector<std::thread> threads;
    threads.reserve(workers);

    for (unsigned t = 0; t < workers; ++t) {
        const size_t begin = t * chunk;
        if (begin > last) {
            break;
        }
        size_t end = begin + chunk;
        if (end > 0) {
            --end;
        }
        size_t overlappedBegin = begin;
        if (t > 0 && patLen > 1) {
            const size_t overlap = patLen - 1;
            overlappedBegin = (begin > overlap) ? (begin - overlap) : 0;
        }
        const size_t endInclusive = std::min(end, last);
        threads.emplace_back(scanRange, overlappedBegin, endInclusive);
    }

    for (auto& th : threads) {
        th.join();
    }

    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    if (matches.size() > maxMatches) {
        matches.resize(maxMatches);
    }
    return matches;
}

void AnalysisEngine::ScanCryptoAndAntiSignatures(const uint8_t* data, size_t size,
                                                 const std::vector<SectionInfo>& sections,
                                                 std::vector<CryptoDetection>& outDetections) {
    outDetections.clear();
    if (!data || size == 0) {
        return;
    }

    for (const auto& sig : kCryptoAndAntiSignatures) {
        const auto pat = ParseAobPattern(sig.pattern);
        const auto hits = ScanAob(data, size, pat, 32);
        for (size_t offset : hits) {
            CryptoDetection cd;
            cd.name = sig.name;
            cd.type = sig.category;
            cd.offset = offset;
            cd.rva = FileOffsetToRva(static_cast<DWORD>(offset), sections);
            cd.sectionName = GetSectionNameByOffset(static_cast<DWORD>(offset), sections);
            outDetections.push_back(std::move(cd));
        }
    }
}

std::vector<ExtractedString> AnalysisEngine::ExtractStrings(const uint8_t* data, size_t size,
                                                            const std::vector<SectionInfo>& sections,
                                                            size_t minLength, size_t maxResults) {
    std::vector<ExtractedString> result;
    if (!data || size == 0 || minLength == 0) {
        return result;
    }

    std::string ascii;
    ascii.reserve(64);
    size_t asciiStart = 0;

    auto flushAscii = [&]() {
        if (ascii.size() >= minLength && result.size() < maxResults) {
            ExtractedString es;
            es.offset = asciiStart;
            es.rva = FileOffsetToRva(static_cast<DWORD>(asciiStart), sections);
            es.text = Utf8ToWide(ascii);
            es.isUnicode = false;
            es.sectionName = GetSectionNameByOffset(static_cast<DWORD>(asciiStart), sections);
            result.push_back(std::move(es));
        }
        ascii.clear();
    };

    for (size_t i = 0; i < size && result.size() < maxResults; ++i) {
        if (IsPrintableAscii(data[i])) {
            if (ascii.empty()) {
                asciiStart = i;
            }
            ascii.push_back(static_cast<char>(data[i]));
        } else {
            flushAscii();
        }
    }
    flushAscii();

    std::wstring utf16;
    utf16.reserve(32);
    size_t utfStart = 0;
    const size_t evenLimit = size - (size % 2);

    auto flushUtf = [&]() {
        if (utf16.size() >= minLength && result.size() < maxResults) {
            ExtractedString es;
            es.offset = utfStart;
            es.rva = FileOffsetToRva(static_cast<DWORD>(utfStart), sections);
            es.text = utf16;
            es.isUnicode = true;
            es.sectionName = GetSectionNameByOffset(static_cast<DWORD>(utfStart), sections);
            result.push_back(std::move(es));
        }
        utf16.clear();
    };

    for (size_t i = 0; i + 1 < evenLimit && result.size() < maxResults; i += 2) {
        const wchar_t ch = static_cast<wchar_t>(data[i] | (static_cast<wchar_t>(data[i + 1]) << 8));
        if (IsPrintableUtf16Char(ch)) {
            if (utf16.empty()) {
                utfStart = i;
            }
            utf16.push_back(ch);
        } else {
            flushUtf();
        }
    }
    flushUtf();

    std::sort(result.begin(), result.end(), [](const ExtractedString& a, const ExtractedString& b) {
        return a.offset < b.offset;
    });
    if (result.size() > maxResults) {
        result.resize(maxResults);
    }
    return result;
}

uint8_t AnalysisEngine::InvertJccOpcode(uint8_t opcode) noexcept {
    // Short Jcc 70-7F and near Jcc 80-8F are paired even/odd.
    if ((opcode >= 0x70 && opcode <= 0x7F) || (opcode >= 0x80 && opcode <= 0x8F)) {
        return (opcode % 2 == 0) ? static_cast<uint8_t>(opcode + 1) : static_cast<uint8_t>(opcode - 1);
    }
    return opcode;
}

DecodedInsn AnalysisEngine::DecodeInstruction(const uint8_t* code, size_t maxLen,
                                              ULONGLONG currentAddr, bool is64Bit) {
    DecodedInsn insn;
    if (!code || maxLen == 0) {
        insn.text = L"db ??";
        insn.bytesHex = L"??";
        return insn;
    }

    size_t idx = 0;
    bool hasRex = false;
    if (is64Bit && (code[idx] >= 0x40 && code[idx] <= 0x4F)) {
        hasRex = true;
        ++idx;
        if (idx >= maxLen) {
            insn.length = 1;
            insn.text = L"rex prefix";
            insn.bytesHex = HexByte(code[0]);
            return insn;
        }
    }

    const uint8_t op = code[idx++];
    std::wstringstream disasm;
    size_t insnLen = idx;
    insn.invertOpcodeOffset = hasRex ? 1 : 0;

    auto hexDump = [&](size_t length) {
        std::wstringstream hexStr;
        for (size_t b = 0; b < length && b < maxLen; ++b) {
            hexStr << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(code[b]) << L" ";
        }
        insn.bytesHex = hexStr.str();
    };

    static const wchar_t* kJccNames[] = {
        L"jo", L"jno", L"jb", L"jnb", L"jz", L"jnz", L"jbe", L"ja",
        L"js", L"jns", L"jp", L"jnp", L"jl", L"jge", L"jle", L"jg"
    };

    if (op >= 0x70 && op <= 0x7F) {
        insn.isJump = true;
        insn.isConditionalJump = true;
        insn.invertOpcode = InvertJccOpcode(op);
        if (idx < maxLen) {
            const int8_t rel = static_cast<int8_t>(code[idx++]);
            insnLen = idx;
            insn.relativeDisplacement = rel;
            insn.targetAddress = currentAddr + insnLen + rel;
            disasm << kJccNames[op - 0x70] << L" short " << HexQword(insn.targetAddress);
        } else {
            disasm << kJccNames[op - 0x70] << L" short ...";
        }
    } else if (op == 0x0F && idx < maxLen && code[idx] >= 0x80 && code[idx] <= 0x8F) {
        const uint8_t op2 = code[idx++];
        insn.isJump = true;
        insn.isConditionalJump = true;
        insn.invertOpcode = InvertJccOpcode(op2);
        insn.invertOpcodeOffset = hasRex ? 2 : 1;
        if (idx + 4 <= maxLen) {
            int32_t rel = 0;
            std::memcpy(&rel, code + idx, sizeof(rel));
            idx += 4;
            insnLen = idx;
            insn.relativeDisplacement = rel;
            insn.targetAddress = currentAddr + insnLen + static_cast<int64_t>(rel);
            disasm << kJccNames[op2 - 0x80] << L" near " << HexQword(insn.targetAddress);
        } else {
            disasm << kJccNames[op2 - 0x80] << L" near ...";
        }
    } else {
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
            insn.isJump = true;
            if (idx < maxLen) {
                const int8_t rel = static_cast<int8_t>(code[idx++]);
                insnLen = idx;
                insn.relativeDisplacement = rel;
                insn.targetAddress = currentAddr + insnLen + rel;
                disasm << L"jmp short " << HexQword(insn.targetAddress);
            } else {
                disasm << L"jmp short ...";
            }
            break;
        }
        case 0xE9: {
            insn.isJump = true;
            if (idx + 4 <= maxLen) {
                int32_t rel = 0;
                std::memcpy(&rel, code + idx, sizeof(rel));
                idx += 4;
                insnLen = idx;
                insn.relativeDisplacement = rel;
                insn.targetAddress = currentAddr + insnLen + static_cast<int64_t>(rel);
                disasm << L"jmp " << HexQword(insn.targetAddress);
            } else {
                disasm << L"jmp ...";
            }
            break;
        }
        case 0xE8: {
            insn.isCall = true;
            if (idx + 4 <= maxLen) {
                int32_t rel = 0;
                std::memcpy(&rel, code + idx, sizeof(rel));
                idx += 4;
                insnLen = idx;
                insn.relativeDisplacement = rel;
                insn.targetAddress = currentAddr + insnLen + static_cast<int64_t>(rel);
                disasm << L"call " << HexQword(insn.targetAddress);
            } else {
                disasm << L"call ...";
            }
            break;
        }
        case 0x85:
        case 0x84: {
            if (idx < maxLen) {
                const uint8_t modrm = code[idx++];
                insnLen = idx;
                if (modrm == 0xC0) {
                    disasm << L"test eax, eax";
                } else if (modrm == 0xC9) {
                    disasm << L"test ecx, ecx";
                } else {
                    disasm << L"test r/m";
                }
            } else {
                disasm << L"test ...";
            }
            break;
        }
        case 0x31:
        case 0x33: {
            if (idx < maxLen) {
                const uint8_t modrm = code[idx++];
                insnLen = idx;
                if (modrm == 0xC0) {
                    disasm << L"xor eax, eax";
                } else if (modrm == 0xDB) {
                    disasm << L"xor ebx, ebx";
                } else if (modrm == 0xC9) {
                    disasm << L"xor ecx, ecx";
                } else {
                    disasm << L"xor r/m";
                }
            } else {
                disasm << L"xor ...";
            }
            break;
        }
        case 0x8B: {
            if (idx < maxLen) {
                const uint8_t modrm = code[idx++];
                insnLen = idx;
                if (is64Bit && (modrm & 0xC7) == 0x05 && idx + 4 <= maxLen) {
                    int32_t disp = 0;
                    std::memcpy(&disp, code + idx, sizeof(disp));
                    idx += 4;
                    insnLen = idx;
                    disasm << L"mov reg, [rip+" << HexDword(static_cast<DWORD>(disp)) << L"]";
                } else if (modrm == 0xEC) {
                    disasm << (is64Bit ? L"mov rbp, rsp" : L"mov ebp, esp");
                } else {
                    disasm << L"mov r, r/m";
                }
            } else {
                disasm << L"mov ...";
            }
            break;
        }
        case 0x8D: {
            if (idx < maxLen) {
                const uint8_t modrm = code[idx++];
                insnLen = idx;
                if (is64Bit && (modrm & 0xC7) == 0x05 && idx + 4 <= maxLen) {
                    int32_t disp = 0;
                    std::memcpy(&disp, code + idx, sizeof(disp));
                    idx += 4;
                    insnLen = idx;
                    disasm << L"lea reg, [rip+" << HexDword(static_cast<DWORD>(disp)) << L"]";
                } else {
                    disasm << L"lea r, m";
                }
            } else {
                disasm << L"lea ...";
            }
            break;
        }
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {
            static const wchar_t* kRegs[] = {
                L"rax/eax", L"rcx/ecx", L"rdx/edx", L"rbx/ebx",
                L"rsp/esp", L"rbp/ebp", L"rsi/esi", L"rdi/edi"
            };
            disasm << L"push " << kRegs[op - 0x50];
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            static const wchar_t* kRegs[] = {
                L"rax/eax", L"rcx/ecx", L"rdx/edx", L"rbx/ebx",
                L"rsp/esp", L"rbp/ebp", L"rsi/esi", L"rdi/edi"
            };
            disasm << L"pop " << kRegs[op - 0x58];
            break;
        }
        default:
            disasm << L"db 0x" << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(op);
            insnLen = hasRex ? 2 : 1;
            break;
        }
    }

    insn.length = insnLen;
    insn.text = disasm.str();
    hexDump(insnLen);
    return insn;
}

}  // namespace axianware
