#pragma once

#include "Core.h"

#include <cstddef>

namespace axianware {

struct PatternByte {
    uint8_t value = 0;
    bool isWildcard = false;
};

struct DecodedInsn {
    size_t length = 1;
    std::wstring text;
    std::wstring bytesHex;
    bool isJump = false;
    bool isConditionalJump = false;
    bool isCall = false;
    uint8_t invertOpcode = 0;
    size_t invertOpcodeOffset = 0;
    int32_t relativeDisplacement = 0;
    ULONGLONG targetAddress = 0;
};

class AnalysisEngine {
public:
    [[nodiscard]] static std::vector<PatternByte> ParseAobPattern(std::wstring_view pattern);

    [[nodiscard]] static std::vector<size_t> ScanAob(const uint8_t* data, size_t dataSize,
                                                     const std::vector<PatternByte>& pattern,
                                                     size_t maxMatches = 1000,
                                                     unsigned threadCount = 0);

    static void ScanCryptoAndAntiSignatures(const uint8_t* data, size_t size,
                                            const std::vector<SectionInfo>& sections,
                                            std::vector<CryptoDetection>& outDetections);

    [[nodiscard]] static std::vector<ExtractedString> ExtractStrings(const uint8_t* data, size_t size,
                                                                     const std::vector<SectionInfo>& sections,
                                                                     size_t minLength = 4,
                                                                     size_t maxResults = 8000);

    [[nodiscard]] static DecodedInsn DecodeInstruction(const uint8_t* code, size_t maxLen,
                                                       ULONGLONG currentAddr, bool is64Bit);

    [[nodiscard]] static uint8_t InvertJccOpcode(uint8_t opcode) noexcept;
};

}  // namespace axianware
