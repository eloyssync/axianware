#pragma once

#include "Core.h"

#include <cstddef>

namespace axianware {

class PEParser {
public:
    [[nodiscard]] static bool Parse(const uint8_t* base, size_t fileSize, PEAnalysisReport& outReport);

    static bool ReadCString(const uint8_t* base, size_t fileSize, size_t offset,
                            size_t maxLength, std::string& out);

private:
    [[nodiscard]] static bool ParseHeaders(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                                           const IMAGE_DATA_DIRECTORY*& dataDirs, DWORD& numberOfRvaAndSizes);
    [[nodiscard]] static bool ParseSections(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                                            const IMAGE_SECTION_HEADER* sectionHeaders, WORD sectionCount);
    static void ParseOverlay(const uint8_t* base, size_t fileSize, PEAnalysisReport& report);
    static void ParseRichHeader(const uint8_t* base, size_t fileSize, PEAnalysisReport& report);
    static void ParseImports(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                             const IMAGE_DATA_DIRECTORY& importDir);
    static void ParseExports(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                             const IMAGE_DATA_DIRECTORY& exportDir);
    static void ParseTls(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                         const IMAGE_DATA_DIRECTORY& tlsDir);

    [[nodiscard]] static std::wstring LookupRichProduct(WORD productId);
    [[nodiscard]] static bool Fits(size_t offset, size_t length, size_t fileSize) noexcept;
};

}  // namespace axianware
