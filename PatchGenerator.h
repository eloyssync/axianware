#pragma once

#include "Core.h"

#include <cstddef>

namespace axianware {

class PatchGenerator {
public:
    [[nodiscard]] static std::wstring FileNameFromPath(const std::wstring& path);

    [[nodiscard]] static std::wstring Generate1337Patch(const std::wstring& targetPath,
                                                        const PEAnalysisReport& report,
                                                        const StagedPatchManager& patches);

    [[nodiscard]] static std::wstring GenerateInlineHookDllTemplate(const PEAnalysisReport& report,
                                                                    DWORD targetRva);

    [[nodiscard]] static std::wstring GenerateCheatEngineScript(const std::wstring& targetPath,
                                                                const PEAnalysisReport& report,
                                                                DWORD rva,
                                                                const uint8_t* originalBytes,
                                                                const uint8_t* patchBytes,
                                                                size_t length);

    [[nodiscard]] static bool StageDisableDynamicBase(const uint8_t* image, size_t fileSize,
                                                      const PEAnalysisReport& report,
                                                      StagedPatchManager& patches);

    [[nodiscard]] static bool StageSectionReadWrite(const uint8_t* image, size_t fileSize,
                                                    const PEAnalysisReport& report,
                                                    WORD sectionIndex, bool writable,
                                                    StagedPatchManager& patches);

    [[nodiscard]] static bool RecalculateAndWriteCheckSum(uint8_t* image, size_t fileSize,
                                                          const PEAnalysisReport& report);
};

}  // namespace axianware
