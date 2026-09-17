#include "PEParser.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace axianware {

namespace {

constexpr DWORD kDansSignature = 0x536E6144;  // "DanS"
constexpr DWORD kRichSignature = 0x68636952;  // "Rich"
constexpr double kPackedEntropy = 7.2;
constexpr size_t kMaxImportModules = 4096;
constexpr size_t kMaxImportFunctions = 65536;
constexpr size_t kMaxExports = 65536;
constexpr size_t kMaxTlsCallbacks = 256;

template <typename T>
const T* At(const uint8_t* base, size_t offset, size_t fileSize) {
    if (offset + sizeof(T) > fileSize) {
        return nullptr;
    }
    return reinterpret_cast<const T*>(base + offset);
}

}  // namespace

bool PEParser::Fits(size_t offset, size_t length, size_t fileSize) noexcept {
    if (length == 0) {
        return offset <= fileSize;
    }
    return offset < fileSize && length <= fileSize - offset;
}

bool PEParser::ReadCString(const uint8_t* base, size_t fileSize, size_t offset, size_t maxLength, std::string& out) {
    out.clear();
    if (!base || offset >= fileSize || maxLength == 0) {
        return false;
    }
    const size_t limit = std::min(maxLength, fileSize - offset);
    const char* start = reinterpret_cast<const char*>(base + offset);
    size_t n = 0;
    while (n < limit && start[n] != '\0') {
        const unsigned char ch = static_cast<unsigned char>(start[n]);
        if (ch < 0x20 && ch != '\t') {
            break;
        }
        ++n;
    }
    if (n == 0) {
        return false;
    }
    out.assign(start, n);
    return true;
}

std::wstring PEParser::LookupRichProduct(WORD productId) {
    static const std::unordered_map<WORD, const wchar_t*> kProducts = {
        {0x0000, L"Unknown / Import"},
        {0x0001, L"Import0"},
        {0x0002, L"Linker 5.10"},
        {0x0004, L"CVTRES"},
        {0x0006, L"VS97 Linker"},
        {0x000A, L"VS98 C++"},
        {0x000B, L"VS98 C"},
        {0x000E, L"VS98 Linker"},
        {0x0015, L"VS2002 C++"},
        {0x0016, L"VS2002 C"},
        {0x0017, L"VS2002 Linker"},
        {0x0019, L"VS2003 C++"},
        {0x001A, L"VS2003 C"},
        {0x001C, L"VS2003 Linker"},
        {0x001E, L"VS2003 Export"},
        {0x0040, L"MASM"},
        {0x005A, L"VS2005 C++"},
        {0x005C, L"VS2005 C"},
        {0x005E, L"VS2005 Linker"},
        {0x0060, L"VS2005 Export"},
        {0x006D, L"VS2008 C++"},
        {0x006E, L"VS2008 C"},
        {0x0078, L"VS2008 Linker"},
        {0x007A, L"VS2008 Export"},
        {0x0083, L"VS2010 C++"},
        {0x0084, L"VS2010 C"},
        {0x0091, L"VS2010 Linker"},
        {0x0095, L"VS2010 Export"},
        {0x009E, L"VS2012 C++"},
        {0x009F, L"VS2012 C"},
        {0x00AA, L"VS2012 Linker"},
        {0x00CE, L"VS2013 C++"},
        {0x00CF, L"VS2013 C"},
        {0x00DC, L"VS2013 Linker"},
        {0x00E0, L"VS2015 C++"},
        {0x00E1, L"VS2015 C"},
        {0x00EE, L"VS2015 Linker"},
        {0x0102, L"VS2017 C++"},
        {0x0103, L"VS2017 C"},
        {0x0104, L"VS2017 Linker"},
        {0x0105, L"VS2017 Export"},
        {0x010E, L"VS2019 C++"},
        {0x010F, L"VS2019 C"},
        {0x0110, L"VS2019 Linker"},
        {0x011A, L"VS2022 C++"},
        {0x011B, L"VS2022 C"},
        {0x011C, L"VS2022 Linker"},
    };
    const auto it = kProducts.find(productId);
    if (it != kProducts.end()) {
        return it->second;
    }
    return L"Unknown ProdID";
}

bool PEParser::ParseHeaders(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                            const IMAGE_DATA_DIRECTORY*& dataDirs, DWORD& numberOfRvaAndSizes) {
    dataDirs = nullptr;
    numberOfRvaAndSizes = 0;

    if (!Fits(0, sizeof(IMAGE_DOS_HEADER), fileSize)) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (dos->e_lfanew <= 0) {
        return false;
    }

    report.eLfanew = dos->e_lfanew;
    report.ntHeadersOffset = static_cast<DWORD>(dos->e_lfanew);

    const size_t ntOff = static_cast<size_t>(dos->e_lfanew);
    if (!Fits(ntOff, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), fileSize)) {
        return false;
    }

    const auto* signature = reinterpret_cast<const DWORD*>(base + ntOff);
    if (*signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + ntOff + sizeof(DWORD));
    report.machine = fileHeader->Machine;
    report.numberOfSections = fileHeader->NumberOfSections;

    report.optionalHeaderOffset = static_cast<DWORD>(ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    const size_t optOff = report.optionalHeaderOffset;
    if (!Fits(optOff, sizeof(WORD), fileSize)) {
        return false;
    }

    const WORD magic = *reinterpret_cast<const WORD*>(base + optOff);
    WORD dllCharacteristics = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!Fits(optOff, sizeof(IMAGE_OPTIONAL_HEADER64), fileSize)) {
            return false;
        }
        report.is64Bit = true;
        const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + optOff);
        report.entryPointRva = opt64->AddressOfEntryPoint;
        report.imageBase = opt64->ImageBase;
        report.sizeOfImage = opt64->SizeOfImage;
        report.sizeOfHeaders = opt64->SizeOfHeaders;
        report.sectionAlignment = opt64->SectionAlignment;
        report.fileAlignment = opt64->FileAlignment;
        report.originalCheckSum = opt64->CheckSum;
        report.checkSumOffset = static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt64->CheckSum) - base);
        report.dllCharacteristicsOffset =
            static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt64->DllCharacteristics) - base);
        dllCharacteristics = opt64->DllCharacteristics;
        numberOfRvaAndSizes = opt64->NumberOfRvaAndSizes;
        dataDirs = opt64->DataDirectory;
        report.sectionTableOffset = report.optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!Fits(optOff, sizeof(IMAGE_OPTIONAL_HEADER32), fileSize)) {
            return false;
        }
        report.is64Bit = false;
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + optOff);
        report.entryPointRva = opt32->AddressOfEntryPoint;
        report.imageBase = opt32->ImageBase;
        report.sizeOfImage = opt32->SizeOfImage;
        report.sizeOfHeaders = opt32->SizeOfHeaders;
        report.sectionAlignment = opt32->SectionAlignment;
        report.fileAlignment = opt32->FileAlignment;
        report.originalCheckSum = opt32->CheckSum;
        report.checkSumOffset = static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt32->CheckSum) - base);
        report.dllCharacteristicsOffset =
            static_cast<DWORD>(reinterpret_cast<const uint8_t*>(&opt32->DllCharacteristics) - base);
        dllCharacteristics = opt32->DllCharacteristics;
        numberOfRvaAndSizes = opt32->NumberOfRvaAndSizes;
        dataDirs = opt32->DataDirectory;
        report.sectionTableOffset = report.optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    } else {
        return false;
    }

    if (fileHeader->SizeOfOptionalHeader < sizeof(WORD)) {
        return false;
    }

    report.security.dllCharacteristics = dllCharacteristics;
    report.security.aslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    report.security.highEntropyVA = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    report.security.dep = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    report.security.safeSEH = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
    report.security.controlFlowGuard = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    report.security.noIsolation = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0;
    return true;
}

bool PEParser::ParseSections(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                             const IMAGE_SECTION_HEADER* sectionHeaders, WORD sectionCount) {
    if (!sectionHeaders) {
        return false;
    }
    const size_t tableBytes = static_cast<size_t>(sectionCount) * sizeof(IMAGE_SECTION_HEADER);
    if (!Fits(report.sectionTableOffset, tableBytes, fileSize)) {
        return false;
    }

    report.sections.clear();
    report.sections.reserve(sectionCount);

    for (WORD i = 0; i < sectionCount; ++i) {
        const auto& sec = sectionHeaders[i];
        char nameBuf[9] = {};
        std::memcpy(nameBuf, sec.Name, 8);

        SectionInfo info;
        info.name = nameBuf;
        info.virtualAddress = sec.VirtualAddress;
        info.virtualSize = sec.Misc.VirtualSize;
        info.rawDataOffset = sec.PointerToRawData;
        info.rawDataSize = sec.SizeOfRawData;
        info.characteristics = sec.Characteristics;
        info.sectionIndex = i;
        info.headerFileOffset =
            report.sectionTableOffset + static_cast<DWORD>(i) * static_cast<DWORD>(sizeof(IMAGE_SECTION_HEADER));

        if (info.rawDataSize > 0 && Fits(info.rawDataOffset, 1, fileSize)) {
            const size_t valid = std::min<size_t>(info.rawDataSize, fileSize - info.rawDataOffset);
            info.entropy = CalculateShannonEntropy(base + info.rawDataOffset, valid);
            info.isSuspiciousEntropy = info.entropy > kPackedEntropy;
        }
        report.sections.push_back(std::move(info));
    }
    return true;
}

void PEParser::ParseOverlay(const uint8_t* base, size_t fileSize, PEAnalysisReport& report) {
    DWORD endOfImage = report.sizeOfHeaders;
    for (const auto& sec : report.sections) {
        if (sec.rawDataSize == 0) {
            continue;
        }
        const uint64_t end = static_cast<uint64_t>(sec.rawDataOffset) + sec.rawDataSize;
        if (end > endOfImage) {
            endOfImage = static_cast<DWORD>(std::min<uint64_t>(end, 0xFFFFFFFFull));
        }
    }

    if (fileSize > endOfImage) {
        report.overlay.present = true;
        report.overlay.offset = endOfImage;
        report.overlay.size = static_cast<DWORD>(fileSize - endOfImage);
        report.overlay.entropy = CalculateShannonEntropy(base + endOfImage, fileSize - endOfImage);
    } else {
        report.overlay = OverlayInfo{};
    }
}

void PEParser::ParseRichHeader(const uint8_t* base, size_t fileSize, PEAnalysisReport& report) {
    report.richHeader = RichHeaderInfo{};
    const size_t peOff = static_cast<size_t>(report.eLfanew);
    if (peOff < 8 || peOff > fileSize) {
        return;
    }

    // Walk DWORD-aligned backwards from NT headers looking for "Rich".
    size_t searchEnd = peOff & ~static_cast<size_t>(3);
    if (searchEnd > peOff) {
        searchEnd = peOff;
    }
    DWORD richOff = 0;
    DWORD xorKey = 0;
    bool foundRich = false;
    for (size_t off = 0x80; off + 8 <= searchEnd; off += 4) {
        const DWORD value = *reinterpret_cast<const DWORD*>(base + off);
        if (value == kRichSignature) {
            richOff = static_cast<DWORD>(off);
            xorKey = *reinterpret_cast<const DWORD*>(base + off + 4);
            foundRich = true;
            // keep scanning; the last "Rich" before PE is canonical
        }
    }
    if (!foundRich) {
        return;
    }

    DWORD dansOff = 0;
    bool foundDans = false;
    for (size_t off = sizeof(IMAGE_DOS_HEADER); off + 4 <= richOff; off += 4) {
        const DWORD encoded = *reinterpret_cast<const DWORD*>(base + off);
        if ((encoded ^ xorKey) == kDansSignature) {
            dansOff = static_cast<DWORD>(off);
            foundDans = true;
            break;
        }
    }
    if (!foundDans) {
        return;
    }

    report.richHeader.present = true;
    report.richHeader.xorKey = xorKey;
    report.richHeader.dansOffset = dansOff;
    report.richHeader.richOffset = richOff;

    // Skip DanS + three padding DWORDs (all XOR-encoded).
    size_t cursor = static_cast<size_t>(dansOff) + 16;
    while (cursor + 8 <= richOff) {
        const DWORD compIdEnc = *reinterpret_cast<const DWORD*>(base + cursor);
        const DWORD countEnc = *reinterpret_cast<const DWORD*>(base + cursor + 4);
        const DWORD compId = compIdEnc ^ xorKey;
        const DWORD count = countEnc ^ xorKey;

        RichHeaderEntry entry;
        entry.buildNumber = static_cast<WORD>(compId & 0xFFFF);
        entry.productId = static_cast<WORD>((compId >> 16) & 0xFFFF);
        entry.count = count;
        entry.productName = LookupRichProduct(entry.productId);
        report.richHeader.entries.push_back(entry);
        cursor += 8;
    }
}

void PEParser::ParseImports(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                            const IMAGE_DATA_DIRECTORY& importDir) {
    report.imports.clear();
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        return;
    }

    const DWORD descOff = RvaToFileOffset(importDir.VirtualAddress, report.sections, fileSize);
    if (descOff == 0) {
        return;
    }

    size_t modules = 0;
    size_t descIndex = 0;
    while (modules < kMaxImportModules) {
        const size_t off = static_cast<size_t>(descOff) + descIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const auto* desc = At<IMAGE_IMPORT_DESCRIPTOR>(base, off, fileSize);
        if (!desc) {
            break;
        }
        if (desc->Characteristics == 0 && desc->Name == 0 && desc->FirstThunk == 0) {
            break;
        }

        ImportModule mod;
        const DWORD nameOff = RvaToFileOffset(desc->Name, report.sections, fileSize);
        if (nameOff == 0 || !ReadCString(base, fileSize, nameOff, 260, mod.dllName)) {
            ++descIndex;
            continue;
        }

        const DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        const DWORD thunkOff = RvaToFileOffset(thunkRva, report.sections, fileSize);
        if (thunkOff == 0) {
            report.imports.push_back(std::move(mod));
            ++descIndex;
            ++modules;
            continue;
        }

        size_t funcCount = 0;
        size_t thunkIndex = 0;
        if (report.is64Bit) {
            while (funcCount < kMaxImportFunctions) {
                const size_t tOff = static_cast<size_t>(thunkOff) + thunkIndex * sizeof(IMAGE_THUNK_DATA64);
                const auto* thunk = At<IMAGE_THUNK_DATA64>(base, tOff, fileSize);
                if (!thunk || thunk->u1.AddressOfData == 0) {
                    break;
                }
                ImportFunction fn;
                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    fn.isOrdinal = true;
                    fn.ordinal = static_cast<WORD>(IMAGE_ORDINAL64(thunk->u1.Ordinal));
                } else {
                    const DWORD ibnOff =
                        RvaToFileOffset(static_cast<DWORD>(thunk->u1.AddressOfData), report.sections, fileSize);
                    if (ibnOff && Fits(ibnOff, sizeof(WORD) + 1, fileSize)) {
                        ReadCString(base, fileSize, ibnOff + sizeof(WORD), 512, fn.name);
                    }
                }
                const ApiMeta meta = LookupApiMeta(fn.name);
                fn.risk = meta.risk;
                fn.category = meta.category;
                if (fn.risk != ApiRisk::Normal) {
                    mod.sensitiveCount++;
                }
                mod.functions.push_back(std::move(fn));
                ++thunkIndex;
                ++funcCount;
            }
        } else {
            while (funcCount < kMaxImportFunctions) {
                const size_t tOff = static_cast<size_t>(thunkOff) + thunkIndex * sizeof(IMAGE_THUNK_DATA32);
                const auto* thunk = At<IMAGE_THUNK_DATA32>(base, tOff, fileSize);
                if (!thunk || thunk->u1.AddressOfData == 0) {
                    break;
                }
                ImportFunction fn;
                if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
                    fn.isOrdinal = true;
                    fn.ordinal = static_cast<WORD>(IMAGE_ORDINAL32(thunk->u1.Ordinal));
                } else {
                    const DWORD ibnOff = RvaToFileOffset(thunk->u1.AddressOfData, report.sections, fileSize);
                    if (ibnOff && Fits(ibnOff, sizeof(WORD) + 1, fileSize)) {
                        ReadCString(base, fileSize, ibnOff + sizeof(WORD), 512, fn.name);
                    }
                }
                const ApiMeta meta = LookupApiMeta(fn.name);
                fn.risk = meta.risk;
                fn.category = meta.category;
                if (fn.risk != ApiRisk::Normal) {
                    mod.sensitiveCount++;
                }
                mod.functions.push_back(std::move(fn));
                ++thunkIndex;
                ++funcCount;
            }
        }

        report.imports.push_back(std::move(mod));
        ++descIndex;
        ++modules;
    }
}

void PEParser::ParseExports(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                            const IMAGE_DATA_DIRECTORY& exportDir) {
    report.exports.clear();
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
        return;
    }

    const DWORD dirOff = RvaToFileOffset(exportDir.VirtualAddress, report.sections, fileSize);
    const auto* dir = At<IMAGE_EXPORT_DIRECTORY>(base, dirOff, fileSize);
    if (!dir) {
        return;
    }

    const DWORD namesOff = RvaToFileOffset(dir->AddressOfNames, report.sections, fileSize);
    const DWORD ordsOff = RvaToFileOffset(dir->AddressOfNameOrdinals, report.sections, fileSize);
    const DWORD funcsOff = RvaToFileOffset(dir->AddressOfFunctions, report.sections, fileSize);
    if (!namesOff || !ordsOff || !funcsOff) {
        return;
    }

    const DWORD exportBegin = exportDir.VirtualAddress;
    const DWORD exportEnd = exportDir.VirtualAddress + exportDir.Size;
    const DWORD named = std::min<DWORD>(dir->NumberOfNames, static_cast<DWORD>(kMaxExports));

    for (DWORD i = 0; i < named; ++i) {
        const size_t nameRvaPos = static_cast<size_t>(namesOff) + i * sizeof(DWORD);
        const size_t ordPos = static_cast<size_t>(ordsOff) + i * sizeof(WORD);
        const auto* nameRvaPtr = At<DWORD>(base, nameRvaPos, fileSize);
        const auto* ordinalPtr = At<WORD>(base, ordPos, fileSize);
        if (!nameRvaPtr || !ordinalPtr) {
            break;
        }

        ExportInfo exp;
        const DWORD nameOff = RvaToFileOffset(*nameRvaPtr, report.sections, fileSize);
        if (nameOff) {
            ReadCString(base, fileSize, nameOff, 512, exp.name);
        }
        exp.ordinal = static_cast<WORD>(dir->Base + *ordinalPtr);

        const size_t funcPos = static_cast<size_t>(funcsOff) + static_cast<size_t>(*ordinalPtr) * sizeof(DWORD);
        const auto* funcRvaPtr = At<DWORD>(base, funcPos, fileSize);
        if (!funcRvaPtr) {
            continue;
        }
        exp.rva = *funcRvaPtr;
        exp.fileOffset = RvaToFileOffset(exp.rva, report.sections, fileSize);

        if (exp.rva >= exportBegin && exp.rva < exportEnd) {
            exp.isForwarded = true;
            const DWORD fwdOff = RvaToFileOffset(exp.rva, report.sections, fileSize);
            if (fwdOff) {
                ReadCString(base, fileSize, fwdOff, 512, exp.forwarder);
            }
        }
        report.exports.push_back(std::move(exp));
    }
}

void PEParser::ParseTls(const uint8_t* base, size_t fileSize, PEAnalysisReport& report,
                        const IMAGE_DATA_DIRECTORY& tlsDir) {
    report.tls = TlsDirectoryInfo{};
    if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0) {
        return;
    }

    const DWORD tlsOff = RvaToFileOffset(tlsDir.VirtualAddress, report.sections, fileSize);
    if (tlsOff == 0) {
        return;
    }

    ULONGLONG callbacksVa = 0;
    if (report.is64Bit) {
        const auto* tls = At<IMAGE_TLS_DIRECTORY64>(base, tlsOff, fileSize);
        if (!tls) {
            return;
        }
        report.tls.present = true;
        report.tls.startAddressOfRawData = tls->StartAddressOfRawData;
        report.tls.endAddressOfRawData = tls->EndAddressOfRawData;
        report.tls.addressOfIndex = tls->AddressOfIndex;
        report.tls.addressOfCallBacks = tls->AddressOfCallBacks;
        report.tls.sizeOfZeroFill = tls->SizeOfZeroFill;
        report.tls.characteristics = tls->Characteristics;
        callbacksVa = tls->AddressOfCallBacks;
    } else {
        const auto* tls = At<IMAGE_TLS_DIRECTORY32>(base, tlsOff, fileSize);
        if (!tls) {
            return;
        }
        report.tls.present = true;
        report.tls.startAddressOfRawData = tls->StartAddressOfRawData;
        report.tls.endAddressOfRawData = tls->EndAddressOfRawData;
        report.tls.addressOfIndex = tls->AddressOfIndex;
        report.tls.addressOfCallBacks = tls->AddressOfCallBacks;
        report.tls.sizeOfZeroFill = tls->SizeOfZeroFill;
        report.tls.characteristics = tls->Characteristics;
        callbacksVa = tls->AddressOfCallBacks;
    }

    if (callbacksVa == 0 || callbacksVa < report.imageBase) {
        return;
    }

    const ULONGLONG callbacksRva64 = callbacksVa - report.imageBase;
    if (callbacksRva64 > 0xFFFFFFFFull) {
        return;
    }
    const DWORD callbacksRva = static_cast<DWORD>(callbacksRva64);
    const DWORD cbOff = RvaToFileOffset(callbacksRva, report.sections, fileSize);
    if (cbOff == 0) {
        return;
    }

    const size_t slotSize = report.is64Bit ? sizeof(ULONGLONG) : sizeof(DWORD);
    for (size_t i = 0; i < kMaxTlsCallbacks; ++i) {
        const size_t slotOff = static_cast<size_t>(cbOff) + i * slotSize;
        if (!Fits(slotOff, slotSize, fileSize)) {
            break;
        }

        ULONGLONG va = 0;
        if (report.is64Bit) {
            va = *reinterpret_cast<const ULONGLONG*>(base + slotOff);
        } else {
            va = *reinterpret_cast<const DWORD*>(base + slotOff);
        }
        if (va == 0) {
            break;
        }

        TlsCallbackInfo cb;
        cb.va = va;
        if (va >= report.imageBase) {
            const ULONGLONG rva64 = va - report.imageBase;
            if (rva64 <= 0xFFFFFFFFull) {
                cb.rva = static_cast<DWORD>(rva64);
                cb.fileOffset = RvaToFileOffset(cb.rva, report.sections, fileSize);
            }
        }
        report.tls.callbacks.push_back(cb);
    }
}

bool PEParser::Parse(const uint8_t* base, size_t fileSize, PEAnalysisReport& outReport) {
    outReport = PEAnalysisReport{};
    if (!base || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY* dataDirs = nullptr;
    DWORD numberOfRvaAndSizes = 0;
    if (!ParseHeaders(base, fileSize, outReport, dataDirs, numberOfRvaAndSizes)) {
        return false;
    }

    const auto* sectionHeaders =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + outReport.sectionTableOffset);
    if (!ParseSections(base, fileSize, outReport, sectionHeaders, outReport.numberOfSections)) {
        return false;
    }

    outReport.entryPointOffset = RvaToFileOffset(outReport.entryPointRva, outReport.sections, fileSize);
    outReport.overallEntropy = CalculateShannonEntropy(base, fileSize);
    outReport.computedCheckSum = CalculatePECheckSum(base, fileSize, outReport.checkSumOffset);
    outReport.checksumMatches = (outReport.computedCheckSum == outReport.originalCheckSum) ||
                                (outReport.originalCheckSum == 0);

    ParseOverlay(base, fileSize, outReport);
    ParseRichHeader(base, fileSize, outReport);

    auto directory = [&](unsigned index) -> IMAGE_DATA_DIRECTORY {
        IMAGE_DATA_DIRECTORY empty{};
        if (!dataDirs || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES || index >= numberOfRvaAndSizes) {
            return empty;
        }
        return dataDirs[index];
    };

    ParseImports(base, fileSize, outReport, directory(IMAGE_DIRECTORY_ENTRY_IMPORT));
    ParseExports(base, fileSize, outReport, directory(IMAGE_DIRECTORY_ENTRY_EXPORT));
    ParseTls(base, fileSize, outReport, directory(IMAGE_DIRECTORY_ENTRY_TLS));
    return true;
}

}  // namespace axianware
