#include "UI.h"

#include "AnalysisEngine.h"
#include "PatchGenerator.h"
#include "PEParser.h"

#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>

#include <algorithm>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

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
#define IDM_ANALYSIS_EXPORTS     2106

#define IDM_PATCH_NOP_PROLOGUE   3001
#define IDM_PATCH_RET_PROLOGUE   3002
#define IDM_PATCH_INVERT_JUMP    3004
#define IDM_PATCH_GEN_HOOK       3006
#define IDM_PATCH_GEN_X64DBG     3007
#define IDM_PATCH_GEN_CHEATENG   3008
#define IDM_PATCH_DISABLE_ASLR   3009
#define IDM_PATCH_SECTION_RW     3010
#define IDM_PATCH_ROLLBACK       3011

#define IDM_HELP_ABOUT           4001

namespace axianware::ui {
namespace {

HWND g_hWndMain = nullptr;
HWND g_hListView = nullptr;
HWND g_hRichEdit = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hSearchEdit = nullptr;
HWND g_hSearchBtn = nullptr;
HMODULE g_hMsftedit = nullptr;

std::wstring g_currentFilePath;
PEAnalysisReport g_report;
StagedPatchManager g_patches;
size_t g_mappedSize = 0;

void RichEditClear(HWND hRichEdit) {
    SetWindowTextW(hRichEdit, L"");
}

void RichEditAppend(HWND hRichEdit, const std::wstring& text, COLORREF color = RGB(220, 220, 220), bool bold = false) {
    CHARRANGE cr{};
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessageW(hRichEdit, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&cr));

    CHARFORMAT2W cf{};
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

void UpdateStatusBar(HWND hStatusBar, const std::wstring& status, const PEAnalysisReport& rep) {
    SendMessageW(hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(status.c_str()));
    const std::wstring arch = rep.is64Bit ? L"x64 (PE32+)" : L"x86 (PE32)";
    SendMessageW(hStatusBar, SB_SETTEXT, 1, reinterpret_cast<LPARAM>(arch.c_str()));

    std::wstringstream ent;
    ent << L"Entropy: " << std::fixed << std::setprecision(2) << rep.overallEntropy;
    SendMessageW(hStatusBar, SB_SETTEXT, 2, reinterpret_cast<LPARAM>(ent.str().c_str()));

    const std::wstring patch = g_patches.Empty()
                                   ? L"CLEAN"
                                   : (L"STAGED (" + std::to_wstring(g_patches.Count()) + L" B)");
    SendMessageW(hStatusBar, SB_SETTEXT, 3, reinterpret_cast<LPARAM>(patch.c_str()));
}

void UpdateListViewItems(HWND hListView, const PEAnalysisReport& rep) {
    ListView_DeleteAllItems(hListView);
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    int idx = 0;

    auto addRow = [&](const std::wstring& cat, const std::wstring& name, const std::wstring& val,
                      const std::wstring& extra) {
        item.iItem = idx;
        item.pszText = const_cast<LPWSTR>(cat.c_str());
        ListView_InsertItem(hListView, &item);
        ListView_SetItemText(hListView, idx, 1, const_cast<LPWSTR>(name.c_str()));
        ListView_SetItemText(hListView, idx, 2, const_cast<LPWSTR>(val.c_str()));
        ListView_SetItemText(hListView, idx, 3, const_cast<LPWSTR>(extra.c_str()));
        ++idx;
    };

    for (const auto& sec : rep.sections) {
        std::wstringstream val, extra;
        val << L"RVA: " << HexDword(sec.virtualAddress) << L" | Raw: " << HexDword(sec.rawDataOffset);
        extra << L"Entropy: " << std::fixed << std::setprecision(2) << sec.entropy
              << (sec.isSuspiciousEntropy ? L" [HIGH]" : L"");
        addRow(L"Section", Utf8ToWide(sec.name), val.str(), extra.str());
    }

    if (rep.overlay.present) {
        std::wstringstream val, extra;
        val << L"Raw: " << HexDword(rep.overlay.offset) << L" | Size: " << HexDword(rep.overlay.size);
        extra << L"Entropy: " << std::fixed << std::setprecision(2) << rep.overlay.entropy;
        addRow(L"Overlay", L"Trailing data", val.str(), extra.str());
    }

    if (rep.tls.present) {
        addRow(L"TLS", L"Callbacks", std::to_wstring(rep.tls.callbacks.size()),
               HexQword(rep.tls.addressOfCallBacks));
    }

    for (const auto& imp : rep.imports) {
        const std::wstring alert = imp.sensitiveCount > 0
                                       ? (L"ALERT: " + std::to_wstring(imp.sensitiveCount) + L" sensitive API")
                                       : L"Normal";
        addRow(L"Import DLL", Utf8ToWide(imp.dllName),
               std::to_wstring(imp.functions.size()) + L" Functions", alert);
    }

    for (const auto& cd : rep.cryptoDetections) {
        std::wstringstream val;
        val << L"Raw: " << HexDword(static_cast<DWORD>(cd.offset)) << L" | RVA: " << HexDword(cd.rva);
        addRow(cd.type, cd.name, val.str(), L"Sec: " + Utf8ToWide(cd.sectionName));
    }
}

void RenderSummaryReport(HWND hRichEdit, const std::wstring& filePath, const PEAnalysisReport& rep) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"================================================================================\r\n", RGB(0, 150, 255), true);
    RichEditAppend(hRichEdit, L"                     AXIANWARE  PE AUDIT REPORT                                 \r\n", RGB(0, 255, 200), true);
    RichEditAppend(hRichEdit, L"================================================================================\r\n\r\n", RGB(0, 150, 255), true);

    RichEditAppend(hRichEdit, L"[+] File Path:       ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, filePath + L"\r\n", RGB(255, 255, 255));
    RichEditAppend(hRichEdit, L"[+] Architecture:    ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, rep.is64Bit ? L"AMD64 / x64 (PE32+)\r\n" : L"i386 / x86 (PE32)\r\n", RGB(255, 255, 255));

    std::wstringstream ep;
    ep << HexDword(rep.entryPointRva) << L" (File offset: " << HexDword(rep.entryPointOffset) << L")\r\n";
    RichEditAppend(hRichEdit, L"[+] Entry Point:     ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, ep.str(), RGB(255, 255, 255));

    std::wstringstream chk;
    chk << HexDword(rep.originalCheckSum) << L"  (computed " << HexDword(rep.computedCheckSum)
        << (rep.checksumMatches ? L", OK)\r\n" : L", MISMATCH)\r\n");
    RichEditAppend(hRichEdit, L"[+] PE CheckSum:     ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit, chk.str(), rep.checksumMatches ? RGB(100, 255, 100) : RGB(255, 80, 80));

    std::wstringstream ent;
    ent << std::fixed << std::setprecision(4) << rep.overallEntropy;
    RichEditAppend(hRichEdit, L"[+] Total Entropy:   ", RGB(255, 255, 0), true);
    RichEditAppend(hRichEdit,
                   ent.str() + (rep.overallEntropy > 7.2 ? L" [ALERT: Packed / Encrypted]\r\n\r\n" : L" [Normal]\r\n\r\n"),
                   rep.overallEntropy > 7.2 ? RGB(255, 80, 80) : RGB(100, 255, 100));

    RichEditAppend(hRichEdit, L"--- [ SECURITY MITIGATIONS ] ---------------------------------------------------\r\n", RGB(100, 200, 255), true);
    auto flagLine = [&](const wchar_t* label, bool enabled, bool warnIfOff = true) {
        RichEditAppend(hRichEdit, label, RGB(200, 200, 200));
        RichEditAppend(hRichEdit, enabled ? L"ENABLED\r\n" : L"DISABLED\r\n",
                       enabled ? RGB(100, 255, 100) : (warnIfOff ? RGB(255, 80, 80) : RGB(160, 160, 160)), true);
    };
    flagLine(L"  [*] ASLR (Dynamic Base):            ", rep.security.aslr);
    flagLine(L"  [*] High Entropy VA:                ", rep.security.highEntropyVA, false);
    flagLine(L"  [*] DEP / NX:                       ", rep.security.dep);
    flagLine(L"  [*] Control Flow Guard (CFG):       ", rep.security.controlFlowGuard, false);
    flagLine(L"  [*] SafeSEH / SEH present:          ", rep.security.safeSEH, false);
    RichEditAppend(hRichEdit, L"\r\n", RGB(200, 200, 200));

    RichEditAppend(hRichEdit, L"--- [ OVERLAY ] ----------------------------------------------------------------\r\n", RGB(100, 200, 255), true);
    if (rep.overlay.present) {
        std::wstringstream ov;
        ov << L"  Present at raw " << HexDword(rep.overlay.offset) << L", size " << HexDword(rep.overlay.size)
           << L", entropy " << std::fixed << std::setprecision(4) << rep.overlay.entropy << L"\r\n\r\n";
        RichEditAppend(hRichEdit, ov.str(), RGB(255, 180, 80), true);
    } else {
        RichEditAppend(hRichEdit, L"  No overlay (file ends at last section raw data).\r\n\r\n", RGB(100, 255, 100));
    }

    RichEditAppend(hRichEdit, L"--- [ RICH HEADER ] ------------------------------------------------------------\r\n", RGB(100, 200, 255), true);
    if (rep.richHeader.present) {
        std::wstringstream rh;
        rh << L"  XOR key " << HexDword(rep.richHeader.xorKey) << L"  DanS@" << HexDword(rep.richHeader.dansOffset)
           << L"  Rich@" << HexDword(rep.richHeader.richOffset) << L"\r\n";
        RichEditAppend(hRichEdit, rh.str(), RGB(200, 220, 255));
        for (const auto& e : rep.richHeader.entries) {
            std::wstringstream line;
            line << L"  ProdID 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill(L'0') << e.productId
                 << L"  build " << std::dec << e.buildNumber << L"  count " << e.count << L"  " << e.productName
                 << L"\r\n";
            RichEditAppend(hRichEdit, line.str(), RGB(200, 200, 200));
        }
        RichEditAppend(hRichEdit, L"\r\n", RGB(200, 200, 200));
    } else {
        RichEditAppend(hRichEdit, L"  Not present (or stripped).\r\n\r\n", RGB(160, 160, 160));
    }

    RichEditAppend(hRichEdit, L"--- [ TLS CALLBACKS ] ----------------------------------------------------------\r\n", RGB(100, 200, 255), true);
    if (rep.tls.present) {
        std::wstringstream tls;
        tls << L"  AddressOfCallBacks VA " << HexQword(rep.tls.addressOfCallBacks) << L"  ("
            << rep.tls.callbacks.size() << L" slots)\r\n";
        RichEditAppend(hRichEdit, tls.str(),
                       rep.tls.callbacks.empty() ? RGB(200, 200, 200) : RGB(255, 180, 80), !rep.tls.callbacks.empty());
        for (size_t i = 0; i < rep.tls.callbacks.size(); ++i) {
            const auto& cb = rep.tls.callbacks[i];
            std::wstringstream line;
            line << L"  [" << i << L"] VA " << HexQword(cb.va) << L"  RVA " << HexDword(cb.rva)
                 << L"  File " << HexDword(cb.fileOffset) << L"\r\n";
            RichEditAppend(hRichEdit, line.str(), RGB(255, 215, 120));
        }
        RichEditAppend(hRichEdit, L"\r\n", RGB(200, 200, 200));
    } else {
        RichEditAppend(hRichEdit, L"  TLS directory not present.\r\n\r\n", RGB(160, 160, 160));
    }

    RichEditAppend(hRichEdit, L"--- [ SECTION ENTROPY ] --------------------------------------------------------\r\n", RGB(100, 200, 255), true);
    for (const auto& sec : rep.sections) {
        std::wstringstream ss;
        ss << L"  " << std::left << std::setw(8) << Utf8ToWide(sec.name)
           << L" | VA " << HexDword(sec.virtualAddress)
           << L" | Raw " << HexDword(sec.rawDataOffset)
           << L" | Entropy " << std::fixed << std::setprecision(4) << sec.entropy;
        if (sec.isSuspiciousEntropy) {
            ss << L" [PACKED / OBFUSCATED]";
        }
        ss << L"\r\n";
        RichEditAppend(hRichEdit, ss.str(), sec.isSuspiciousEntropy ? RGB(255, 80, 80) : RGB(200, 200, 200),
                       sec.isSuspiciousEntropy);
    }
}

void RenderImports(HWND hRichEdit, const PEAnalysisReport& rep) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"=== IMPORT ADDRESS TABLE ================================================\r\n\r\n",
                   RGB(0, 150, 255), true);
    for (const auto& mod : rep.imports) {
        std::wstringstream hdr;
        hdr << Utf8ToWide(mod.dllName) << L"  (" << mod.functions.size() << L" imports";
        if (mod.sensitiveCount) {
            hdr << L", " << mod.sensitiveCount << L" sensitive";
        }
        hdr << L")\r\n";
        RichEditAppend(hRichEdit, hdr.str(), mod.sensitiveCount ? RGB(255, 180, 80) : RGB(0, 255, 200), true);
        for (const auto& fn : mod.functions) {
            std::wstringstream line;
            if (fn.isOrdinal) {
                line << L"    ord " << fn.ordinal;
            } else {
                line << L"    " << Utf8ToWide(fn.name);
            }
            if (fn.risk != ApiRisk::Normal) {
                line << L"  [" << fn.category << L"]";
            }
            line << L"\r\n";
            RichEditAppend(hRichEdit, line.str(), fn.risk != ApiRisk::Normal ? RGB(255, 80, 80) : RGB(200, 220, 255));
        }
        RichEditAppend(hRichEdit, L"\r\n", RGB(200, 200, 200));
    }
}

void RenderExports(HWND hRichEdit, const PEAnalysisReport& rep) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"=== EXPORT DIRECTORY ====================================================\r\n\r\n",
                   RGB(0, 150, 255), true);
    if (rep.exports.empty()) {
        RichEditAppend(hRichEdit, L"No named exports.\r\n", RGB(160, 160, 160));
        return;
    }
    for (const auto& exp : rep.exports) {
        std::wstringstream line;
        line << L"  " << Utf8ToWide(exp.name) << L"  ord " << exp.ordinal << L"  RVA " << HexDword(exp.rva)
             << L"  File " << HexDword(exp.fileOffset);
        if (exp.isForwarded) {
            line << L"  -> " << Utf8ToWide(exp.forwarder);
        }
        line << L"\r\n";
        RichEditAppend(hRichEdit, line.str(), exp.isForwarded ? RGB(255, 215, 120) : RGB(200, 220, 255));
    }
}

void RenderDisassemblyView(HWND hRichEdit, const uint8_t* base, size_t fileSize, DWORD targetOffset,
                           DWORD targetRva, size_t instructionCount = 36) {
    RichEditClear(hRichEdit);
    RichEditAppend(hRichEdit, L"=== DISASSEMBLY =========================================================\r\n\r\n",
                   RGB(0, 150, 255), true);
    if (targetOffset >= fileSize) {
        RichEditAppend(hRichEdit, L"Target offset is outside the file.\r\n", RGB(255, 80, 80));
        return;
    }

    size_t currOffset = targetOffset;
    ULONGLONG currRva = targetRva;
    for (size_t i = 0; i < instructionCount && currOffset < fileSize; ++i) {
        const DecodedInsn insn =
            AnalysisEngine::DecodeInstruction(base + currOffset, fileSize - currOffset, currRva, g_report.is64Bit);
        std::wstringstream ss;
        ss << HexDword(static_cast<DWORD>(currRva)) << L"  (Raw " << HexDword(static_cast<DWORD>(currOffset)) << L")  "
           << std::left << std::setw(20) << insn.bytesHex << L"  " << insn.text;
        if (insn.isConditionalJump) {
            ss << L"  [Jcc invertible]";
        }
        ss << L"\r\n";
        RichEditAppend(hRichEdit, ss.str(),
                       insn.isConditionalJump ? RGB(255, 180, 80) : ((i == 0) ? RGB(255, 255, 0) : RGB(200, 220, 255)));
        currOffset += insn.length;
        currRva += insn.length;
    }
}

bool LoadBinary(HWND hWnd, const std::wstring& path) {
    MemoryMappedFile mmf;
    if (!mmf.Open(path)) {
        MessageBoxW(hWnd, L"Failed to map target file.", L"File Error", MB_ICONERROR);
        return false;
    }
    if (!PEParser::Parse(mmf.Data(), mmf.Size(), g_report)) {
        MessageBoxW(hWnd, L"Invalid Portable Executable header.", L"Parser Error", MB_ICONERROR);
        return false;
    }
    g_currentFilePath = path;
    g_mappedSize = mmf.Size();
    g_patches.Clear();
    g_report.isPatched = false;
    UpdateListViewItems(g_hListView, g_report);
    RenderSummaryReport(g_hRichEdit, g_currentFilePath, g_report);
    UpdateStatusBar(g_hStatusBar, L"Binary loaded", g_report);
    return true;
}

void OnFileOpen(HWND hWnd) {
    wchar_t szFile[MAX_PATH] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"PE Executables (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        if (LoadBinary(hWnd, szFile)) {
            std::thread([hWnd, path = g_currentFilePath]() {
                MemoryMappedFile mmf;
                if (!mmf.Open(path)) {
                    return;
                }
                auto* detections = new std::vector<CryptoDetection>();
                AnalysisEngine::ScanCryptoAndAntiSignatures(mmf.Data(), mmf.Size(), g_report.sections, *detections);
                PostMessageW(hWnd, WM_APP_CRYPTO_COMPLETE, 0, reinterpret_cast<LPARAM>(detections));
            }).detach();
        }
    }
}

void OnFileSaveAs(HWND hWnd) {
    if (g_currentFilePath.empty()) {
        MessageBoxW(hWnd, L"No binary loaded.", L"Save Error", MB_ICONWARNING);
        return;
    }
    wchar_t szOut[MAX_PATH] = {};
    wcscpy_s(szOut, g_currentFilePath.c_str());
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"Executable Files (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szOut;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) {
        return;
    }

    MemoryMappedFile src;
    if (!src.Open(g_currentFilePath)) {
        MessageBoxW(hWnd, L"Failed to read source binary.", L"Error", MB_ICONERROR);
        return;
    }
    std::vector<uint8_t> buffer(src.Data(), src.Data() + src.Size());
    src.Close();
    if (!g_patches.ApplyToBuffer(buffer.data(), buffer.size())) {
        MessageBoxW(hWnd, L"Staged patch is out of bounds.", L"Error", MB_ICONERROR);
        return;
    }
    if (!PatchGenerator::RecalculateAndWriteCheckSum(buffer.data(), buffer.size(), g_report)) {
        MessageBoxW(hWnd, L"Failed to recalculate PE CheckSum.", L"Error", MB_ICONERROR);
        return;
    }

    ScopedHandle hOut(CreateFileW(szOut, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hOut.IsValid()) {
        MessageBoxW(hWnd, L"Failed to create output file.", L"Error", MB_ICONERROR);
        return;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(hOut.Get(), buffer.data(), static_cast<DWORD>(buffer.size()), &written, nullptr);
    if (!ok || written != buffer.size()) {
        MessageBoxW(hWnd, L"Failed to write patched binary.", L"Error", MB_ICONERROR);
        return;
    }
    MessageBoxW(hWnd, L"Saved with recalculated PE CheckSum.", L"Saved", MB_ICONINFORMATION);
    UpdateStatusBar(g_hStatusBar, L"Binary saved", g_report);
}

uint8_t ReadOriginalByte(DWORD offset) {
    MemoryMappedFile mmf;
    if (!mmf.Open(g_currentFilePath) || offset >= mmf.Size()) {
        return 0;
    }
    return mmf.Data()[offset];
}

void StageByte(HWND hWnd, DWORD offset, uint8_t patched, const wchar_t* status) {
    if (g_currentFilePath.empty() || g_mappedSize == 0) {
        return;
    }
    const uint8_t original = ReadOriginalByte(offset);
    if (!g_patches.Add(offset, original, patched, g_mappedSize)) {
        MessageBoxW(hWnd, L"Patch offset is outside the file.", L"Patch", MB_ICONWARNING);
        return;
    }
    g_report.isPatched = true;
    UpdateStatusBar(g_hStatusBar, status, g_report);
}

void OnInvertJump(HWND hWnd) {
    if (g_currentFilePath.empty()) {
        return;
    }
    MemoryMappedFile mmf;
    if (!mmf.Open(g_currentFilePath)) {
        return;
    }
    const DWORD targetOffset = g_report.entryPointOffset;
    if (targetOffset >= mmf.Size()) {
        return;
    }
    const DecodedInsn insn = AnalysisEngine::DecodeInstruction(
        mmf.Data() + targetOffset, mmf.Size() - targetOffset, g_report.entryPointRva, g_report.is64Bit);
    if (!insn.isConditionalJump || insn.invertOpcode == 0) {
        MessageBoxW(hWnd, L"Instruction at the entry point is not an invertible Jcc.", L"Info", MB_ICONINFORMATION);
        return;
    }
    const DWORD patchOff = targetOffset + static_cast<DWORD>(insn.invertOpcodeOffset);
    StageByte(hWnd, patchOff, insn.invertOpcode, L"Jcc inverted (staged)");
    MessageBoxW(hWnd, L"Conditional jump inverted in the staged buffer. Save As to write it.", L"Patch Staged",
                MB_ICONINFORMATION);
}

void OnDisableAslr(HWND hWnd) {
    if (g_currentFilePath.empty()) {
        return;
    }
    MemoryMappedFile mmf;
    if (!mmf.Open(g_currentFilePath)) {
        return;
    }
    if (!PatchGenerator::StageDisableDynamicBase(mmf.Data(), mmf.Size(), g_report, g_patches)) {
        MessageBoxW(hWnd, L"Could not locate DllCharacteristics.", L"Error", MB_ICONERROR);
        return;
    }
    g_report.isPatched = true;
    UpdateStatusBar(g_hStatusBar, L"DYNAMIC_BASE cleared (staged)", g_report);
    MessageBoxW(hWnd, L"ASLR / Dynamic Base flags staged for the Optional Header. Save As to commit.",
                L"Patch Staged", MB_ICONINFORMATION);
}

void OnSectionReadWrite(HWND hWnd) {
    if (g_currentFilePath.empty() || g_report.sections.empty()) {
        return;
    }
    MemoryMappedFile mmf;
    if (!mmf.Open(g_currentFilePath)) {
        return;
    }
    if (!PatchGenerator::StageSectionReadWrite(mmf.Data(), mmf.Size(), g_report, 0, true, g_patches)) {
        MessageBoxW(hWnd, L"Could not update section characteristics.", L"Error", MB_ICONERROR);
        return;
    }
    g_report.isPatched = true;
    UpdateStatusBar(g_hStatusBar, L"First section marked R/W (staged)", g_report);
    MessageBoxW(hWnd, L"IMAGE_SCN_MEM_READ|WRITE staged on section[0]. Save As to commit.", L"Patch Staged",
                MB_ICONINFORMATION);
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
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_EXPORTS, L"&Exported APIs (EAT)");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_STRINGS, L"&Extract Strings (Async)");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_CRYPTO_SCAN, L"&Crypto & Anti-Analysis Audit");
        AppendMenuW(hMenuAnalysis, MF_STRING, IDM_ANALYSIS_DISASM_EP, L"&Disassemble Entry Point");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuAnalysis), L"&Analysis");

        HMENU hMenuPatch = CreatePopupMenu();
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_NOP_PROLOGUE, L"NOP Out Entry (0x90)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_RET_PROLOGUE, L"Force Return (RET / 0xC3)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_INVERT_JUMP, L"Invert Conditional Jump (Jcc)");
        AppendMenuW(hMenuPatch, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_DISABLE_ASLR, L"Clear DYNAMIC_BASE (ASLR) flag");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_SECTION_RW, L"Mark first section Read/Write");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_ROLLBACK, L"Rollback staged patches");
        AppendMenuW(hMenuPatch, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_HOOK, L"Generate local trampoline DLL template");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_X64DBG, L"Generate x64dbg Patch (.1337)");
        AppendMenuW(hMenuPatch, MF_STRING, IDM_PATCH_GEN_CHEATENG, L"Generate Cheat Engine Script");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuPatch), L"&Patch && Toolkit");

        HMENU hMenuHelp = CreatePopupMenu();
        AppendMenuW(hMenuHelp, MF_STRING, IDM_HELP_ABOUT, L"&About AXIANWARE...");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hMenuHelp), L"&Help");
        SetMenu(hWnd, hMenuBar);

        g_hSearchEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"E8 ?? ?? ?? ?? 85 C0",
                                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 5, 5, 340, 26, hWnd,
                                        reinterpret_cast<HMENU>(IDC_SEARCH_EDIT), GetModuleHandleW(nullptr), nullptr);
        g_hSearchBtn = CreateWindowExW(0, L"BUTTON", L"Find AOB", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 350, 5, 90, 26,
                                       hWnd, reinterpret_cast<HMENU>(IDC_SEARCH_BTN), GetModuleHandleW(nullptr),
                                       nullptr);
        g_hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                      WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 0, 36, 440, 560, hWnd,
                                      reinterpret_cast<HMENU>(IDC_MAIN_LISTVIEW), GetModuleHandleW(nullptr), nullptr);
        ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        LVCOLUMNW lvc{};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        const wchar_t* headers[] = {L"Category", L"Name / Symbol", L"Address / Offset", L"Entropy & Attributes"};
        const int widths[] = {110, 140, 150, 120};
        for (int i = 0; i < 4; ++i) {
            lvc.iSubItem = i;
            lvc.pszText = const_cast<LPWSTR>(headers[i]);
            lvc.cx = widths[i];
            ListView_InsertColumn(g_hListView, i, &lvc);
        }

        g_hRichEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                ES_READONLY,
            440, 0, 600, 600, hWnd, reinterpret_cast<HMENU>(IDC_MAIN_RICHEDIT), GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g_hRichEdit, EM_SETBKGNDCOLOR, 0, RGB(20, 22, 26));

        g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0,
                                       hWnd, reinterpret_cast<HMENU>(IDC_MAIN_STATUSBAR), GetModuleHandleW(nullptr),
                                       nullptr);
        int statWidths[] = {350, 500, 680, -1};
        SendMessageW(g_hStatusBar, SB_SETPARTS, 4, reinterpret_cast<LPARAM>(statWidths));
        SendMessageW(g_hStatusBar, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Ready"));
        return 0;
    }

    case WM_SIZE: {
        const int width = LOWORD(lParam);
        const int height = HIWORD(lParam);
        SendMessageW(g_hStatusBar, WM_SIZE, wParam, lParam);
        RECT rcStatus{};
        GetWindowRect(g_hStatusBar, &rcStatus);
        const int statH = rcStatus.bottom - rcStatus.top;
        const int clientH = height - statH;
        const int listWidth = (std::max)(360, width * 38 / 100);
        MoveWindow(g_hSearchEdit, 5, 5, listWidth - 100, 26, TRUE);
        MoveWindow(g_hSearchBtn, listWidth - 90, 5, 85, 26, TRUE);
        MoveWindow(g_hListView, 0, 36, listWidth, clientH - 36, TRUE);
        MoveWindow(g_hRichEdit, listWidth, 0, width - listWidth, clientH, TRUE);
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
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        for (size_t i = 0; i < matches->size(); ++i) {
            const size_t off = (*matches)[i];
            const DWORD rva = FileOffsetToRva(static_cast<DWORD>(off), g_report.sections);
            const std::string sec = GetSectionNameByOffset(static_cast<DWORD>(off), g_report.sections);
            std::wstringstream name, val, extra;
            name << L"Match #" << (i + 1);
            val << L"Raw: " << HexDword(static_cast<DWORD>(off)) << L" | RVA: " << HexDword(rva);
            extra << L"Sec: " << Utf8ToWide(sec);
            const std::wstring cat = L"AOB Match";
            const std::wstring n = name.str();
            const std::wstring v = val.str();
            const std::wstring e = extra.str();
            item.iItem = static_cast<int>(i);
            item.pszText = const_cast<LPWSTR>(cat.c_str());
            ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, static_cast<int>(i), 1, const_cast<LPWSTR>(n.c_str()));
            ListView_SetItemText(g_hListView, static_cast<int>(i), 2, const_cast<LPWSTR>(v.c_str()));
            ListView_SetItemText(g_hListView, static_cast<int>(i), 3, const_cast<LPWSTR>(e.c_str()));
        }
        UpdateStatusBar(g_hStatusBar, L"Found " + std::to_wstring(matches->size()) + L" AOB matches", g_report);
        return 0;
    }

    case WM_APP_STRINGS_COMPLETE: {
        std::unique_ptr<std::vector<ExtractedString>> pStrings(reinterpret_cast<std::vector<ExtractedString>*>(lParam));
        g_report.strings = std::move(*pStrings);
        RichEditClear(g_hRichEdit);
        RichEditAppend(g_hRichEdit, L"=== EXTRACTED STRINGS ====================================================\r\n\r\n",
                       RGB(0, 150, 255), true);
        for (size_t i = 0; i < (std::min)(g_report.strings.size(), static_cast<size_t>(1200)); ++i) {
            const auto& s = g_report.strings[i];
            std::wstringstream ss;
            ss << L"[" << (s.isUnicode ? L"UTF-16" : L"ASCII ") << L" " << HexDword(static_cast<DWORD>(s.offset))
               << L" | RVA " << HexDword(s.rva) << L"] " << s.text << L"\r\n";
            RichEditAppend(g_hRichEdit, ss.str(), s.isUnicode ? RGB(255, 215, 120) : RGB(180, 220, 255));
        }
        UpdateStatusBar(g_hStatusBar, L"Strings extraction complete", g_report);
        return 0;
    }

    case WM_APP_CRYPTO_COMPLETE: {
        std::unique_ptr<std::vector<CryptoDetection>> pDet(reinterpret_cast<std::vector<CryptoDetection>*>(lParam));
        g_report.cryptoDetections = std::move(*pDet);
        UpdateListViewItems(g_hListView, g_report);
        UpdateStatusBar(g_hStatusBar, L"Crypto & anti-analysis audit complete", g_report);
        return 0;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_SEARCH_BTN) {
            wchar_t patBuf[512] = {};
            GetWindowTextW(g_hSearchEdit, patBuf, 512);
            const std::wstring path = g_currentFilePath;
            const std::wstring pattern = patBuf;
            std::thread([hWnd, path, pattern]() {
                MemoryMappedFile mmf;
                if (!mmf.Open(path)) {
                    return;
                }
                const auto pat = AnalysisEngine::ParseAobPattern(pattern);
                auto* matches = new std::vector<size_t>(AnalysisEngine::ScanAob(mmf.Data(), mmf.Size(), pat));
                PostMessageW(hWnd, WM_APP_AOB_COMPLETE, 0, reinterpret_cast<LPARAM>(matches));
            }).detach();
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
                RichEditAppend(g_hRichEdit, L"=== RAW HEX DUMP (first 4 KiB) ===\r\n\r\n", RGB(0, 150, 255), true);
                std::wstringstream ss;
                const size_t limit = (std::min)(mmf.Size(), static_cast<size_t>(4096));
                for (size_t i = 0; i < limit; i += 16) {
                    ss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(8) << i << L"    ";
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < limit) {
                            ss << std::setw(2) << static_cast<int>(mmf.Data()[i + j]) << L" ";
                        } else {
                            ss << L"   ";
                        }
                    }
                    ss << L"\r\n";
                }
                RichEditAppend(g_hRichEdit, ss.str(), RGB(0, 255, 128));
                UpdateStatusBar(g_hStatusBar, L"Hex view", g_report);
            }
            break;
        }
        case IDM_ANALYSIS_SUMMARY:
            RenderSummaryReport(g_hRichEdit, g_currentFilePath, g_report);
            break;
        case IDM_ANALYSIS_IMPORTS:
            RenderImports(g_hRichEdit, g_report);
            break;
        case IDM_ANALYSIS_EXPORTS:
            RenderExports(g_hRichEdit, g_report);
            break;
        case IDM_ANALYSIS_STRINGS: {
            const std::wstring path = g_currentFilePath;
            std::thread([hWnd, path]() {
                MemoryMappedFile mmf;
                if (!mmf.Open(path)) {
                    return;
                }
                auto* strings = new std::vector<ExtractedString>(
                    AnalysisEngine::ExtractStrings(mmf.Data(), mmf.Size(), g_report.sections));
                PostMessageW(hWnd, WM_APP_STRINGS_COMPLETE, 0, reinterpret_cast<LPARAM>(strings));
            }).detach();
            break;
        }
        case IDM_ANALYSIS_CRYPTO_SCAN: {
            const std::wstring path = g_currentFilePath;
            std::thread([hWnd, path]() {
                MemoryMappedFile mmf;
                if (!mmf.Open(path)) {
                    return;
                }
                auto* detections = new std::vector<CryptoDetection>();
                AnalysisEngine::ScanCryptoAndAntiSignatures(mmf.Data(), mmf.Size(), g_report.sections, *detections);
                PostMessageW(hWnd, WM_APP_CRYPTO_COMPLETE, 0, reinterpret_cast<LPARAM>(detections));
            }).detach();
            break;
        }
        case IDM_ANALYSIS_DISASM_EP: {
            MemoryMappedFile mmf;
            if (mmf.Open(g_currentFilePath)) {
                RenderDisassemblyView(g_hRichEdit, mmf.Data(), mmf.Size(), g_report.entryPointOffset,
                                      g_report.entryPointRva);
                UpdateStatusBar(g_hStatusBar, L"Disassembly", g_report);
            }
            break;
        }
        case IDM_PATCH_NOP_PROLOGUE:
            StageByte(hWnd, g_report.entryPointOffset, 0x90, L"NOP staged");
            StageByte(hWnd, g_report.entryPointOffset + 1, 0x90, L"NOP sled staged");
            MessageBoxW(hWnd, L"NOP sled staged. Save As to commit.", L"Staged", MB_ICONINFORMATION);
            break;
        case IDM_PATCH_RET_PROLOGUE:
            StageByte(hWnd, g_report.entryPointOffset, 0xC3, L"RET staged");
            MessageBoxW(hWnd, L"RET staged. Save As to commit.", L"Staged", MB_ICONINFORMATION);
            break;
        case IDM_PATCH_INVERT_JUMP:
            OnInvertJump(hWnd);
            break;
        case IDM_PATCH_DISABLE_ASLR:
            OnDisableAslr(hWnd);
            break;
        case IDM_PATCH_SECTION_RW:
            OnSectionReadWrite(hWnd);
            break;
        case IDM_PATCH_ROLLBACK:
            g_patches.RollbackAll();
            g_report.isPatched = false;
            UpdateStatusBar(g_hStatusBar, L"Staged patches rolled back", g_report);
            break;
        case IDM_PATCH_GEN_HOOK: {
            const std::wstring code = PatchGenerator::GenerateInlineHookDllTemplate(g_report, g_report.entryPointRva);
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(220, 220, 220));
            break;
        }
        case IDM_PATCH_GEN_X64DBG: {
            const std::wstring code = PatchGenerator::Generate1337Patch(g_currentFilePath, g_report, g_patches);
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(100, 255, 100));
            break;
        }
        case IDM_PATCH_GEN_CHEATENG: {
            uint8_t orig[2] = {ReadOriginalByte(g_report.entryPointOffset),
                               ReadOriginalByte(g_report.entryPointOffset + 1)};
            uint8_t patch[2] = {0x90, 0x90};
            const auto it0 = g_patches.Patches().find(g_report.entryPointOffset);
            const auto it1 = g_patches.Patches().find(g_report.entryPointOffset + 1);
            if (it0 != g_patches.Patches().end()) {
                orig[0] = it0->second.original;
                patch[0] = it0->second.patched;
            }
            if (it1 != g_patches.Patches().end()) {
                orig[1] = it1->second.original;
                patch[1] = it1->second.patched;
            }
            const std::wstring code = PatchGenerator::GenerateCheatEngineScript(
                g_currentFilePath, g_report, g_report.entryPointRva, orig, patch, 2);
            RichEditClear(g_hRichEdit);
            RichEditAppend(g_hRichEdit, code, RGB(255, 215, 120));
            break;
        }
        case IDM_HELP_ABOUT:
            MessageBoxW(hWnd, L"AXIANWARE\nPE audit toolkit\ncreated by eloyssync.", L"About", MB_ICONINFORMATION);
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

}  // namespace

int Run(HINSTANCE hInstance, int nCmdShow) {
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    g_hMsftedit = LoadLibraryW(L"msftedit.dll");
    if (!g_hMsftedit) {
        return 1;
    }

    const wchar_t CLASS_NAME[] = L"PEInspectorSuiteWindowClass";
    WNDCLASSEXW wc{};
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

    g_hWndMain = CreateWindowExW(0, CLASS_NAME, L"AXIANWARE", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
                                 CW_USEDEFAULT, 1140, 740, nullptr, nullptr, hInstance, nullptr);
    if (!g_hWndMain) {
        FreeLibrary(g_hMsftedit);
        return 1;
    }

    ShowWindow(g_hWndMain, nCmdShow);
    UpdateWindow(g_hWndMain);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FreeLibrary(g_hMsftedit);
    return static_cast<int>(msg.wParam);
}

}  // namespace axianware::ui
