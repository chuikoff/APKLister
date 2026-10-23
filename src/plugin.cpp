// SPDX-License-Identifier: GPL-2.0-or-later
// APK Lister: Total Commander Lister (WLX) plugin front-end.
#include <windows.h>
#include <commctrl.h>
#include <wincodec.h>
#include <string>
#include <vector>
#include "analyzer.h"
#include "plat.h"
#include "version.h"

#define EXPORT extern "C" __declspec(dllexport)

// ---- WLX SDK constants (listplug.h)
#define lc_copy 1
#define lc_newparams 2
#define lc_selectall 3
#define lc_setpercent 4
#define lcs_findfirst 1
#define lcs_matchcase 2
#define lcs_wholewords 4
#define lcs_backwards 8
#define LISTPLUGIN_OK 0
#define LISTPLUGIN_ERROR 1
struct ListDefaultParamStruct { int size; DWORD PluginInterfaceVersionLow; DWORD PluginInterfaceVersionHi; char DefaultIniName[MAX_PATH]; };

static HINSTANCE g_inst;
static wchar_t g_default_ini[MAX_PATH]; // TC's lsplugin.ini (from ListSetDefaultParams)
static const wchar_t* kClass = L"APKListerWindow";
static const int kHeaderH = 76; // header height at 96 dpi: title, package line, architecture line

struct View {
    HWND hwnd = nullptr, edit = nullptr;
    HFONT mono = nullptr, title_font = nullptr, ui_font = nullptr, ui_bold = nullptr;
    WNDPROC old_edit = nullptr;
    Report rep;
    std::wstring text, lower_text;
    HBITMAP icon = nullptr; int icon_w = 0, icon_h = 0;
    std::wstring title, subtitle, arch;
    int dpi = 96;
    int S(int v) const { return MulDiv(v, dpi, 96); }
};

static std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n); return w;
}
static std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0'); WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr); return s;
}
static std::wstring crlf(const std::string& s) {
    std::wstring w = widen(s), o; o.reserve(w.size() + w.size() / 20);
    for (wchar_t c : w) { if (c == L'\n') o += L'\r'; o += c; }
    return o;
}

// ---- language: apklister.ini next to the plugin, then TC's lsplugin.ini ([APKLister] Language=auto|ru|en),
// then TC's own UI language (wincmd.ini [Configuration] LanguageIni), then the Windows UI language.
static std::wstring read_ini(const wchar_t* file, const wchar_t* sec, const wchar_t* key) {
    if (!file || !*file) return L"";
    wchar_t buf[260] = L"";
    GetPrivateProfileStringW(sec, key, L"\x01", buf, 260, file);
    return buf[0] == 1 ? std::wstring(L"\x01") : std::wstring(buf);
}
static bool lang_from_setting(const std::wstring& v, Lang& out) { return v != L"\x01" && parse_lang(narrow(v), out); }
static Lang resolve_lang() {
    Lang l;
    wchar_t dll[MAX_PATH] = L""; GetModuleFileNameW(g_inst, dll, MAX_PATH);
    std::wstring own = dll; size_t k = own.find_last_of(L"\\/"); own = (k == std::wstring::npos ? std::wstring() : own.substr(0, k + 1)) + L"apklister.ini";
    if (lang_from_setting(read_ini(own.c_str(), L"APKLister", L"Language"), l)) return l;
    if (lang_from_setting(read_ini(g_default_ini, L"APKLister", L"Language"), l)) return l;
    wchar_t tcini[MAX_PATH] = L"";
    if (GetEnvironmentVariableW(L"COMMANDER_INI", tcini, MAX_PATH) && tcini[0]) {
        std::wstring li = read_ini(tcini, L"Configuration", L"LanguageIni");
        if (li != L"\x01") {
            CharLowerBuffW(&li[0], (DWORD)li.size());
            if (li.find(L"rus") != std::wstring::npos) return Lang::Ru;
            if (!li.empty()) return Lang::En;
        }
    }
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_RUSSIAN ? Lang::Ru : Lang::En;
}

// ---- icon decoding through WIC (PNG always; WebP/JPEG when the codec exists)
static HBITMAP decode_image(const std::vector<uint8_t>& data, int maxw, int maxh, bool on_white, int* outw, int* outh) {
    if (data.empty()) return nullptr;
    HRESULT ci = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    HBITMAP bmp = nullptr;
    IWICImagingFactory* f = nullptr; IWICStream* s = nullptr; IWICBitmapDecoder* d = nullptr;
    IWICBitmapFrameDecode* fr = nullptr; IWICBitmapScaler* sc = nullptr; IWICFormatConverter* cv = nullptr;
    UINT w = 0, h = 0;
    do {
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory, (void**)&f))) break;
        if (FAILED(f->CreateStream(&s))) break;
        if (FAILED(s->InitializeFromMemory((BYTE*)data.data(), (DWORD)data.size()))) break;
        if (FAILED(f->CreateDecoderFromStream(s, nullptr, WICDecodeMetadataCacheOnDemand, &d))) break;
        if (FAILED(d->GetFrame(0, &fr))) break;
        if (FAILED(fr->GetSize(&w, &h)) || !w || !h) break;
        double k = (double)maxw / w; if ((double)maxh / h < k) k = (double)maxh / h;
        UINT tw = (UINT)(w * k + 0.5), th = (UINT)(h * k + 0.5); if (!tw) tw = 1; if (!th) th = 1;
        if (FAILED(f->CreateBitmapScaler(&sc))) break;
        if (FAILED(sc->Initialize(fr, tw, th, WICBitmapInterpolationModeFant))) break;
        if (FAILED(f->CreateFormatConverter(&cv))) break;
        if (FAILED(cv->Initialize(sc, GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0, WICBitmapPaletteTypeCustom))) break;
        BITMAPINFO bi = {}; bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = (LONG)tw; bi.bmiHeader.biHeight = -(LONG)th;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
        void* bits = nullptr;
        bmp = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (!bmp) break;
        if (FAILED(cv->CopyPixels(nullptr, tw * 4, tw * 4 * th, (BYTE*)bits))) { DeleteObject(bmp); bmp = nullptr; break; }
        if (on_white) { // premultiplied -> composite on white, opaque
            uint8_t* p = (uint8_t*)bits;
            for (UINT i = 0; i < tw * th; i++, p += 4) { int a = p[3]; p[0] = (uint8_t)(p[0] + 255 - a); p[1] = (uint8_t)(p[1] + 255 - a); p[2] = (uint8_t)(p[2] + 255 - a); p[3] = 255; }
        }
        if (outw) *outw = (int)tw;
        if (outh) *outh = (int)th;
    } while (0);
    if (cv) cv->Release(); if (sc) sc->Release(); if (fr) fr->Release(); if (d) d->Release(); if (s) s->Release(); if (f) f->Release();
    if (ci == S_OK || ci == S_FALSE) CoUninitialize();
    return bmp;
}

static void layout(View* v) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int hh = v->S(kHeaderH);
    MoveWindow(v->edit, 0, hh, rc.right, rc.bottom - hh > 0 ? rc.bottom - hh : 0, TRUE);
    InvalidateRect(v->hwnd, nullptr, FALSE);
}

static void load_file(View* v, const std::wstring& path) {
    v->rep = Report();
    MappedFile mf; std::string err; std::string p8 = narrow(path);
    Lang lang = resolve_lang();
    set_lang(lang);
    if (!mf.open(p8, err)) {
        v->rep.title = narrow(path.substr(path.find_last_of(L"\\/") + 1));
        v->rep.subtitle = T("cannot open file: ") + err;
        v->rep.summary = T("cannot open file: ") + p8 + "\n" + err + "\n";
    } else {
        AnalyzeOptions opt;
        opt.summary_only = true;
        opt.lang = lang;
        analyze(p8, Bytes(mf.p, (size_t)mf.size), opt, v->rep);
    }
    v->text = crlf(v->rep.summary);
    v->lower_text.clear();
    v->rep.summary.clear(); v->rep.summary.shrink_to_fit();
    v->title = widen(v->rep.title); v->subtitle = widen(v->rep.subtitle); v->arch = widen(v->rep.arch);
    if (v->icon) DeleteObject(v->icon);
    v->icon = decode_image(v->rep.icon, v->S(44), v->S(44), false, &v->icon_w, &v->icon_h);
    v->rep.icon.clear(); v->rep.icon.shrink_to_fit();
    SendMessageW(v->edit, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(v->edit, v->text.c_str());
    SendMessageW(v->edit, EM_SETSEL, 0, 0);
    SendMessageW(v->edit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(v->edit, nullptr, TRUE);
    InvalidateRect(v->hwnd, nullptr, TRUE);
}

static LRESULT CALLBACK EditProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    View* v = (View*)GetWindowLongPtrW(GetParent(h), GWLP_USERDATA);
    if (!v) return DefWindowProcW(h, m, w, l);
    bool ctrl = GetKeyState(VK_CONTROL) < 0;
    if (m == WM_KEYDOWN) {
        if (ctrl && w == 'A') { SendMessageW(h, EM_SETSEL, 0, -1); return 0; }
        if (ctrl && (w == 'C' || w == VK_INSERT)) { SendMessageW(h, WM_COPY, 0, 0); return 0; }
        switch (w) {
        case VK_LEFT: case VK_RIGHT: case VK_UP: case VK_DOWN: case VK_PRIOR: case VK_NEXT: case VK_HOME: case VK_END:
        case VK_SHIFT: case VK_CONTROL: case VK_MENU:
            break;
        default: // let Total Commander's lister handle everything else (Esc, N/P, F-keys, 1-7 view modes, ...)
            PostMessageW(GetParent(v->hwnd), m, w, l);
            return 0;
        }
    } else if (m == WM_CHAR) {
        if (w >= 0x20 || w == 1 || w == 0x1b || w == '\t' || w == '\r') return 0; // swallow (no beeps); Ctrl+C (3) goes through
    } else if (m == WM_SYSKEYDOWN || m == WM_SYSKEYUP) {
        PostMessageW(GetParent(v->hwnd), m, w, l);
        return 0;
    }
    return CallWindowProcW(v->old_edit, h, m, w, l);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    View* v = (View*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_CREATE: {
        v = new View(); v->hwnd = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)v);
        HDC dc = GetDC(h); v->dpi = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(h, dc);
        v->mono = CreateFontW(-MulDiv(10, v->dpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        v->title_font = CreateFontW(-MulDiv(14, v->dpi, 72), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
        v->ui_bold = CreateFontW(-MulDiv(9, v->dpi, 72), 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
        v->ui_font = CreateFontW(-MulDiv(9, v->dpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
        v->edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
            0, 0, 10, 10, h, (HMENU)2, g_inst, nullptr);
        SendMessageW(v->edit, WM_SETFONT, (WPARAM)v->mono, TRUE);
        SendMessageW(v->edit, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
        SendMessageW(v->edit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(v->S(6), v->S(6)));
        v->old_edit = (WNDPROC)SetWindowLongPtrW(v->edit, GWLP_WNDPROC, (LONG_PTR)EditProc);
        return 0;
    }
    case WM_SIZE: if (v) layout(v); return 0;
    case WM_SETFOCUS: if (v) SetFocus(v->edit); return 0;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)w; SetTextColor(dc, RGB(0x1f, 0x23, 0x28)); SetBkColor(dc, RGB(255, 255, 255));
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        if (v) {
            RECT rc; GetClientRect(h, &rc);
            RECT hr = { 0, 0, rc.right, v->S(kHeaderH) };
            HBRUSH bg = CreateSolidBrush(RGB(0xf6, 0xf8, 0xfa)); FillRect(dc, &hr, bg); DeleteObject(bg);
            RECT line = { 0, hr.bottom - 1, rc.right, hr.bottom }; HBRUSH lb = CreateSolidBrush(RGB(0xd0, 0xd7, 0xde)); FillRect(dc, &line, lb); DeleteObject(lb);
            int x = v->S(10);
            if (v->icon) {
                HDC mdc = CreateCompatibleDC(dc); HGDIOBJ old = SelectObject(mdc, v->icon);
                BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
                int box = v->S(44), ix = x + (box - v->icon_w) / 2, iy = v->S(16) + (box - v->icon_h) / 2;
                AlphaBlend(dc, ix, iy, v->icon_w, v->icon_h, mdc, 0, 0, v->icon_w, v->icon_h, bf);
                SelectObject(mdc, old); DeleteDC(mdc);
                x += box + v->S(10);
            } else {
                RECT ib = { x, v->S(16), x + v->S(44), v->S(60) };
                HBRUSH g = CreateSolidBrush(RGB(0x3d, 0xdc, 0x84)); FillRect(dc, &ib, g); DeleteObject(g);
                SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255)); HGDIOBJ of = SelectObject(dc, v->title_font);
                DrawTextW(dc, L"APK", 3, &ib, DT_CENTER | DT_VCENTER | DT_SINGLELINE); SelectObject(dc, of);
                x += v->S(54);
            }
            SetBkMode(dc, TRANSPARENT);
            HGDIOBJ of = SelectObject(dc, v->ui_font);
            // version in the top right corner, so the user can see which DLL TC actually loaded
            static const wchar_t* ver = L"APK Lister " TEXT(APKL_VER_STR);
            SIZE vs = {}; GetTextExtentPoint32W(dc, ver, lstrlenW(ver), &vs);
            SetTextColor(dc, RGB(0x8c, 0x95, 0x9f));
            RECT vr = { rc.right - v->S(8) - vs.cx, v->S(6), rc.right - v->S(8), v->S(24) };
            DrawTextW(dc, ver, -1, &vr, DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX);
            SelectObject(dc, v->title_font);
            SetTextColor(dc, RGB(0x1f, 0x23, 0x28));
            RECT tr = { x, v->S(4), rc.right - v->S(16) - vs.cx, v->S(30) };
            DrawTextW(dc, v->title.c_str(), (int)v->title.size(), &tr, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(dc, v->ui_font);
            SetTextColor(dc, RGB(0x57, 0x60, 0x6a));
            RECT sr = { x, v->S(31), rc.right - v->S(8), v->S(50) };
            DrawTextW(dc, v->subtitle.c_str(), (int)v->subtitle.size(), &sr, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(dc, v->ui_bold);
            SetTextColor(dc, RGB(0x0b, 0x6e, 0x4f));
            RECT ar = { x, v->S(51), rc.right - v->S(8), v->S(71) };
            DrawTextW(dc, v->arch.c_str(), (int)v->arch.size(), &ar, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(dc, of);
        }
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY:
        if (v) {
            SetWindowLongPtrW(v->edit, GWLP_WNDPROC, (LONG_PTR)v->old_edit);
            if (v->icon) DeleteObject(v->icon);
            DeleteObject(v->mono); DeleteObject(v->title_font); DeleteObject(v->ui_font); DeleteObject(v->ui_bold);
            SetWindowLongPtrW(h, GWLP_USERDATA, 0);
            delete v;
        }
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

static bool register_class() {
    static bool done = false;
    if (done) return true;
    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_STANDARD_CLASSES }; InitCommonControlsEx(&icc);
    WNDCLASSW wc = {}; wc.lpfnWndProc = WndProc; wc.hInstance = g_inst; wc.lpszClassName = kClass;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.style = CS_HREDRAW | CS_VREDRAW;
    done = RegisterClassW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return done;
}

EXPORT HWND __stdcall ListLoadW(HWND parent, WCHAR* file, int flags) {
    if (!register_class()) return nullptr;
    RECT rc; GetClientRect(parent, &rc);
    HWND h = CreateWindowExW(0, kClass, L"APK Lister", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN, 0, 0, rc.right, rc.bottom, parent, nullptr, g_inst, nullptr);
    if (!h) return nullptr;
    View* v = (View*)GetWindowLongPtrW(h, GWLP_USERDATA);
    HCURSOR oc = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    load_file(v, file);
    SetCursor(oc);
    layout(v);
    SetFocus(v->edit);
    return h;
}

EXPORT HWND __stdcall ListLoad(HWND parent, char* file, int flags) {
    int n = MultiByteToWideChar(CP_ACP, 0, file, -1, nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_ACP, 0, file, -1, &w[0], n);
    return ListLoadW(parent, &w[0], flags);
}

EXPORT int __stdcall ListLoadNextW(HWND parent, HWND win, WCHAR* file, int flags) {
    View* v = (View*)GetWindowLongPtrW(win, GWLP_USERDATA);
    if (!v) return LISTPLUGIN_ERROR;
    HCURSOR oc = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    load_file(v, file);
    SetCursor(oc);
    return LISTPLUGIN_OK;
}
EXPORT int __stdcall ListLoadNext(HWND parent, HWND win, char* file, int flags) {
    int n = MultiByteToWideChar(CP_ACP, 0, file, -1, nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_ACP, 0, file, -1, &w[0], n);
    return ListLoadNextW(parent, win, &w[0], flags);
}

EXPORT void __stdcall ListCloseWindow(HWND win) { DestroyWindow(win); }

EXPORT void __stdcall ListGetDetectString(char* s, int maxlen) {
    lstrcpynA(s, "EXT=\"APK\" | EXT=\"XAPK\" | EXT=\"APKS\" | EXT=\"APKM\" | EXT=\"AAB\" | EXT=\"APEX\"", maxlen);
}

EXPORT void __stdcall ListSetDefaultParams(ListDefaultParamStruct* dps) {
    if (dps && dps->DefaultIniName[0]) MultiByteToWideChar(CP_ACP, 0, dps->DefaultIniName, -1, g_default_ini, MAX_PATH);
}

EXPORT int __stdcall ListSendCommand(HWND win, int cmd, int param) {
    View* v = (View*)GetWindowLongPtrW(win, GWLP_USERDATA);
    if (!v) return LISTPLUGIN_ERROR;
    switch (cmd) {
    case lc_copy: SendMessageW(v->edit, WM_COPY, 0, 0); return LISTPLUGIN_OK;
    case lc_selectall: SendMessageW(v->edit, EM_SETSEL, 0, -1); return LISTPLUGIN_OK;
    case lc_newparams: return LISTPLUGIN_OK;
    }
    return LISTPLUGIN_ERROR;
}

static bool is_word(wchar_t c) { return IsCharAlphaNumericW(c) || c == L'_'; }

EXPORT int __stdcall ListSearchTextW(HWND win, WCHAR* what, int params) {
    View* v = (View*)GetWindowLongPtrW(win, GWLP_USERDATA);
    if (!v || !what || !*what) return LISTPLUGIN_ERROR;
    bool mc = params & lcs_matchcase, ww = params & lcs_wholewords, back = params & lcs_backwards;
    const std::wstring& txt = v->text;
    std::wstring needle = what;
    const std::wstring* hay = &txt;
    if (!mc) {
        std::wstring& lt = v->lower_text;
        if (lt.size() != txt.size()) { lt = txt; if (!lt.empty()) CharLowerBuffW(&lt[0], (DWORD)lt.size()); }
        CharLowerBuffW(&needle[0], (DWORD)needle.size());
        hay = &lt;
    }
    DWORD s0 = 0, s1 = 0; SendMessageW(v->edit, EM_GETSEL, (WPARAM)&s0, (LPARAM)&s1);
    size_t n = needle.size(), pos;
    if (params & lcs_findfirst) pos = back ? hay->size() : 0;
    else pos = back ? s0 : s1;
    for (;;) {
        size_t f;
        if (back) { if (pos == 0) return LISTPLUGIN_ERROR; f = hay->rfind(needle, pos - 1); }
        else f = hay->find(needle, pos);
        if (f == std::wstring::npos) return LISTPLUGIN_ERROR;
        bool ok = true;
        if (ww) {
            if (f > 0 && is_word((*hay)[f - 1])) ok = false;
            if (f + n < hay->size() && is_word((*hay)[f + n])) ok = false;
        }
        if (ok) {
            SendMessageW(v->edit, EM_SETSEL, f, f + n);
            SendMessageW(v->edit, EM_SCROLLCARET, 0, 0);
            return LISTPLUGIN_OK;
        }
        pos = back ? f : f + 1;
    }
}

EXPORT int __stdcall ListSearchText(HWND win, char* what, int params) {
    int n = MultiByteToWideChar(CP_ACP, 0, what, -1, nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_ACP, 0, what, -1, &w[0], n);
    return ListSearchTextW(win, &w[0], params);
}

EXPORT HBITMAP __stdcall ListGetPreviewBitmapW(WCHAR* file, int width, int height, char* contentbuf, int contentbuflen) {
    MappedFile mf; std::string err;
    if (!mf.open(narrow(file), err)) return nullptr;
    AnalyzeOptions opt; opt.icon_only = true;
    Report r;
    analyze(narrow(file), Bytes(mf.p, (size_t)mf.size), opt, r);
    if (r.icon.empty()) return nullptr;
    return decode_image(r.icon, width, height, true, nullptr, nullptr);
}
EXPORT HBITMAP __stdcall ListGetPreviewBitmap(char* file, int width, int height, char* contentbuf, int contentbuflen) {
    int n = MultiByteToWideChar(CP_ACP, 0, file, -1, nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_ACP, 0, file, -1, &w[0], n);
    return ListGetPreviewBitmapW(&w[0], width, height, contentbuf, contentbuflen);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { g_inst = h; DisableThreadLibraryCalls(h); }
    else if (reason == DLL_PROCESS_DETACH) UnregisterClassW(kClass, g_inst);
    return TRUE;
}
