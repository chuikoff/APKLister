// SPDX-License-Identifier: GPL-2.0-or-later
// APK Lister: Total Commander Lister (WLX) plugin front-end.
// 0.2.0: owner-drawn "Bold" view (hero band in the icon's colour, summary tiles, two-column sections).
#include <windows.h>
#include <commctrl.h>
#include <wincodec.h>
#include <gdiplus.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>
#include "analyzer.h"
#include "plat.h"
#include "tables.h"
#include "util.h"
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
#define lcp_darkmode 128
#define lcp_darkmodenative 256
#define LISTPLUGIN_OK 0
#define LISTPLUGIN_ERROR 1
struct ListDefaultParamStruct { int size; DWORD PluginInterfaceVersionLow; DWORD PluginInterfaceVersionHi; char DefaultIniName[MAX_PATH]; };
#ifndef WM_DPICHANGED_AFTERPARENT
#define WM_DPICHANGED_AFTERPARENT 0x02E3
#endif

static HINSTANCE g_inst;
static wchar_t g_default_ini[MAX_PATH]; // TC's lsplugin.ini (from ListSetDefaultParams)
static int g_iface = 0;                 // TC plugin interface version * 100 (2.12 -> 212), 0 = unknown
static const wchar_t* kClass = L"APKListerWindow";
static ULONG_PTR g_gdip = 0;
static int g_windows = 0;

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

static std::wstring own_ini() {
    wchar_t dll[MAX_PATH] = L""; GetModuleFileNameW(g_inst, dll, MAX_PATH);
    std::wstring own = dll; size_t k = own.find_last_of(L"\\/");
    return (k == std::wstring::npos ? std::wstring() : own.substr(0, k + 1)) + L"apklister.ini";
}

// ---- theme: [APKLister] Theme=auto|light|dark, then TC's dark-mode flags, then the Windows app theme
static bool resolve_dark(int flags) {
    std::wstring t = read_ini(own_ini().c_str(), L"APKLister", L"Theme");
    if (t == L"\x01" || t.empty() || !lstrcmpiW(t.c_str(), L"auto")) t = read_ini(g_default_ini, L"APKLister", L"Theme");
    if (!lstrcmpiW(t.c_str(), L"dark")) return true;
    if (!lstrcmpiW(t.c_str(), L"light")) return false;
    if (flags & (lcp_darkmode | lcp_darkmodenative)) return true;
    if (g_iface >= 212) return false; // TC 10+ tells us explicitly
    DWORD v = 1, sz = sizeof v;
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme",
                     RRF_RT_REG_DWORD, nullptr, &v, &sz) == ERROR_SUCCESS) return v == 0;
    return false;
}

// ---- icon decoding through WIC (PNG always; WebP/JPEG when the codec exists) into premultiplied BGRA
static bool decode_pixels(const std::vector<uint8_t>& data, int maxw, int maxh, std::vector<uint32_t>& px, int& ow, int& oh) {
    if (data.empty() || maxw <= 0 || maxh <= 0) return false;
    HRESULT ci = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool ok = false;
    IWICImagingFactory* f = nullptr; IWICStream* s = nullptr; IWICBitmapDecoder* d = nullptr;
    IWICBitmapFrameDecode* fr = nullptr; IWICBitmapScaler* sc = nullptr; IWICFormatConverter* cv = nullptr;
    UINT w = 0, h = 0;
    do {
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory, (void**)&f))) break;
        if (FAILED(f->CreateStream(&s))) break;
        if (FAILED(s->InitializeFromMemory((BYTE*)data.data(), (DWORD)data.size()))) break;
        if (FAILED(f->CreateDecoderFromStream(s, nullptr, WICDecodeMetadataCacheOnDemand, &d))) break;
        if (FAILED(d->GetFrame(0, &fr))) break;
        if (FAILED(fr->GetSize(&w, &h)) || !w || !h || w > 16384 || h > 16384) break;
        double k = (double)maxw / w; if ((double)maxh / h < k) k = (double)maxh / h;
        UINT tw = (UINT)(w * k + 0.5), th = (UINT)(h * k + 0.5); if (!tw) tw = 1; if (!th) th = 1;
        if (FAILED(f->CreateBitmapScaler(&sc))) break;
        if (FAILED(sc->Initialize(fr, tw, th, WICBitmapInterpolationModeFant))) break;
        if (FAILED(f->CreateFormatConverter(&cv))) break;
        if (FAILED(cv->Initialize(sc, GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0, WICBitmapPaletteTypeCustom))) break;
        px.assign((size_t)tw * th, 0);
        if (FAILED(cv->CopyPixels(nullptr, tw * 4, tw * 4 * th, (BYTE*)px.data()))) break;
        ow = (int)tw; oh = (int)th; ok = true;
    } while (0);
    if (cv) cv->Release(); if (sc) sc->Release(); if (fr) fr->Release(); if (d) d->Release(); if (s) s->Release(); if (f) f->Release();
    if (ci == S_OK || ci == S_FALSE) CoUninitialize();
    return ok;
}
static HBITMAP make_dib(const std::vector<uint32_t>& px, int w, int h, bool on_white) {
    BITMAPINFO bi = {}; bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bmp) return nullptr;
    memcpy(bits, px.data(), (size_t)w * h * 4);
    if (on_white) { // premultiplied -> composite on white, opaque
        uint8_t* p = (uint8_t*)bits;
        for (int i = 0; i < w * h; i++, p += 4) { int a = p[3]; p[0] = (uint8_t)(p[0] + 255 - a); p[1] = (uint8_t)(p[1] + 255 - a); p[2] = (uint8_t)(p[2] + 255 - a); p[3] = 255; }
    }
    return bmp;
}
static HBITMAP decode_image(const std::vector<uint8_t>& data, int maxw, int maxh, bool on_white, int* outw, int* outh) {
    std::vector<uint32_t> px; int w = 0, h = 0;
    if (!decode_pixels(data, maxw, maxh, px, w, h)) return nullptr;
    if (outw) *outw = w;
    if (outh) *outh = h;
    return make_dib(px, w, h, on_white);
}

// ---- colours
static inline int cr(COLORREF c) { return GetRValue(c); }
static inline int cg(COLORREF c) { return GetGValue(c); }
static inline int cb(COLORREF c) { return GetBValue(c); }
static COLORREF hex(unsigned v) { return RGB((v >> 16) & 255, (v >> 8) & 255, v & 255); }
static COLORREF mix(COLORREF a, COLORREF b, double t) { // t = share of b
    return RGB((int)(cr(a) + (cr(b) - cr(a)) * t + 0.5), (int)(cg(a) + (cg(b) - cg(a)) * t + 0.5), (int)(cb(a) + (cb(b) - cb(a)) * t + 0.5));
}
static double lin(int v) { double c = v / 255.0; return c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4); }
static double lum(COLORREF c) { return 0.2126 * lin(cr(c)) + 0.7152 * lin(cg(c)) + 0.0722 * lin(cb(c)); }
static double contrast(COLORREF a, COLORREF b) { double x = lum(a), y = lum(b); if (x < y) std::swap(x, y); return (x + 0.05) / (y + 0.05); }
// move c towards `to` until it reaches `need` contrast against `bg`
static COLORREF ensure(COLORREF c, COLORREF bg, double need, COLORREF to) {
    for (int i = 0; i < 40 && contrast(c, bg) < need; i++) c = mix(c, to, 0.08);
    return c;
}
static void rgb2hsv(COLORREF c, double& h, double& s, double& v) {
    double r = cr(c) / 255.0, g = cg(c) / 255.0, b = cb(c) / 255.0;
    double mx = std::max(r, std::max(g, b)), mn = std::min(r, std::min(g, b)), d = mx - mn;
    v = mx; s = mx > 0 ? d / mx : 0; h = 0;
    if (d > 0) {
        if (mx == r) h = 60 * fmod((g - b) / d + 6, 6.0);
        else if (mx == g) h = 60 * ((b - r) / d + 2);
        else h = 60 * ((r - g) / d + 4);
    }
}
// dominant (and a secondary, different-hue) colour of an icon; false when the icon is grey/empty
static bool icon_colors(const std::vector<uint32_t>& px, COLORREF& primary, COLORREF& secondary, bool& have2) {
    struct Bin { double r = 0, g = 0, b = 0, n = 0; };
    std::vector<Bin> bins(4096);
    double total = 0;
    for (uint32_t p : px) {
        int a = p >> 24; if (a < 200) continue;
        int r = ((p >> 16) & 255) * 255 / a, g = ((p >> 8) & 255) * 255 / a, b = (p & 255) * 255 / a;
        if (r > 255) r = 255; if (g > 255) g = 255; if (b > 255) b = 255;
        total++;
        double h, s, v; rgb2hsv(RGB(r, g, b), h, s, v);
        if (s < 0.25 || v < 0.2) continue;
        Bin& x = bins[(r >> 4) << 8 | (g >> 4) << 4 | (b >> 4)];
        double wgt = 0.5 + s; // prefer saturated colours
        x.r += r * wgt; x.g += g * wgt; x.b += b * wgt; x.n += wgt;
    }
    // merge neighbours: score of a bin = own weight + weight of the 6 face neighbours / 2
    int best = -1; double bs = 0;
    auto score = [&](int i) { double s = bins[i].n; int r = i >> 8, g = (i >> 4) & 15, b = i & 15;
        const int d[6][3] = { {1,0,0},{-1,0,0},{0,1,0},{0,-1,0},{0,0,1},{0,0,-1} };
        for (auto& q : d) { int R = r + q[0], G = g + q[1], B = b + q[2]; if (R < 0 || G < 0 || B < 0 || R > 15 || G > 15 || B > 15) continue; s += bins[R << 8 | G << 4 | B].n * 0.5; }
        return s; };
    for (int i = 0; i < 4096; i++) if (bins[i].n > 0) { double s = score(i); if (s > bs) { bs = s; best = i; } }
    if (best < 0 || total <= 0 || bins[best].n < total * 0.04) return false;
    primary = RGB((int)(bins[best].r / bins[best].n), (int)(bins[best].g / bins[best].n), (int)(bins[best].b / bins[best].n));
    double h1, s1, v1; rgb2hsv(primary, h1, s1, v1);
    have2 = false; double b2 = 0; int sec = -1;
    for (int i = 0; i < 4096; i++) {
        if (bins[i].n < total * 0.015) continue;
        COLORREF c = RGB((int)(bins[i].r / bins[i].n), (int)(bins[i].g / bins[i].n), (int)(bins[i].b / bins[i].n));
        double h, s, v; rgb2hsv(c, h, s, v);
        double dh = fabs(h - h1); if (dh > 180) dh = 360 - dh;
        if (dh < 40) continue;
        double sc = score(i); if (sc > b2) { b2 = sc; sec = i; secondary = c; }
    }
    have2 = sec >= 0;
    return true;
}
static COLORREF hash_color(const std::string& s) {
    static const unsigned pal[] = { 0x1975D0, 0x2E7D32, 0x6A1B9A, 0xC62828, 0x00838F, 0xEF6C00, 0x37474F };
    uint32_t h = 2166136261u; for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return hex(pal[h % 7]);
}

enum TagKind { TgNone, TgDanger, TgSpecial, TgNormal, TgSignature, TgOk, TgBad, TgInfo, TgMuted, TgCount };
struct Pal {
    bool dark = false;
    COLORREF bg, text, muted, key, sec, sel, find, find_text, footer;
    COLORREF band, band_text, band_sub, band_ver, pill_bg, pill_text, icon_box;
    COLORREF tile_bg, tile_bd, tile_lbl, tile_num, tile_hint;
    COLORREF warn_bg, warn_bd, warn_lbl, warn_num, ok_bg, ok_bd, ok_lbl, ok_num;
    COLORREF tag_bg[TgCount], tag_fg[TgCount];
};
static void make_palette(Pal& p, bool dark, COLORREF band, bool icon_ok, COLORREF sec2, bool have2, int arch_state) {
    p.dark = dark;
    if (!dark) {
        p.bg = hex(0xffffff); p.text = hex(0x1f2328); p.muted = hex(0x6e7781); p.key = hex(0x6e7781); p.footer = hex(0x8c959f);
        p.tile_hint = hex(0x6e7781);
        p.warn_bg = hex(0xfff3f1); p.warn_bd = hex(0xffd9d4); p.warn_lbl = hex(0xa3554d); p.warn_num = hex(0xc4231c);
        p.ok_bg = hex(0xf1faea); p.ok_bd = hex(0xd8eec6); p.ok_lbl = hex(0x5b7a43); p.ok_num = hex(0x2f6b00);
        const unsigned bgs[TgCount] = { 0, 0xffe8e6, 0xfff0e0, 0, 0xf1e8fd, 0xe8f5dc, 0xffe8e6, 0xe3eefb, 0 };
        const unsigned fgs[TgCount] = { 0x6e7781, 0xc4231c, 0x9a4300, 0x6e7781, 0x6a2fb5, 0x2f6b00, 0xc4231c, 0x0b4f9c, 0x8c959f };
        for (int i = 0; i < TgCount; i++) { p.tag_bg[i] = hex(bgs[i]); p.tag_fg[i] = hex(fgs[i]); }
        p.find = hex(0xffd33d); p.find_text = hex(0x1f2328);
    } else {
        p.bg = hex(0x16191d); p.text = hex(0xe6e8eb); p.muted = hex(0x8b949e); p.key = hex(0x8b949e); p.footer = hex(0x7d8792);
        p.tile_hint = hex(0x8b949e);
        p.warn_bg = hex(0x3a1a18); p.warn_bd = hex(0x5c2a26); p.warn_lbl = hex(0xd49a94); p.warn_num = hex(0xff8e86);
        p.ok_bg = hex(0x15291a); p.ok_bd = hex(0x24452c); p.ok_lbl = hex(0x8fb79a); p.ok_num = hex(0x7ee2a0);
        const unsigned bgs[TgCount] = { 0, 0x4a1714, 0x3d2410, 0, 0x2e1d4a, 0x13361f, 0x4a1714, 0x0f2f52, 0 };
        const unsigned fgs[TgCount] = { 0x8b949e, 0xff8e86, 0xffb27a, 0x8b949e, 0xc9a6ff, 0x7ee2a0, 0xff8e86, 0x8cc4ff, 0x7d8792 };
        for (int i = 0; i < TgCount; i++) { p.tag_bg[i] = hex(bgs[i]); p.tag_fg[i] = hex(fgs[i]); }
        p.find = hex(0xb08800); p.find_text = hex(0xffffff);
    }
    // hero band
    if (dark) band = mix(band, hex(0x000000), 0.18);
    COLORREF white = hex(0xffffff), ink = hex(0x111111);
    if (contrast(white, band) >= 4.5) p.band_text = white;
    else if (contrast(ink, band) >= 4.5) p.band_text = ink;
    else { p.band_text = white; band = ensure(band, white, 4.5, hex(0x000000)); }
    p.band = band;
    p.band_sub = mix(p.band_text, band, 0.15);
    p.band_ver = mix(p.band_text, band, 0.25);
    p.icon_box = white;
    if (arch_state == 1 || arch_state == 3) {
        COLORREF pc = have2 ? sec2 : hex(0x3ddc84);
        // keep the pill visible on the band
        if (contrast(pc, band) < 1.6) pc = p.band_text == white ? mix(pc, white, 0.55) : mix(pc, hex(0x000000), 0.4);
        p.pill_bg = pc;
        COLORREF dk = mix(pc, hex(0x000000), 0.8);
        p.pill_text = contrast(dk, pc) >= 4.5 ? dk : ensure(mix(pc, white, 0.9), pc, 4.5, white);
    } else if (arch_state == 2) {
        p.pill_bg = hex(0xffd54f); p.pill_text = hex(0x3d2b00);
    } else {
        p.pill_bg = mix(band, p.band_text, 0.22); p.pill_text = p.band_text;
    }
    // tiles and section titles follow the band colour
    COLORREF base = icon_ok ? band : band;
    if (!dark) {
        p.tile_bg = mix(base, white, 0.945); p.tile_bd = mix(base, white, 0.85);
        p.tile_num = ensure(mix(base, hex(0x000000), 0.3), p.tile_bg, 7.0, hex(0x000000));
        p.tile_lbl = ensure(mix(p.tile_num, hex(0x6e7781), 0.6), p.tile_bg, 4.5, hex(0x000000));
        p.sec = ensure(base, p.bg, 4.5, hex(0x000000));
        p.sel = mix(p.sec, white, 0.86);
    } else {
        p.tile_bg = mix(hex(0x1f2328), base, 0.06); p.tile_bd = mix(hex(0x30363d), base, 0.12);
        p.tile_num = ensure(mix(base, white, 0.25), p.tile_bg, 6.0, white);
        p.tile_lbl = ensure(mix(p.tile_num, hex(0x8b949e), 0.6), p.tile_bg, 4.5, white);
        p.sec = ensure(mix(base, white, 0.15), p.bg, 4.5, white);
        p.sel = mix(p.sec, p.bg, 0.78);
    }
}
// ---- the drawn view
enum Font { F_NAME, F_SUB, F_PILL, F_VER, F_TL, F_TN, F_TH, F_SEC, F_ROW, F_ROWB, F_MONO, F_TAG, F_NOTE, F_TN2, F_COUNT };
struct FontSpec { int px10; int weight; bool mono; };
static const FontSpec kFonts[F_COUNT] = {
    { 320, FW_BOLD, false }, { 135, FW_NORMAL, false }, { 120, FW_BOLD, false }, { 110, FW_NORMAL, false },
    { 105, FW_BOLD, false }, { 210, FW_BOLD, false }, { 110, FW_NORMAL, false }, { 120, FW_BOLD, false },
    { 125, FW_NORMAL, false }, { 125, FW_SEMIBOLD, false }, { 120, FW_NORMAL, true }, { 105, FW_BOLD, false }, { 115, FW_NORMAL, false },
    { 170, FW_BOLD, false },
};

struct El {
    enum Type { Fill, Text, Icon } type = Text;
    RECT r = {};
    COLORREF color = 0, border = CLR_INVALID;
    int radius = 0;
    std::wstring s;
    int font = F_ROW, extra = 0;
    UINT fmt = 0;
    int row = -1;       // row this element belongs to (selection / search)
    bool search = false;
};
struct Row {
    RECT r = {};
    int item = -1;      // index into rep.items, -1 for the footer
    std::string plain, value;
};
struct Block { std::vector<El> els; std::vector<Row> rows; int h = 0; };

struct View {
    HWND hwnd = nullptr;
    Report rep;
    std::vector<uint8_t> icon_data;
    HBITMAP icon = nullptr; int icon_w = 0, icon_h = 0, icon_for = 0;
    COLORREF icon_c1 = 0, icon_c2 = 0; bool icon_ok = false, icon_2 = false;
    HFONT fonts[F_COUNT] = {};
    int dpi = 96, flags = 0;
    bool dark = false;
    Pal pal;
    std::vector<El> els;
    std::vector<Row> rows;
    int doc_h = 0, sy = 0, lay_w = -1;
    int sel_a = -1, sel_b = -1; bool sel_all = false, dragging = false;
    int m_el = -1, m_off = 0, m_len = 0;
    HDC mdc = nullptr; HBITMAP mbmp = nullptr; int mw = 0, mh = 0;
    int S(int v) const { return MulDiv(v, dpi, 96); }
    int S10(int v10) const { return MulDiv(v10, dpi, 960); }
};

static int window_dpi(HWND h) {
    typedef UINT(WINAPI * PGetDpiForWindow)(HWND);
    static PGetDpiForWindow f = (PGetDpiForWindow)(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow");
    UINT d = f ? f(h) : 0;
    if (!d) { HDC dc = GetDC(h); d = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(h, dc); }
    return d ? (int)d : 96;
}
static void make_fonts(View* v) {
    for (auto& f : v->fonts) if (f) { DeleteObject(f); f = nullptr; }
    for (int i = 0; i < F_COUNT; i++)
        v->fonts[i] = CreateFontW(-v->S10(kFonts[i].px10), 0, 0, 0, kFonts[i].weight, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, kFonts[i].mono ? FIXED_PITCH | FF_MODERN : VARIABLE_PITCH | FF_SWISS, kFonts[i].mono ? L"Consolas" : L"Segoe UI");
}
static void set_theme(View* v) {
    typedef HRESULT(WINAPI * PSetWindowTheme)(HWND, LPCWSTR, LPCWSTR);
    static HMODULE ux = LoadLibraryW(L"uxtheme.dll");
    static PSetWindowTheme f = ux ? (PSetWindowTheme)(void*)GetProcAddress(ux, "SetWindowTheme") : nullptr;
    v->dark = resolve_dark(v->flags);
    COLORREF band = v->icon_ok ? v->icon_c1 : hash_color(v->rep.facts.package.empty() ? v->rep.title : v->rep.facts.package);
    make_palette(v->pal, v->dark, band, v->icon_ok, v->icon_c2, v->icon_2, v->rep.facts.have ? v->rep.facts.arch_state : -1);
    if (f) f(v->hwnd, v->dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
}
static void make_icon(View* v) {
    int sz = v->S(72);
    if (v->icon && v->icon_for == sz) return;
    if (v->icon) { DeleteObject(v->icon); v->icon = nullptr; }
    v->icon = decode_image(v->icon_data, sz, sz, false, &v->icon_w, &v->icon_h);
    v->icon_for = sz;
}

// text measuring on a shared memory DC
static HDC measure_dc() { static HDC dc = CreateCompatibleDC(nullptr); return dc; }
struct ISize { int cx, cy; };
static ISize text_size(View* v, int font, const std::wstring& s, int width, UINT fmt, int extra = 0) {
    HDC dc = measure_dc();
    HGDIOBJ of = SelectObject(dc, v->fonts[font]);
    SetTextCharacterExtra(dc, extra);
    RECT r = { 0, 0, width > 0 ? width : 100000, 0 };
    std::wstring t = s.empty() ? std::wstring(L" ") : s;
    DrawTextW(dc, t.c_str(), (int)t.size(), &r, fmt | DT_CALCRECT | DT_NOPREFIX);
    SetTextCharacterExtra(dc, 0);
    SelectObject(dc, of);
    ISize z = { (int)(r.right - r.left), (int)(r.bottom - r.top) };
    return z;
}
static int text_w(View* v, int font, const std::wstring& s, int extra = 0) { return text_size(v, font, s, 0, DT_SINGLELINE, extra).cx; }
static int line_h(View* v, int font) { return text_size(v, font, L"Ag", 0, DT_SINGLELINE).cy; }
static const UINT kWrap = DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX;
static const UINT kOne = DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;

static El text_el(int font, const std::wstring& s, RECT r, COLORREF c, UINT fmt, int row = -1, bool search = false, int extra = 0) {
    El e; e.type = El::Text; e.font = font; e.s = s; e.r = r; e.color = c; e.fmt = fmt; e.row = row; e.search = search; e.extra = extra; return e;
}
static El fill_el(RECT r, COLORREF c, int radius = 0, COLORREF border = CLR_INVALID) {
    El e; e.type = El::Fill; e.r = r; e.color = c; e.radius = radius; e.border = border; return e;
}
static std::wstring upper(std::wstring s) { if (!s.empty()) CharUpperBuffW(&s[0], (DWORD)s.size()); return s; }
static std::string short_count(uint64_t n) {
    if (n < 10000) return with_commas(n);
    if (n < 1000000) return strf("%.1f K", n / 1000.0);
    return strf("%.2f M", n / 1000000.0);
}
static std::string short_sz(uint64_t n) {
    bool ru = get_lang() == Lang::Ru;
    if (n < 1024) return strf("%llu %s", (unsigned long long)n, ru ? "Б" : "B");
    if (n < 1024 * 1024) return strf("%.1f %s", n / 1024.0, ru ? "КиБ" : "KiB");
    if (n < 1024ull * 1024 * 1024) return strf("%.1f %s", n / 1048576.0, ru ? "МиБ" : "MiB");
    return strf("%.2f %s", n / 1073741824.0, ru ? "ГиБ" : "GiB");
}
static std::string android_short(int api) {
    const char* n = android_version_name(api);
    if (!n || !*n) return strf("API %d", api);
    std::string s = n; size_t k = s.find(' '); return k == std::string::npos ? s : s.substr(0, k);
}

static int tag_kind(const ReportItem& it) { return it.tag_kind >= 0 && it.tag_kind < TgCount ? it.tag_kind : TgNone; }
static bool tag_is_pill(int k) { return k == TgDanger || k == TgSpecial || k == TgSignature || k == TgOk || k == TgBad || k == TgInfo; }

// "name      value" (padded columns in the text report): split at the first run of 3+ spaces when the rest has none
static bool split_columns(const std::string& t, std::string& left, std::string& right) {
    size_t k = t.find("   ");
    if (k == std::string::npos || k == 0) return false;
    size_t r = t.find_first_not_of(' ', k);
    if (r == std::string::npos || t.find("   ", r) != std::string::npos) return false;
    left = t.substr(0, k); right = t.substr(r);
    return true;
}
static std::string collapse_spaces(const std::string& t) {
    std::string o; o.reserve(t.size());
    for (size_t i = 0; i < t.size(); i++) { if (t[i] == ' ' && i + 2 < t.size() && t[i + 1] == ' ' && t[i + 2] == ' ') continue; o += t[i]; }
    return o;
}
static int count_runs(const std::string& t) { int n = 0; for (size_t i = 0; i + 1 < t.size(); i++) if (t[i] == ' ' && t[i + 1] == ' ' && (i == 0 || t[i - 1] != ' ')) n++; return n; }
// a section holding aligned tables that do not fit a column is laid out across the full width
static bool section_wide(View* v, size_t a, size_t b, int cw) {
    const auto& items = v->rep.items;
    for (size_t i = a + 1; i < b; i++) {
        const ReportItem& it = items[i];
        if (it.kind != ReportItem::Line || !it.mono || !it.tag.empty()) continue;
        std::string l, r;
        if (split_columns(it.value, l, r)) continue;
        if (count_runs(it.value) >= 2 && text_w(v, F_MONO, widen(it.value)) + std::max(0, it.ind - 2) * v->S(7) > cw) return true;
    }
    return false;
}

// one section (items [a, b)) laid out at width w, coordinates relative to the block
static Block build_section(View* v, size_t a, size_t b, int w) {
    Block bk; const Pal& p = v->pal; const auto& items = v->rep.items;
    int y = v->S(8);
    auto add_row = [&](int item, RECT r, const std::string& plain, const std::string& value) {
        Row rw; rw.item = item; rw.r = r; rw.plain = plain; rw.value = value; bk.rows.push_back(rw); return (int)bk.rows.size() - 1; };
    // header: "TITLE (note)" -> title left, note right
    {
        const ReportItem& h = items[a];
        std::string t = h.key, note;
        size_t k = t.rfind(" (");
        if (k != std::string::npos && !t.empty() && t.back() == ')') { note = t.substr(k + 2, t.size() - k - 3); t = t.substr(0, k); }
        std::wstring wt = upper(widen(t)), wn = widen(note);
        int ex = std::max(1, v->S10(7));
        int nw = note.empty() ? 0 : text_w(v, F_NOTE, wn) + v->S(2);
        int tw = std::max(v->S(40), w - nw - (nw ? v->S(10) : 0));
        ISize ts = text_size(v, F_SEC, wt, tw, kWrap, ex);
        int row = add_row((int)a, RECT{ 0, 0, w, 0 }, h.plain, h.key);
        bk.els.push_back(text_el(F_SEC, wt, RECT{ 0, y, tw, y + ts.cy }, p.sec, kWrap, row, true, ex));
        if (nw) {
            int lh = line_h(v, F_SEC), nh = line_h(v, F_NOTE);
            bk.els.push_back(text_el(F_NOTE, wn, RECT{ w - nw, y + lh - nh, w, y + lh }, p.footer, DT_SINGLELINE | DT_NOPREFIX | DT_RIGHT, row, true));
        }
        y += ts.cy + v->S(3);
        bk.els.push_back(fill_el(RECT{ 0, y, w, y + v->S(2) }, p.sec));
        y += v->S(2) + v->S(5);
        bk.rows[row].r.bottom = y;
    }
    // label column width for this section
    int lw = 0;
    for (size_t i = a + 1; i < b; i++) if (items[i].kind == ReportItem::KV) lw = std::max(lw, text_w(v, F_ROW, widen(items[i].key)) + (items[i].ind > 2 ? v->S(14) : 0));
    lw = std::min(std::max(lw + v->S(14), v->S(110)), std::max(v->S(110), w * 40 / 100));
    int pad = v->S(2);
    for (size_t i = a + 1; i < b; i++) {
        const ReportItem& it = items[i];
        if (it.kind == ReportItem::Blank) { if (i + 1 < b && i > a + 1) y += v->S(6); continue; }
        int dx = std::max(0, it.ind - 2) * v->S(7);
        int top = y;
        int row = add_row((int)i, RECT{}, it.plain, it.kind == ReportItem::KV ? it.value : it.value);
        if (it.kind == ReportItem::KV) {
            int kx = dx, kw = std::max(v->S(50), lw - dx - v->S(10));
            std::wstring wk = widen(it.key), wv = widen(it.value), wn = widen(it.note);
            ISize ks = text_size(v, F_ROW, wk, kw, kWrap);
            int vf = it.mono ? F_MONO : F_ROW;
            int vx = std::max(lw, kx + kw + v->S(10)), vw = std::max(v->S(40), w - vx);
            ISize vs = text_size(v, vf, wv, vw, kWrap);
            int vy = y + pad + (it.mono ? (line_h(v, F_ROW) - line_h(v, F_MONO) + 1) / 2 : 0);
            bk.els.push_back(text_el(F_ROW, wk, RECT{ kx, y + pad, kx + kw, y + pad + ks.cy }, p.key, kWrap, row, true));
            bk.els.push_back(text_el(vf, wv, RECT{ vx, vy, vx + vw, vy + vs.cy }, p.text, kWrap, row, true));
            int bottom = std::max(y + pad + ks.cy, vy + vs.cy);
            if (!wn.empty()) {
                int one = text_w(v, vf, wv), nw = text_w(v, F_NOTE, wn);
                int lh = line_h(v, F_ROW), nh = line_h(v, F_NOTE);
                if (vs.cy <= line_h(v, vf) && one + v->S(10) + nw <= vw)
                    bk.els.push_back(text_el(F_NOTE, wn, RECT{ vx + one + v->S(10), y + pad + lh - nh, vx + vw, y + pad + lh }, p.footer, DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS, row, true));
                else {
                    ISize ns = text_size(v, F_NOTE, wn, vw, kWrap);
                    bk.els.push_back(text_el(F_NOTE, wn, RECT{ vx, bottom, vx + vw, bottom + ns.cy }, p.footer, kWrap, row, true));
                    bottom += ns.cy;
                }
            }
            y = bottom + pad;
        } else {
            if (it.strong) y += v->S(3);
            int f = it.strong ? F_ROWB : it.mono ? F_MONO : F_ROW;
            int k = tag_kind(it);
            std::string shown = it.value, right;
            if (k != TgNone && shown.compare(0, 19, "android.permission.") == 0) shown = shown.substr(19); // full name stays in copy
            bool rmono = false;
            if (it.mono && it.tag.empty()) {
                std::string l, r;
                if (split_columns(shown, l, r) && text_w(v, F_MONO, widen(r)) <= (w - dx) * 45 / 100) { shown = l; right = r; rmono = true; }
                else if (text_w(v, F_MONO, widen(shown)) > w - dx) shown = collapse_spaces(shown);
            }
            std::wstring wt = widen(shown), wg = widen(rmono ? right : it.tag);
            if (tag_is_pill(k) && !wg.empty()) CharLowerBuffW(&wg[0], (DWORD)wg.size());
            int tw = 0, tf = rmono ? F_MONO : tag_is_pill(k) ? F_TAG : F_NOTE;
            if (!wg.empty()) tw = text_w(v, tf, wg) + (tag_is_pill(k) ? v->S(12) : 0);
            if (tw > w / 2) tw = w / 2;
            int xw = std::max(v->S(40), w - dx - (tw ? tw + v->S(10) : 0));
            ISize ts = text_size(v, f, wt, xw, kWrap);
            int lh = line_h(v, F_ROW);
            int ty = y + pad + (f == F_MONO ? (lh - line_h(v, F_MONO) + 1) / 2 : 0);
            bk.els.push_back(text_el(f, wt, RECT{ dx, ty, dx + xw, ty + ts.cy }, it.strong ? p.text : p.text, kWrap, row, true));
            int bottom = std::max(y + pad + lh, ty + ts.cy);
            if (tw) {
                if (tag_is_pill(k)) {
                    int ph = v->S(17), py = y + pad + (lh - ph) / 2;
                    bk.els.push_back(fill_el(RECT{ w - tw, py, w, py + ph }, p.tag_bg[k], v->S(4)));
                    bk.els.push_back(text_el(F_TAG, wg, RECT{ w - tw, py, w, py + ph }, p.tag_fg[k], DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS, row, true));
                } else if (rmono) {
                    bk.els.push_back(text_el(F_MONO, wg, RECT{ w - tw, ty, w, ty + line_h(v, F_MONO) }, p.muted, DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX | DT_END_ELLIPSIS, row, true));
                } else {
                    int nh = line_h(v, F_NOTE);
                    bk.els.push_back(text_el(F_NOTE, wg, RECT{ w - tw, y + pad + lh - nh, w, y + pad + lh }, p.tag_fg[k], DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX | DT_END_ELLIPSIS, row, true));
                }
            }
            y = bottom + pad;
        }
        bk.rows[row].r = RECT{ 0, top, w, y };
    }
    bk.h = y;
    return bk;
}

static void place(View* v, Block& bk, int x, int y) {
    int base = (int)v->rows.size();
    for (auto& r : bk.rows) { OffsetRect(&r.r, x, y); v->rows.push_back(std::move(r)); }
    for (auto& e : bk.els) { OffsetRect(&e.r, x, y); if (e.row >= 0) e.row += base; v->els.push_back(std::move(e)); }
}

static std::string arch_pill_text(const Report& rep) {
    for (auto& it : rep.items) if (it.kind == ReportItem::KV && it.ind == 2 && it.key == T("Architecture")) {
        std::string s = it.value; size_t k;
        while ((k = s.find("; ")) != std::string::npos) s.replace(k, 2, "  ·  ");
        return s;
    }
    std::string a = rep.arch; size_t k = a.find(": ");
    return k == std::string::npos ? a : a.substr(k + 2);
}

static void layout(View* v) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int W = std::max(1, (int)rc.right);
    v->lay_w = W;
    v->els.clear(); v->rows.clear();
    v->m_el = -1;
    const Pal& p = v->pal; const Report& rep = v->rep; const ReportFacts& f = rep.facts;
    // hero
    int H = v->S(132);
    v->els.push_back(fill_el(RECT{ 0, 0, W, H }, p.band));
    std::wstring ver = L"APK Lister " TEXT(APKL_VER_STR);
    int verw = text_w(v, F_VER, ver);
    v->els.push_back(text_el(F_VER, ver, RECT{ W - v->S(14) - verw, v->S(8), W - v->S(14), v->S(8) + line_h(v, F_VER) }, p.band_ver, DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX));
    bool compact = W < v->S(520);
    int box = compact ? v->S(64) : v->S(88), bx = v->S(22), by = (H - box) / 2;
    v->els.push_back(fill_el(RECT{ bx, by, bx + box, by + box }, p.icon_box, compact ? v->S(15) : v->S(20)));
    make_icon(v);
    if (v->icon) {
        El e; e.type = El::Icon; int iw = v->icon_w, ih = v->icon_h;
        if (compact) { iw = iw * 52 / 72; ih = ih * 52 / 72; }
        e.r = RECT{ bx + (box - iw) / 2, by + (box - ih) / 2, bx + (box - iw) / 2 + iw, by + (box - ih) / 2 + ih };
        v->els.push_back(e);
    } else {
        std::wstring t = widen(rep.title.empty() ? std::string("?") : rep.title.substr(0, 1));
        if (!rep.title.empty() && (unsigned char)rep.title[0] >= 0x80) { std::wstring wt = widen(rep.title); t = wt.substr(0, 1); }
        v->els.push_back(text_el(F_NAME, upper(t), RECT{ bx, by, bx + box, by + box }, p.band, DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX));
    }
    int tx = bx + box + v->S(18), tr = W - v->S(22);
    int nameF = compact ? F_TN : F_NAME;
    int nh = line_h(v, nameF), sh = line_h(v, F_SUB), ph = v->S(22);
    std::string sub;
    if (f.have) {
        sub = f.package;
        if (!f.version.empty() || !f.version_code.empty()) sub += "  ·  " + (f.version.empty() ? std::string("-") : f.version) + (f.version_code.empty() ? "" : " (" + f.version_code + ")");
        sub += "  ·  " + rep.kind;
        if (!f.compiler.empty()) sub += "  ·  " + f.compiler;
        if (!f.agp.empty()) sub += "  ·  AGP " + f.agp;
    } else sub = rep.subtitle;
    bool pill = f.have;
    int blockh = nh + sh + (pill ? v->S(9) + ph : 0);
    int ty = (H - blockh) / 2;
    v->els.push_back(text_el(nameF, widen(rep.title), RECT{ tx, ty, std::max(tx + v->S(40), std::min(tr, W - v->S(28) - verw)), ty + nh }, p.band_text, kOne));
    ty += nh;
    v->els.push_back(text_el(F_SUB, widen(sub), RECT{ tx, ty, tr, ty + sh }, p.band_sub, kOne));
    ty += sh + v->S(9);
    if (pill) {
        std::wstring pt = widen(arch_pill_text(rep));
        int pw = std::min(text_w(v, F_PILL, pt) + v->S(22), std::max(v->S(40), tr - tx));
        v->els.push_back(fill_el(RECT{ tx, ty, tx + pw, ty + ph }, p.pill_bg, v->S(11)));
        v->els.push_back(text_el(F_PILL, pt, RECT{ tx + v->S(11), ty, tx + pw - v->S(11), ty + ph }, p.pill_text, kOne | DT_VCENTER | DT_CENTER));
    }
    int y = H;
    // tiles
    if (f.have) {
        struct Tile { std::string label, num, hint; int style; }; // style 0 normal, 1 warn, 2 ok
        std::vector<Tile> t;
        t.push_back({ T("Version"), f.version.empty() ? "-" : f.version, f.version_code.empty() ? "" : strf(T("code %s"), f.version_code.c_str()), 0 });
        std::string api = (f.min_sdk >= 0 ? strf("%d", f.min_sdk) : std::string("-")) + " → " + (f.target_sdk >= 0 ? strf("%d", f.target_sdk) : std::string("-"));
        std::string apih = f.min_sdk >= 0 && f.target_sdk >= 0 ? strf(T("Android %s → %s"), android_short(f.min_sdk).c_str(), android_short(f.target_sdk).c_str()) : "";
        t.push_back({ "API", api, apih, 0 });
        Tile ar; ar.label = T("Architecture"); ar.style = 0;
        if (f.arch_state == 1 || f.arch_state == 3) {
            ar.num = strf(T("%d ABI"), (int)f.abis.size());
            ar.hint = f.arch_state == 3 ? T(".so outside lib/") : f.page16 == 1 ? T("16 KB pages ✓") : f.page16 == 2 ? T("16 KB pages ✗") : "";
            if (ar.hint.empty()) for (auto& a : f.abis) ar.hint += (ar.hint.empty() ? "" : ", ") + a;
            ar.style = f.page16 == 2 ? 1 : 2;
        } else if (f.arch_state == 2) { ar.num = T("in splits"); ar.hint = T("open the whole XAPK/APKS"); }
        else { ar.num = T("any"); ar.hint = T("no native code"); }
        t.push_back(ar);
        t.push_back({ T("Size"), short_sz(f.size), f.apk_count > 0 ? strf(T("%d APK files"), f.apk_count) : f.usize ? strf(T("%s uncompressed"), short_sz(f.usize).c_str()) : "", 0 });
        if (f.perms >= 0) t.push_back({ T("Permissions"), f.perms_danger ? strf("%d / %d", f.perms, f.perms_danger) : strf("%d", f.perms),
                                       f.perms_danger ? strf(T("dangerous: %d"), f.perms_danger) : T("no dangerous"), f.perms_danger ? 1 : 0 });
        else t.push_back({ T("Permissions"), "-", "", 0 });
        if (f.dex_files > 0) t.push_back({ "DEX", short_count(f.dex_methods), strf(T("methods · %d files"), f.dex_files), 0 });
        else t.push_back({ "DEX", "-", T("no DEX"), 0 });
        int cols = W >= v->S(760) ? 6 : W >= v->S(420) ? 3 : 2;
        int px = v->S(14), gap = v->S(8), th = v->S(74);
        int tw = (W - 2 * px - (cols - 1) * gap) / cols;
        y += v->S(12);
        for (size_t i = 0; i < t.size(); i++) {
            int c = (int)i % cols, r = (int)i / cols;
            int x0 = px + c * (tw + gap), y0 = y + r * (th + gap);
            COLORREF bg = t[i].style == 1 ? p.warn_bg : t[i].style == 2 ? p.ok_bg : p.tile_bg;
            COLORREF bd = t[i].style == 1 ? p.warn_bd : t[i].style == 2 ? p.ok_bd : p.tile_bd;
            COLORREF lc = t[i].style == 1 ? p.warn_lbl : t[i].style == 2 ? p.ok_lbl : p.tile_lbl;
            COLORREF nc = t[i].style == 1 ? p.warn_num : t[i].style == 2 ? p.ok_num : p.tile_num;
            v->els.push_back(fill_el(RECT{ x0, y0, x0 + tw, y0 + th }, bg, v->S(8), bd));
            int ix = x0 + v->S(10), iw = x0 + tw - v->S(8);
            int ly = y0 + v->S(8), lh = line_h(v, F_TL);
            v->els.push_back(text_el(F_TL, upper(widen(t[i].label)), RECT{ ix, ly, iw, ly + lh }, lc, kOne, -1, false, std::max(1, v->S10(5))));
            int ny = ly + lh + v->S(1), nh2 = line_h(v, F_TN);
            std::wstring num = widen(t[i].num);
            int nf = text_w(v, F_TN, num) <= iw - ix ? F_TN : F_TN2; // long numbers in narrow tiles
            int nyy = nf == F_TN ? ny : ny + (nh2 - line_h(v, F_TN2)) / 2;
            v->els.push_back(text_el(nf, num, RECT{ ix, nyy, iw, nyy + line_h(v, nf) }, nc, kOne));
            int hy = ny + nh2, hh = line_h(v, F_TH);
            v->els.push_back(text_el(F_TH, widen(t[i].hint), RECT{ ix, hy, iw, hy + hh }, p.tile_hint, kOne));
        }
        y += ((int)t.size() + cols - 1) / cols * (th + gap) - gap + v->S(4);
    }
    // sections
    const auto& items = rep.items;
    size_t n = items.size();
    bool footer = n > 0 && items[n - 1].kind == ReportItem::Line && items[n - 1].ind == 0;
    size_t end = footer ? n - 1 : n;
    int px = v->S(14), gap = v->S(22);
    bool two = W >= v->S(700);
    int cw = two ? (W - 2 * px - gap) / 2 : W - 2 * px;
    int colY[2] = { y, y };
    // sections in report order, except the FILE section (path/type/size are already in the hero and tiles) goes last
    std::vector<std::pair<size_t, size_t>> secs;
    for (size_t a = 0; a < end;) {
        if (items[a].kind != ReportItem::Section) { a++; continue; }
        size_t b = a + 1; while (b < end && items[b].kind != ReportItem::Section) b++;
        secs.push_back({ a, b });
        a = b;
    }
    if (f.have && secs.size() > 1 && items[secs[0].first].key == T("FILE")) std::rotate(secs.begin(), secs.begin() + 1, secs.end());
    for (auto& sc : secs) {
        if (two && section_wide(v, sc.first, sc.second, cw)) {
            int yy = std::max(colY[0], colY[1]);
            Block bk = build_section(v, sc.first, sc.second, W - 2 * px);
            place(v, bk, px, yy);
            colY[0] = colY[1] = yy + bk.h + v->S(10);
            continue;
        }
        Block bk = build_section(v, sc.first, sc.second, cw);
        int c = two && colY[1] < colY[0] ? 1 : 0;
        place(v, bk, px + c * (cw + gap), colY[c]);
        colY[c] += bk.h + v->S(10);
    }
    y = std::max(colY[0], colY[1]);
    if (footer) {
        y += v->S(8);
        std::wstring ft = widen(items[n - 1].value);
        ISize fs = text_size(v, F_NOTE, ft, W - 2 * px, kWrap);
        Row rw; rw.item = (int)n - 1; rw.r = RECT{ px, y, W - px, y + fs.cy }; rw.plain = items[n - 1].plain; rw.value = items[n - 1].value;
        v->rows.push_back(rw);
        v->els.push_back(text_el(F_NOTE, ft, RECT{ px, y, W - px, y + fs.cy }, p.footer, kWrap, (int)v->rows.size() - 1, true));
        y += fs.cy;
    }
    v->doc_h = y + v->S(14);
}

static void update_scroll(View* v) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int maxy = std::max(0, v->doc_h - (int)rc.bottom);
    v->sy = std::min(std::max(0, v->sy), maxy);
    SCROLLINFO si = {}; si.cbSize = sizeof si; si.fMask = SIF_ALL | SIF_DISABLENOSCROLL; si.nMax = std::max(0, v->doc_h - 1); si.nPage = (UINT)rc.bottom; si.nPos = v->sy;
    SetScrollInfo(v->hwnd, SB_VERT, &si, TRUE);
}
static void relayout(View* v) {
    layout(v);
    update_scroll(v);
    RECT rc; GetClientRect(v->hwnd, &rc);
    if (rc.right != v->lay_w) { layout(v); update_scroll(v); } // scrollbar appeared/disappeared
    InvalidateRect(v->hwnd, nullptr, FALSE);
}
static void scroll_to(View* v, int y) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int maxy = std::max(0, v->doc_h - (int)rc.bottom);
    y = std::min(std::max(0, y), maxy);
    if (y == v->sy) return;
    v->sy = y;
    SetScrollPos(v->hwnd, SB_VERT, y, TRUE);
    InvalidateRect(v->hwnd, nullptr, FALSE);
}

// ---- painting
static void round_rect(HDC dc, const RECT& r, int rad, COLORREF fill, COLORREF border) {
    using namespace Gdiplus;
    Graphics g(dc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    REAL x = (REAL)r.left, y = (REAL)r.top, w = (REAL)(r.right - r.left), h = (REAL)(r.bottom - r.top);
    if (border != CLR_INVALID) { x += 0.5f; y += 0.5f; w -= 1; h -= 1; }
    REAL d = (REAL)std::min(rad * 2, (int)std::min(r.right - r.left, r.bottom - r.top));
    GraphicsPath path;
    if (d <= 1) path.AddRectangle(RectF(x, y, w, h));
    else {
        path.AddArc(x, y, d, d, 180, 90); path.AddArc(x + w - d, y, d, d, 270, 90);
        path.AddArc(x + w - d, y + h - d, d, d, 0, 90); path.AddArc(x, y + h - d, d, d, 90, 90); path.CloseFigure();
    }
    SolidBrush b(Color(255, cr(fill), cg(fill), cb(fill)));
    g.FillPath(&b, &path);
    if (border != CLR_INVALID) { Pen pen(Color(255, cr(border), cg(border), cb(border)), 1.0f); g.DrawPath(&pen, &path); }
}
static bool row_selected(View* v, int row) {
    if (row < 0) return false;
    if (v->sel_all) return true;
    if (v->sel_a < 0) return false;
    return row >= std::min(v->sel_a, v->sel_b) && row <= std::max(v->sel_a, v->sel_b);
}
static void paint(View* v, HDC out) {
    RECT rc; GetClientRect(v->hwnd, &rc);
    int cw = std::max(1, (int)rc.right), ch = std::max(1, (int)rc.bottom);
    if (!v->mdc || v->mw != cw || v->mh != ch) {
        if (v->mdc) { DeleteDC(v->mdc); DeleteObject(v->mbmp); }
        v->mdc = CreateCompatibleDC(out); v->mbmp = CreateCompatibleBitmap(out, cw, ch); SelectObject(v->mdc, v->mbmp);
        v->mw = cw; v->mh = ch;
    }
    HDC dc = v->mdc; const Pal& p = v->pal;
    HBRUSH bgb = CreateSolidBrush(p.bg); RECT all = { 0, 0, cw, ch }; FillRect(dc, &all, bgb); DeleteObject(bgb);
    SetBkMode(dc, TRANSPARENT);
    int sy = v->sy;
    {
        // selection backgrounds
        if (v->sel_all || v->sel_a >= 0)
            for (size_t i = 0; i < v->rows.size(); i++) if (row_selected(v, (int)i)) {
                RECT r = v->rows[i].r; OffsetRect(&r, 0, -sy); InflateRect(&r, v->S(4), 0);
                if (r.bottom < 0 || r.top > ch) continue;
                round_rect(dc, r, v->S(3), p.sel, CLR_INVALID);
            }
        for (size_t i = 0; i < v->els.size(); i++) {
            const El& e = v->els[i];
            RECT r = e.r; OffsetRect(&r, 0, -sy);
            if (r.bottom < 0 || r.top > ch) continue;
            if (e.type == El::Fill) {
                if (e.radius <= 0 && e.border == CLR_INVALID) { HBRUSH b = CreateSolidBrush(e.color); FillRect(dc, &r, b); DeleteObject(b); }
                else round_rect(dc, r, e.radius, e.color, e.border);
            } else if (e.type == El::Icon) {
                if (v->icon) {
                    HDC idc = CreateCompatibleDC(dc); HGDIOBJ old = SelectObject(idc, v->icon);
                    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
                    if (r.right - r.left == v->icon_w) AlphaBlend(dc, r.left, r.top, v->icon_w, v->icon_h, idc, 0, 0, v->icon_w, v->icon_h, bf);
                    else { SetStretchBltMode(dc, HALFTONE); AlphaBlend(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, idc, 0, 0, v->icon_w, v->icon_h, bf); }
                    SelectObject(idc, old); DeleteDC(idc);
                }
            } else {
                COLORREF tc = e.color;
                HGDIOBJ of = SelectObject(dc, v->fonts[e.font]);
                SetTextCharacterExtra(dc, e.extra);
                if ((int)i == v->m_el && v->m_len > 0) {
                    RECT hr = r;
                    bool single = (e.fmt & DT_SINGLELINE) || text_size(v, e.font, e.s, r.right - r.left, e.fmt, e.extra).cy <= line_h(v, e.font);
                    if (single) {
                        SIZE a = {}, b = {}, full = {};
                        GetTextExtentPoint32W(dc, e.s.c_str(), v->m_off, &a);
                        GetTextExtentPoint32W(dc, e.s.c_str() + v->m_off, v->m_len, &b);
                        GetTextExtentPoint32W(dc, e.s.c_str(), (int)e.s.size(), &full);
                        int x0 = r.left;
                        if (e.fmt & DT_RIGHT) x0 = r.right - full.cx;
                        else if (e.fmt & DT_CENTER) x0 = r.left + (r.right - r.left - full.cx) / 2;
                        hr.left = x0 + a.cx - 1; hr.right = std::min((int)r.right, (int)(x0 + a.cx + b.cx + 1));
                        hr.bottom = std::min(r.bottom, r.top + (LONG)line_h(v, e.font));
                        if (e.fmt & DT_VCENTER) { int lh = line_h(v, e.font); hr.top = r.top + (r.bottom - r.top - lh) / 2; hr.bottom = hr.top + lh; }
                    }
                    HBRUSH hb = CreateSolidBrush(p.find); FillRect(dc, &hr, hb); DeleteObject(hb);
                    tc = single ? tc : p.find_text;
                    if (single) {
                        // draw text, then the match on top in the contrasting colour
                        SetTextColor(dc, tc);
                        DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
                        HRGN rg = CreateRectRgnIndirect(&hr); SelectClipRgn(dc, rg);
                        SetTextColor(dc, p.find_text);
                        DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
                        SelectClipRgn(dc, nullptr); DeleteObject(rg);
                        SetTextCharacterExtra(dc, 0); SelectObject(dc, of);
                        continue;
                    }
                }
                SetTextColor(dc, tc);
                DrawTextW(dc, e.s.c_str(), (int)e.s.size(), &r, e.fmt | DT_NOPREFIX);
                SetTextCharacterExtra(dc, 0);
                SelectObject(dc, of);
            }
        }
    }
    BitBlt(out, 0, 0, cw, ch, dc, 0, 0, SRCCOPY);
}
// ---- selection, copy, hit testing
static int hit_row(View* v, int x, int ydoc, bool nearest) {
    for (size_t i = 0; i < v->rows.size(); i++) {
        const RECT& r = v->rows[i].r;
        if (x >= r.left - v->S(6) && x < r.right + v->S(6) && ydoc >= r.top && ydoc < r.bottom) return (int)i;
    }
    if (!nearest) return -1;
    int best = -1, bd = INT_MAX;
    for (size_t i = 0; i < v->rows.size(); i++) {
        const RECT& r = v->rows[i].r;
        int dx = x < r.left ? r.left - x : x >= r.right ? x - r.right : 0;
        int dy = ydoc < r.top ? r.top - ydoc : ydoc >= r.bottom ? ydoc - r.bottom : 0;
        int d = dx * 4 + dy;
        if (d < bd) { bd = d; best = (int)i; }
    }
    return best;
}
static void set_clipboard(HWND h, const std::string& s) {
    std::wstring w = crlf(s);
    if (!OpenClipboard(h)) return;
    EmptyClipboard();
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (g) {
        void* p = GlobalLock(g); memcpy(p, w.c_str(), (w.size() + 1) * sizeof(wchar_t)); GlobalUnlock(g);
        if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g);
    }
    CloseClipboard();
}
static std::string trim_right(std::string s) { while (!s.empty() && (s.back() == ' ' || s.back() == '\n')) s.pop_back(); return s; }
static std::string selection_text(View* v) {
    if (v->sel_all || v->sel_a < 0) return v->rep.summary;
    int a = std::min(v->sel_a, v->sel_b), b = std::max(v->sel_a, v->sel_b);
    std::string s;
    for (int i = a; i <= b && i < (int)v->rows.size(); i++) s += trim_right(v->rows[i].plain) + "\n";
    return s;
}
static void do_copy(View* v) { set_clipboard(v->hwnd, selection_text(v)); }
static void select_all(View* v) { v->sel_all = true; v->sel_a = v->sel_b = -1; InvalidateRect(v->hwnd, nullptr, FALSE); }

static void context_menu(View* v, int sx, int sy) {
    POINT pt = { sx, sy };
    if (sx == -1 && sy == -1) { pt.x = v->S(20); pt.y = v->S(20); ClientToScreen(v->hwnd, &pt); }
    POINT cp = pt; ScreenToClient(v->hwnd, &cp);
    int row = hit_row(v, cp.x, cp.y + v->sy, false);
    if (row >= 0 && !row_selected(v, row)) { v->sel_all = false; v->sel_a = v->sel_b = row; InvalidateRect(v->hwnd, nullptr, FALSE); }
    bool multi = v->sel_all || (v->sel_a >= 0 && v->sel_a != v->sel_b);
    HMENU m = CreatePopupMenu();
    std::string val = row >= 0 ? v->rows[row].value : "";
    if (row >= 0 && !val.empty()) AppendMenuW(m, MF_STRING, 1, widen(T("Copy value")).c_str());
    if (v->sel_a >= 0 || v->sel_all) AppendMenuW(m, MF_STRING, 2, widen(T(multi ? "Copy selection" : "Copy line")).c_str());
    AppendMenuW(m, MF_STRING, 3, (widen(T("Copy all")) + L"\tCtrl+C").c_str());
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, 4, (widen(T("Select all")) + L"\tCtrl+A").c_str());
    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, v->hwnd, nullptr);
    DestroyMenu(m);
    if (cmd == 1) set_clipboard(v->hwnd, val);
    else if (cmd == 2) do_copy(v);
    else if (cmd == 3) set_clipboard(v->hwnd, v->rep.summary);
    else if (cmd == 4) select_all(v);
}

// ---- loading
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
    v->icon_data = std::move(v->rep.icon); v->rep.icon.clear();
    if (v->icon) { DeleteObject(v->icon); v->icon = nullptr; }
    v->icon_ok = v->icon_2 = false;
    { std::vector<uint32_t> px; int w = 0, h = 0;
      if (decode_pixels(v->icon_data, 48, 48, px, w, h)) v->icon_ok = icon_colors(px, v->icon_c1, v->icon_c2, v->icon_2); }
    v->sy = 0; v->sel_a = v->sel_b = -1; v->sel_all = false; v->m_el = -1;
    set_theme(v);
    relayout(v);
}

static void key_scroll(View* v, int dy) { scroll_to(v, v->sy + dy); }

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    View* v = (View*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_CREATE: {
        v = new View(); v->hwnd = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)v);
        v->dpi = window_dpi(h);
        make_fonts(v);
        return 0;
    }
    case WM_SIZE: if (v && v->lay_w >= 0) relayout(v); return 0;
    case WM_DPICHANGED_AFTERPARENT: case WM_DPICHANGED:
        if (v) { int d = window_dpi(h); if (d != v->dpi) { v->dpi = d; make_fonts(v); v->icon_for = 0; if (v->icon) { DeleteObject(v->icon); v->icon = nullptr; } relayout(v); } }
        return m == WM_DPICHANGED ? 0 : DefWindowProcW(h, m, w, l);
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        if (v) paint(v, dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_VSCROLL: if (v) {
        RECT rc; GetClientRect(h, &rc);
        SCROLLINFO si = {}; si.cbSize = sizeof si; si.fMask = SIF_TRACKPOS; GetScrollInfo(h, SB_VERT, &si);
        int y = v->sy;
        switch (LOWORD(w)) {
        case SB_LINEUP: y -= v->S(40); break; case SB_LINEDOWN: y += v->S(40); break;
        case SB_PAGEUP: y -= rc.bottom - v->S(40); break; case SB_PAGEDOWN: y += rc.bottom - v->S(40); break;
        case SB_TOP: y = 0; break; case SB_BOTTOM: y = v->doc_h; break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: y = si.nTrackPos; break;
        }
        scroll_to(v, y);
        return 0;
    } break;
    case WM_MOUSEWHEEL: if (v) {
        static int acc = 0; acc += GET_WHEEL_DELTA_WPARAM(w);
        UINT lines = 3; SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        int step = lines == WHEEL_PAGESCROLL ? v->mh : (int)lines * v->S(20);
        int n = acc / 40; acc -= n * 40; // smooth for high-resolution wheels
        key_scroll(v, -n * step / 3);
        return 0;
    } break;
    case WM_GETDLGCODE: return DLGC_WANTARROWS | DLGC_WANTCHARS;
    case WM_KEYDOWN: if (v) {
        bool ctrl = GetKeyState(VK_CONTROL) < 0;
        RECT rc; GetClientRect(h, &rc);
        if (ctrl && w == 'A') { select_all(v); return 0; }
        if (ctrl && (w == 'C' || w == VK_INSERT)) { do_copy(v); return 0; }
        switch (w) {
        case VK_UP: key_scroll(v, -v->S(40)); return 0;
        case VK_DOWN: key_scroll(v, v->S(40)); return 0;
        case VK_PRIOR: key_scroll(v, -(int)(rc.bottom - v->S(40))); return 0;
        case VK_NEXT: case VK_SPACE: key_scroll(v, rc.bottom - v->S(40)); return 0;
        case VK_HOME: scroll_to(v, 0); return 0;
        case VK_END: scroll_to(v, v->doc_h); return 0;
        case VK_LEFT: case VK_RIGHT: case VK_SHIFT: case VK_CONTROL: case VK_MENU: return 0;
        case VK_APPS: context_menu(v, -1, -1); return 0;
        }
        // let Total Commander's lister handle everything else (Esc, N/P, F-keys, 1-7 view modes, ...)
        PostMessageW(GetParent(h), m, w, l);
        return 0;
    } break;
    case WM_CHAR: return 0;
    case WM_SYSKEYDOWN: case WM_SYSKEYUP: case WM_SYSCHAR:
        PostMessageW(GetParent(h), m, w, l);
        return 0;
    case WM_LBUTTONDOWN: case WM_LBUTTONDBLCLK: if (v) {
        SetFocus(h);
        int x = (short)LOWORD(l), y = (short)HIWORD(l) + v->sy;
        int row = hit_row(v, x, y, false);
        bool shift = (w & MK_SHIFT) != 0;
        v->sel_all = false;
        if (shift && v->sel_a >= 0 && row >= 0) v->sel_b = row;
        else { v->sel_a = v->sel_b = row; }
        if (row >= 0) { v->dragging = true; SetCapture(h); }
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    } break;
    case WM_MOUSEMOVE: if (v && v->dragging) {
        RECT rc; GetClientRect(h, &rc);
        int x = (short)LOWORD(l), cy = (short)HIWORD(l);
        if (cy < 0) key_scroll(v, cy); else if (cy > rc.bottom) key_scroll(v, cy - rc.bottom);
        int row = hit_row(v, x, std::min(std::max(cy, 0), (int)rc.bottom) + v->sy, true);
        if (row >= 0 && row != v->sel_b) { v->sel_b = row; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    } break;
    case WM_LBUTTONUP: case WM_CAPTURECHANGED: if (v && v->dragging) { v->dragging = false; if (m == WM_LBUTTONUP) ReleaseCapture(); } return 0;
    case WM_CONTEXTMENU: if (v) { context_menu(v, (short)LOWORD(l), (short)HIWORD(l)); return 0; } break;
    case WM_SETTINGCHANGE: if (v && l && !lstrcmpiW((LPCWSTR)l, L"ImmersiveColorSet")) { set_theme(v); relayout(v); } break;
    case WM_DESTROY:
        if (v) {
            if (v->icon) DeleteObject(v->icon);
            for (auto f : v->fonts) if (f) DeleteObject(f);
            if (v->mdc) { DeleteDC(v->mdc); DeleteObject(v->mbmp); }
            SetWindowLongPtrW(h, GWLP_USERDATA, 0);
            delete v;
            if (--g_windows == 0 && g_gdip) { Gdiplus::GdiplusShutdown(g_gdip); g_gdip = 0; }
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
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.style = CS_DBLCLKS;
    done = RegisterClassW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return done;
}

EXPORT HWND __stdcall ListLoadW(HWND parent, WCHAR* file, int flags) {
    if (!register_class()) return nullptr;
    if (!g_gdip) { Gdiplus::GdiplusStartupInput in; if (Gdiplus::GdiplusStartup(&g_gdip, &in, nullptr) != Gdiplus::Ok) g_gdip = 0; }
    if (!g_gdip) return nullptr;
    RECT rc; GetClientRect(parent, &rc);
    g_windows++;
    HWND h = CreateWindowExW(0, kClass, L"APK Lister", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN, 0, 0, rc.right, rc.bottom, parent, nullptr, g_inst, nullptr);
    if (!h) { if (--g_windows == 0) { Gdiplus::GdiplusShutdown(g_gdip); g_gdip = 0; } return nullptr; }
    View* v = (View*)GetWindowLongPtrW(h, GWLP_USERDATA);
    v->flags = flags;
    HCURSOR oc = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    load_file(v, file);
    SetCursor(oc);
    SetFocus(h);
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
    v->flags = flags;
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
    if (!dps) return;
    if (dps->DefaultIniName[0]) MultiByteToWideChar(CP_ACP, 0, dps->DefaultIniName, -1, g_default_ini, MAX_PATH);
    DWORD lo = dps->PluginInterfaceVersionLow; while (lo >= 100) lo /= 10;
    g_iface = (int)(dps->PluginInterfaceVersionHi * 100 + lo);
}

EXPORT int __stdcall ListSendCommand(HWND win, int cmd, int param) {
    View* v = (View*)GetWindowLongPtrW(win, GWLP_USERDATA);
    if (!v) return LISTPLUGIN_ERROR;
    switch (cmd) {
    case lc_copy: do_copy(v); return LISTPLUGIN_OK;
    case lc_selectall: select_all(v); return LISTPLUGIN_OK;
    case lc_newparams: v->flags = param; set_theme(v); relayout(v); return LISTPLUGIN_OK;
    }
    return LISTPLUGIN_ERROR;
}

static bool is_word(wchar_t c) { return IsCharAlphaNumericW(c) || c == L'_'; }

EXPORT int __stdcall ListSearchTextW(HWND win, WCHAR* what, int params) {
    View* v = (View*)GetWindowLongPtrW(win, GWLP_USERDATA);
    if (!v || !what || !*what) return LISTPLUGIN_ERROR;
    bool mc = params & lcs_matchcase, ww = params & lcs_wholewords, back = params & lcs_backwards;
    std::wstring needle = what;
    if (!mc) CharLowerBuffW(&needle[0], (DWORD)needle.size());
    size_t n = needle.size();
    int ne = (int)v->els.size();
    int ei; long long pos; // pos: forward = first index allowed; backward = last start allowed
    if ((params & lcs_findfirst) || v->m_el < 0 || v->m_el >= ne) { ei = back ? ne - 1 : 0; pos = back ? LLONG_MAX : 0; }
    else { ei = v->m_el; pos = back ? (long long)v->m_off - 1 : (long long)v->m_off + 1; }
    for (; ei >= 0 && ei < ne; ei += back ? -1 : 1, pos = back ? LLONG_MAX : 0) {
        const El& e = v->els[ei];
        if (e.type != El::Text || !e.search || e.s.size() < n) continue;
        std::wstring hay = e.s;
        if (!mc) CharLowerBuffW(&hay[0], (DWORD)hay.size());
        for (;;) {
            size_t f;
            if (back) { if (pos < 0) break; f = hay.rfind(needle, pos == LLONG_MAX ? std::wstring::npos : (size_t)pos); }
            else { if (pos > (long long)hay.size()) break; f = hay.find(needle, (size_t)pos); }
            if (f == std::wstring::npos) break;
            bool ok = true;
            if (ww) {
                if (f > 0 && is_word(hay[f - 1])) ok = false;
                if (f + n < hay.size() && is_word(hay[f + n])) ok = false;
            }
            if (ok) {
                v->m_el = ei; v->m_off = (int)f; v->m_len = (int)n;
                v->sel_all = false; v->sel_a = v->sel_b = e.row;
                RECT rc; GetClientRect(win, &rc);
                if (e.r.top < v->sy || e.r.bottom > v->sy + rc.bottom) scroll_to(v, e.r.top - rc.bottom / 3);
                InvalidateRect(win, nullptr, FALSE);
                return LISTPLUGIN_OK;
            }
            if (back) pos = (long long)f - 1; else pos = (long long)f + 1;
        }
    }
    return LISTPLUGIN_ERROR;
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
