// Minimal Lister host for testing apklister.wlx/.wlx64 without Total Commander.
// usage: testhost.exe plugin.wlx64 file [search-text] [--preview out.bmp] [--size WxH]
#include <windows.h>
#include <cstdio>
#include <string>
typedef HWND(__stdcall* PLoad)(HWND, WCHAR*, int);
typedef int(__stdcall* PSearch)(HWND, WCHAR*, int);
typedef void(__stdcall* PDetect)(char*, int);
typedef HBITMAP(__stdcall* PPreview)(WCHAR*, int, int, char*, int);
typedef void(__stdcall* PClose)(HWND);
static HWND g_plugin;
static LRESULT CALLBACK Proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_SIZE && g_plugin) { MoveWindow(g_plugin, 0, 0, LOWORD(l), HIWORD(l), TRUE); return 0; }
    if (m == WM_KEYDOWN && w == VK_ESCAPE) { DestroyWindow(h); return 0; }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}
static void save_bmp(HBITMAP b, const wchar_t* path) {
    BITMAP bm; GetObject(b, sizeof bm, &bm);
    BITMAPINFOHEADER bi = {}; bi.biSize = sizeof bi; bi.biWidth = bm.bmWidth; bi.biHeight = bm.bmHeight; bi.biPlanes = 1; bi.biBitCount = 32; bi.biCompression = BI_RGB;
    std::string px((size_t)bm.bmWidth * bm.bmHeight * 4, '\0');
    HDC dc = GetDC(nullptr); GetDIBits(dc, b, 0, bm.bmHeight, &px[0], (BITMAPINFO*)&bi, DIB_RGB_COLORS); ReleaseDC(nullptr, dc);
    BITMAPFILEHEADER fh = { 0x4D42, (DWORD)(sizeof fh + sizeof bi + px.size()), 0, 0, sizeof fh + sizeof bi };
    FILE* f = _wfopen(path, L"wb"); if (!f) return;
    fwrite(&fh, sizeof fh, 1, f); fwrite(&bi, sizeof bi, 1, f); fwrite(px.data(), px.size(), 1, f); fclose(f);
}
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { MessageBoxW(nullptr, L"usage: testhost plugin.wlx64 file [search] [--preview out.bmp] [--size WxH]", L"testhost", 0); return 2; }
    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll) { fwprintf(stderr, L"cannot load %ls (%lu)\n", argv[1], GetLastError()); return 1; }
    PLoad load = (PLoad)(void*)GetProcAddress(dll, "ListLoadW");
    PSearch search = (PSearch)(void*)GetProcAddress(dll, "ListSearchTextW");
    PDetect detect = (PDetect)(void*)GetProcAddress(dll, "ListGetDetectString");
    PPreview preview = (PPreview)(void*)GetProcAddress(dll, "ListGetPreviewBitmapW");
    PClose close = (PClose)(void*)GetProcAddress(dll, "ListCloseWindow");
    char ds[512] = ""; if (detect) detect(ds, sizeof ds);
    fprintf(stderr, "exports: ListLoadW=%p ListSearchTextW=%p ListGetPreviewBitmapW=%p ListCloseWindow=%p\ndetect: %s\n", (void*)load, (void*)search, (void*)preview, (void*)close, ds);
    int ww = 1180, wh = 860;
    const wchar_t* find = nullptr; const wchar_t* prev = nullptr;
    for (int i = 3; i < argc; i++) {
        if (!wcscmp(argv[i], L"--preview") && i + 1 < argc) prev = argv[++i];
        else if (!wcscmp(argv[i], L"--size") && i + 1 < argc) { swscanf(argv[++i], L"%dx%d", &ww, &wh); }
        else find = argv[i];
    }
    if (prev && preview) {
        HBITMAP b = preview(argv[2], 96, 96, nullptr, 0);
        fprintf(stderr, "preview bitmap: %p\n", (void*)b);
        if (b) { save_bmp(b, prev); DeleteObject(b); }
        return b ? 0 : 1;
    }
    WNDCLASSW wc = {}; wc.lpfnWndProc = Proc; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"TestLister";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    std::wstring t = L"Lister - [" + std::wstring(argv[2]) + L"]";
    HWND main = CreateWindowExW(0, L"TestLister", t.c_str(), WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN, 0, 0, ww, wh, nullptr, nullptr, wc.hInstance, nullptr);
    DWORD t0 = GetTickCount();
    g_plugin = load ? load(main, argv[2], 0) : nullptr;
    fprintf(stderr, "ListLoadW -> %p in %lu ms\n", (void*)g_plugin, GetTickCount() - t0);
    if (!g_plugin) return 1;
    RECT rc; GetClientRect(main, &rc); MoveWindow(g_plugin, 0, 0, rc.right, rc.bottom, TRUE);
    if (find && search) { MSG m; while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        int r = search(g_plugin, (WCHAR*)find, 1); fprintf(stderr, "search '%ls' -> %d\n", find, r); }
    MSG msg; while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    if (close && IsWindow(g_plugin)) close(g_plugin);
    return 0;
}
