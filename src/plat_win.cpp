// SPDX-License-Identifier: GPL-2.0-or-later
#include "plat.h"
#include <windows.h>
static std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0'); MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n); return w;
}
static std::string errstr(DWORD e) {
    char buf[256]; DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), buf, sizeof buf, nullptr);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == '.')) n--;
    return n ? std::string(buf, n) : "error " + std::to_string(e);
}
bool MappedFile::open(const std::string& path, std::string& err) {
    HANDLE f = CreateFileW(widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) { err = errstr(GetLastError()); return false; }
    h1 = f;
    LARGE_INTEGER li; if (!GetFileSizeEx(f, &li)) { err = errstr(GetLastError()); return false; }
    size = (uint64_t)li.QuadPart;
    if (!size) { p = (const uint8_t*)""; return true; }
    if (sizeof(void*) == 4 && size > 0x60000000ull) { err = "file too large for the 32-bit plugin (use 64-bit Total Commander)"; return false; }
    HANDLE m = CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m) { err = errstr(GetLastError()); return false; }
    h2 = m;
    p = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!p) { err = "MapViewOfFile: " + errstr(GetLastError()); return false; }
    return true;
}
void MappedFile::close() {
    if (p && size) UnmapViewOfFile(p);
    p = nullptr;
    if (h2) CloseHandle((HANDLE)h2);
    h2 = nullptr;
    if (h1) CloseHandle((HANDLE)h1);
    h1 = nullptr;
}
