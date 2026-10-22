// SPDX-License-Identifier: GPL-2.0-or-later
#include "util.h"
#include <cstdarg>
#include <cstdio>
#include <algorithm>

std::string strf(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return std::string();
    if ((size_t)n < sizeof buf) return std::string(buf, n);
    std::string s((size_t)n + 1, '\0');
    va_start(ap, fmt); vsnprintf(&s[0], s.size(), fmt, ap); va_end(ap);
    s.resize(n);
    return s;
}

void append_utf8(std::string& o, uint32_t c) {
    if (c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) c = 0xFFFD;
    if (c < 0x80) o += (char)c;
    else if (c < 0x800) { o += (char)(0xC0 | (c >> 6)); o += (char)(0x80 | (c & 63)); }
    else if (c < 0x10000) { o += (char)(0xE0 | (c >> 12)); o += (char)(0x80 | ((c >> 6) & 63)); o += (char)(0x80 | (c & 63)); }
    else { o += (char)(0xF0 | (c >> 18)); o += (char)(0x80 | ((c >> 12) & 63)); o += (char)(0x80 | ((c >> 6) & 63)); o += (char)(0x80 | (c & 63)); }
}

static std::string utf16_to_utf8(const uint8_t* s, size_t n, bool be) {
    std::string o; o.reserve(n);
    for (size_t i = 0; i < n; i++) {
        uint32_t c = be ? (uint32_t)((s[2 * i] << 8) | s[2 * i + 1]) : rd16(s + 2 * i);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < n) {
            uint32_t d = be ? (uint32_t)((s[2 * i + 2] << 8) | s[2 * i + 3]) : rd16(s + 2 * i + 2);
            if (d >= 0xDC00 && d < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00); i++; }
        }
        append_utf8(o, c);
    }
    return o;
}
std::string utf16le_to_utf8(const uint8_t* s, size_t n) { return utf16_to_utf8(s, n, false); }
std::string utf16be_to_utf8(const uint8_t* s, size_t n) { return utf16_to_utf8(s, n, true); }
std::string latin1_to_utf8(const uint8_t* s, size_t n) {
    std::string o; for (size_t i = 0; i < n; i++) append_utf8(o, s[i]); return o;
}

std::string sanitize_utf8(const std::string& s) {
    std::string o; o.reserve(s.size());
    const uint8_t* p = (const uint8_t*)s.data(); size_t n = s.size(), i = 0;
    while (i < n) {
        uint8_t c = p[i];
        if (c < 0x80) {
            if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') o += strf("\\x%02X", c); else o += (char)c;
            i++; continue;
        }
        int len = (c >= 0xF0 && c < 0xF5) ? 4 : (c >= 0xE0) && c < 0xF0 ? 3 : (c >= 0xC2 && c < 0xE0) ? 2 : 0;
        bool good = len > 0 && i + len <= n;
        for (int k = 1; good && k < len; k++) if ((p[i + k] & 0xC0) != 0x80) good = false;
        if (good) { o.append((const char*)p + i, len); i += len; }
        else { o += "\xEF\xBF\xBD"; i++; }
    }
    return o;
}

std::string hexstr(const uint8_t* p, size_t n, char sep, bool upper) {
    static const char* lo = "0123456789abcdef"; static const char* up = "0123456789ABCDEF";
    const char* d = upper ? up : lo;
    std::string o; o.reserve(n * 3);
    for (size_t i = 0; i < n; i++) {
        if (i && sep) o += sep;
        o += d[p[i] >> 4]; o += d[p[i] & 15];
    }
    return o;
}

std::string with_commas(uint64_t n) {
    std::string s = strf("%llu", (unsigned long long)n), o;
    int c = 0;
    for (size_t i = s.size(); i-- > 0;) { o += s[i]; if (++c % 3 == 0 && i) o += ' '; }
    std::reverse(o.begin(), o.end());
    return o;
}

std::string human_size(uint64_t n) {
    if (n < 1024) return strf("%llu B", (unsigned long long)n);
    const char* u[] = { "KiB", "MiB", "GiB", "TiB" };
    double v = (double)n; int i = -1;
    while (v >= 1024 && i < 3) { v /= 1024; i++; }
    return strf("%.2f %s (%s B)", v, u[i], with_commas(n).c_str());
}

std::string lower(std::string s) { for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32); return s; }
bool ends_with(const std::string& s, const char* suf) { size_t k = strlen(suf); return s.size() >= k && s.compare(s.size() - k, k, suf) == 0; }
bool starts_with(const std::string& s, const char* pre) { size_t k = strlen(pre); return s.size() >= k && s.compare(0, k, pre) == 0; }

std::string xml_escape(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': o += "&amp;"; break; case '<': o += "&lt;"; break; case '>': o += "&gt;"; break;
        case '"': o += "&quot;"; break; case '\n': o += "&#10;"; break;
        default: o += c;
        }
    }
    return o;
}
std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= ' ') a++;
    while (b > a && (unsigned char)s[b - 1] <= ' ') b--;
    return s.substr(a, b - a);
}
std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> v; size_t a = 0;
    while (a <= s.size()) {
        size_t e = s.find('\n', a); if (e == std::string::npos) e = s.size();
        std::string l = s.substr(a, e - a); if (!l.empty() && l.back() == '\r') l.pop_back();
        v.push_back(l); a = e + 1;
    }
    return v;
}
std::string dos_datetime(uint16_t d, uint16_t t) {
    return strf("%04d-%02d-%02d %02d:%02d:%02d", 1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2);
}
const uint8_t* memfind(const uint8_t* h, size_t hn, const void* nd, size_t nn) {
    if (!nn || hn < nn) return nullptr;
    const uint8_t* n = (const uint8_t*)nd;
    const uint8_t* end = h + hn - nn + 1;
    for (const uint8_t* p = h; p < end; ) {
        p = (const uint8_t*)memchr(p, n[0], end - p);
        if (!p) return nullptr;
        if (memcmp(p, n, nn) == 0) return p;
        p++;
    }
    return nullptr;
}
