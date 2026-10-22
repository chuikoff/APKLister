// APK Lister - common helpers (portable C++)
// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

struct Bytes {
    const uint8_t* p = nullptr;
    size_t n = 0;
    Bytes() {}
    Bytes(const uint8_t* pp, size_t nn) : p(pp), n(nn) {}
    explicit Bytes(const std::vector<uint8_t>& v) : p(v.data()), n(v.size()) {}
    bool has(size_t off, size_t len) const { return off <= n && len <= n - off; }
    Bytes sub(size_t off, size_t len) const {
        if (!has(off, len)) return Bytes();
        return Bytes(p + off, len);
    }
    Bytes from(size_t off) const { return off <= n ? Bytes(p + off, n - off) : Bytes(); }
};

inline uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd64(const uint8_t* p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// bounds-checked little-endian reader: once out of range, all reads return 0 and ok=false
struct Reader {
    Bytes b; size_t pos = 0; bool ok = true;
    Reader(Bytes bb) : b(bb) {}
    bool need(size_t k) { if (!ok || !b.has(pos, k)) { ok = false; return false; } return true; }
    uint8_t u8() { if (!need(1)) return 0; return b.p[pos++]; }
    uint16_t u16() { if (!need(2)) return 0; uint16_t v = rd16(b.p + pos); pos += 2; return v; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v = rd32(b.p + pos); pos += 4; return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v = rd64(b.p + pos); pos += 8; return v; }
    Bytes take(size_t k) { if (!need(k)) return Bytes(); Bytes r(b.p + pos, k); pos += k; return r; }
    void skip(size_t k) { if (need(k)) pos += k; }
    size_t left() const { return ok && pos <= b.n ? b.n - pos : 0; }
};

std::string strf(const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::string utf16le_to_utf8(const uint8_t* s, size_t nchars);
std::string utf16be_to_utf8(const uint8_t* s, size_t nchars);
std::string latin1_to_utf8(const uint8_t* s, size_t n);
std::string sanitize_utf8(const std::string& s); // replaces invalid sequences and control chars
void append_utf8(std::string& out, uint32_t cp);
std::string hexstr(const uint8_t* p, size_t n, char sep = 0, bool upper = false);
std::string human_size(uint64_t n);
std::string with_commas(uint64_t n);
std::string lower(std::string s);
bool ends_with(const std::string& s, const char* suf);
bool starts_with(const std::string& s, const char* pre);
std::string xml_escape(const std::string& s);
std::string trim(const std::string& s);
std::vector<std::string> split_lines(const std::string& s);
std::string dos_datetime(uint16_t date, uint16_t time);
const uint8_t* memfind(const uint8_t* hay, size_t hn, const void* needle, size_t nn);
