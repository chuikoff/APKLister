// SPDX-License-Identifier: GPL-2.0-or-later
// Binary XML (AXML / ResXMLTree) decoder.
#include "xml.h"
#include "arsc.h"
#include <algorithm>

const char* ANDROID_NS = "http://schemas.android.com/apk/res/android";

static const struct { uint32_t id; const char* name; } kAttrs[] = {
#include "android_attrs.inc"
};
const char* android_attr_name(uint32_t id) {
    size_t lo = 0, hi = sizeof kAttrs / sizeof kAttrs[0];
    while (lo < hi) { size_t m = (lo + hi) / 2; if (kAttrs[m].id < id) lo = m + 1; else hi = m; }
    if (lo < sizeof kAttrs / sizeof kAttrs[0] && kAttrs[lo].id == id) return kAttrs[lo].name;
    return nullptr;
}

const XAttr* XNode::attr(const char* nm) const {
    for (auto& a : attrs) if (a.name == nm && (a.ns.empty() || a.ns == ANDROID_NS)) return &a;
    return nullptr;
}
std::vector<const XNode*> XNode::children(const char* nm) const {
    std::vector<const XNode*> v;
    for (auto& k : kids) if (!k->is_text && k->name == nm) v.push_back(k.get());
    return v;
}
const XNode* XNode::child(const char* nm) const {
    for (auto& k : kids) if (!k->is_text && k->name == nm) return k.get();
    return nullptr;
}

float u32_as_float(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }

std::string complex_to_string(uint32_t data, bool fraction) {
    static const float radix[4] = { 1.0f / (1 << 8), 1.0f / (1 << 15), 1.0f / (1 << 23), 1.0f / (1u << 31) };
    int32_t mant = (int32_t)(data & 0xFFFFFF00u) >> 8;
    float v = (float)mant * radix[(data >> 4) & 3];
    unsigned unit = data & 15;
    std::string num = strf("%g", v);
    if (fraction) return num + (unit == 0 ? "%" : unit == 1 ? "%p" : "?");
    static const char* u[] = { "px", "dp", "sp", "pt", "in", "mm" };
    return num + (unit < 6 ? u[unit] : "?");
}

std::string format_value(const XAttr& a, const Resources* res) {
    switch (a.type) {
    case RT_STRING: return a.str;
    case RT_NULL: return a.data == 1 ? "@empty" : "@null";
    case RT_REFERENCE: case RT_DYN_REF: {
        if (a.data == 0) return "@null";
        std::string n = res ? res->ref_name(a.data) : std::string();
        if (!n.empty()) return "@" + n;
        if (!a.ref_name.empty()) return (a.ref_name[0] == '@' ? "" : "@") + a.ref_name;
        if ((a.data >> 24) == 0x01) return strf("@android:0x%08x", a.data);
        return strf("@0x%08x", a.data);
    }
    case RT_ATTRIBUTE: case RT_DYN_ATTR: {
        if ((a.data >> 24) == 0x01) { const char* n = android_attr_name(a.data); if (n) return std::string("?android:attr/") + n; }
        std::string n = res ? res->ref_name(a.data) : std::string();
        if (!n.empty()) return "?" + n;
        return strf("?0x%08x", a.data);
    }
    case RT_FLOAT: return strf("%g", u32_as_float(a.data));
    case RT_DIMENSION: return complex_to_string(a.data, false);
    case RT_FRACTION: return complex_to_string(a.data, true);
    case RT_INT_DEC: return strf("%d", (int32_t)a.data);
    case RT_INT_HEX: return strf("0x%08x", a.data);
    case RT_BOOL: return a.data ? "true" : "false";
    case RT_COLOR_ARGB8: return strf("#%08x", a.data);
    case RT_COLOR_RGB8: return strf("#%06x", a.data & 0xFFFFFF);
    case RT_COLOR_ARGB4: return strf("#%04x", a.data & 0xFFFF);
    case RT_COLOR_RGB4: return strf("#%03x", a.data & 0xFFF);
    default: return a.str.empty() ? strf("(type 0x%02x) 0x%08x", a.type, a.data) : a.str;
    }
}

static void emit(const XNode& n, const XDoc& d, const Resources* res, int depth, std::string& o, bool root) {
    std::string ind((size_t)depth * 4, ' ');
    if (n.is_text) { o += ind + xml_escape(n.text) + "\n"; return; }
    std::string q;
    auto pre = [&](const std::string& uri) -> std::string {
        if (uri.empty()) return "";
        auto it = d.prefixes.find(uri);
        if (it != d.prefixes.end() && !it->second.empty()) return it->second + ":";
        if (uri == ANDROID_NS) return "android:";
        return "";
    };
    o += ind + "<" + pre(n.ns) + n.name;
    std::vector<std::pair<std::string, std::string>> decls = n.ns_decls;
    if (root && decls.empty()) for (auto& p : d.prefixes) decls.push_back({ p.second, p.first });
    bool multi = n.attrs.size() + decls.size() > 1;
    std::string aind = ind + "    ";
    for (auto& ns : decls) {
        o += multi ? "\n" + aind : " ";
        o += "xmlns" + (ns.first.empty() ? std::string() : ":" + ns.first) + "=\"" + xml_escape(ns.second) + "\"";
    }
    for (auto& a : n.attrs) {
        o += multi ? "\n" + aind : " ";
        std::string nm = a.name;
        if (nm.empty() && a.res_id) { const char* an = android_attr_name(a.res_id); nm = an ? an : strf("attr_0x%08x", a.res_id); }
        o += pre(a.ns) + nm + "=\"" + xml_escape(sanitize_utf8(format_value(a, res))) + "\"";
    }
    if (n.kids.empty()) { o += " />\n"; return; }
    o += ">\n";
    for (auto& k : n.kids) emit(*k, d, res, depth + 1, o, false);
    o += ind + "</" + pre(n.ns) + n.name + ">\n";
}

std::string to_xml(const XDoc& d, const Resources* res) {
    std::string o = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    if (d.root) emit(*d.root, d, res, 0, o, true);
    return o;
}

// ---------- AXML
StringPool::StringPool(Bytes chunk) { load(chunk); }
bool StringPool::load(Bytes c) {
    if (c.n < 28) return false;
    uint16_t hsz = rd16(c.p + 2); uint32_t sz = rd32(c.p + 4);
    if (sz > c.n || hsz < 28 || hsz > sz) return false;
    count = rd32(c.p + 8);
    uint32_t flags = rd32(c.p + 16), strStart = rd32(c.p + 20);
    utf8 = (flags & 0x100) != 0;
    if ((uint64_t)hsz + (uint64_t)count * 4 > sz) { count = 0; return false; }
    offsets = c.p + hsz;
    if (strStart > sz) { count = 0; return false; }
    strings = Bytes(c.p + strStart, sz - strStart);
    cache.assign(count, std::string());
    have.assign(count, 0);
    return true;
}
const std::string& StringPool::get(uint32_t i) const {
    static const std::string empty;
    if (i >= count) return empty;
    if (have[i]) return cache[i];
    have[i] = 1;
    uint32_t off = rd32(offsets + 4 * (size_t)i);
    std::string& out = cache[i];
    if (off >= strings.n) return out;
    const uint8_t* p = strings.p + off; size_t left = strings.n - off;
    if (utf8) {
        size_t k = 0;
        auto len8 = [&](size_t& v) -> bool {
            if (k >= left) return false;
            v = p[k++];
            if (v & 0x80) { if (k >= left) return false; v = ((v & 0x7F) << 8) | p[k++]; }
            return true;
        };
        size_t u16len, u8len;
        if (!len8(u16len) || !len8(u8len)) return out;
        if (u8len > left - k) u8len = left - k;
        out = sanitize_utf8(std::string((const char*)p + k, u8len));
    } else {
        if (left < 2) return out;
        size_t len = rd16(p), k = 2;
        if (len & 0x8000) { if (left < 4) return out; len = ((len & 0x7FFF) << 16) | rd16(p + 2); k = 4; }
        if (len > (left - k) / 2) len = (left - k) / 2;
        out = utf16le_to_utf8(p + k, len);
    }
    return out;
}

bool parse_axml(Bytes d, XDoc& doc) {
    if (d.n < 8) { doc.error = "AXML too small"; return false; }
    uint16_t t = rd16(d.p);
    if (t != 0x0003) { doc.error = strf("not a binary XML (chunk type 0x%04x)", t); return false; }
    uint16_t hsz = rd16(d.p + 2); uint32_t total = rd32(d.p + 4);
    if (total > d.n) total = (uint32_t)d.n;
    StringPool sp; std::vector<uint32_t> resmap;
    std::vector<XNode*> stack;
    std::vector<std::pair<std::string, std::string>> pending_ns;
    size_t pos = hsz < 8 ? 8 : hsz;
    int guard = 0;
    while (pos + 8 <= total && guard++ < 5000000) {
        uint16_t ct = rd16(d.p + pos), chs = rd16(d.p + pos + 2); uint32_t cs = rd32(d.p + pos + 4);
        if (cs < 8 || cs > total - pos) break;
        Bytes c(d.p + pos, cs);
        if (ct == 0x0001) { sp.load(c); doc.string_count = (int)sp.count; doc.utf8_pool = sp.utf8; }
        else if (ct == 0x0180) {
            for (size_t k = chs; k + 4 <= cs; k += 4) resmap.push_back(rd32(c.p + k));
            doc.res_map_count = (int)resmap.size();
        } else if (ct == 0x0100 && cs >= 24) {
            std::string prefix = sp.get(rd32(c.p + 16)), uri = sp.get(rd32(c.p + 20));
            if (!uri.empty() && !doc.prefixes.count(uri)) doc.prefixes[uri] = prefix;
            pending_ns.push_back({ prefix, uri });
        } else if (ct == 0x0102 && cs >= 36 && chs <= cs - 20) {
            auto n = std::make_unique<XNode>();
            n->line = (int)rd32(c.p + 8);
            const uint8_t* e = c.p + chs;
            uint32_t nsi = rd32(e), nmi = rd32(e + 4);
            uint16_t astart = rd16(e + 8), asize = rd16(e + 10), acount = rd16(e + 12);
            if (nsi != 0xFFFFFFFF) n->ns = sp.get(nsi);
            n->name = sp.get(nmi);
            n->ns_decls.swap(pending_ns);
            if (asize < 20) asize = 20;
            for (uint32_t i = 0; i < acount; i++) {
                size_t ao = chs + astart + (size_t)i * asize;
                if (ao + 20 > cs) break;
                const uint8_t* a = c.p + ao;
                XAttr x;
                uint32_t ans = rd32(a), anm = rd32(a + 4), araw = rd32(a + 8);
                if (ans != 0xFFFFFFFF) x.ns = sp.get(ans);
                x.name = sp.get(anm);
                if (anm < resmap.size()) x.res_id = resmap[anm];
                // obfuscated/stripped names: fall back to framework attr table
                if (x.res_id && (x.res_id >> 24) == 0x01) {
                    const char* an = android_attr_name(x.res_id);
                    if (an && (x.name.empty() || x.name != an)) { x.name = an; if (x.ns.empty()) x.ns = ANDROID_NS; }
                }
                x.type = a[15]; x.data = rd32(a + 16);
                if (araw != 0xFFFFFFFF) x.str = sp.get(araw);
                if (x.type == RT_STRING) x.str = sp.get(x.data);
                n->attrs.push_back(std::move(x));
            }
            XNode* raw = n.get();
            if (stack.empty()) { if (!doc.root) doc.root = std::move(n); else { doc.root->kids.push_back(std::move(n)); } }
            else stack.back()->kids.push_back(std::move(n));
            stack.push_back(raw);
            if (stack.size() > 512) { doc.error = "XML nesting too deep"; break; }
        } else if (ct == 0x0103) {
            if (!stack.empty()) stack.pop_back();
        } else if (ct == 0x0104 && cs >= 28 && !stack.empty()) {
            auto n = std::make_unique<XNode>();
            n->is_text = true; n->text = sp.get(rd32(c.p + chs));
            stack.back()->kids.push_back(std::move(n));
        }
        pos += cs;
    }
    if (!doc.root) { if (doc.error.empty()) doc.error = "no root element"; return false; }
    return true;
}
