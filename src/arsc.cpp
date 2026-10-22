// SPDX-License-Identifier: GPL-2.0-or-later
// resources.arsc (ResTable) reader with lazy entry lookup + resources.pb (aapt2 proto) reader.
#include "arsc.h"
#include "proto.h"
#include "xml.h"
#include <algorithm>
#include <memory>

std::string density_name(uint16_t d) {
    switch (d) {
    case 0: return "any"; case 120: return "ldpi"; case 160: return "mdpi"; case 213: return "tvdpi";
    case 240: return "hdpi"; case 320: return "xhdpi"; case 480: return "xxhdpi"; case 640: return "xxxhdpi";
    case 0xFFFE: return "anydpi"; case 0xFFFF: return "nodpi";
    default: return strf("%udpi", d);
    }
}

std::string Resources::best_string(uint32_t id, int depth) const {
    if (depth > 6) return std::string();
    auto vals = values(id);
    if (vals.empty()) return std::string();
    const ResValue* best = nullptr;
    for (auto& v : vals) if (v.cfg.locale.empty() && (v.cfg.desc == "default" || v.cfg.desc.empty())) { best = &v; break; }
    if (!best) for (auto& v : vals) if (v.cfg.locale.empty()) { best = &v; break; }
    if (!best) best = &vals[0];
    if (best->complex) return std::string();
    if (best->type == RT_REFERENCE && best->data && best->data != id) return best_string(best->data, depth + 1);
    if (best->type == RT_STRING || !best->str.empty()) return best->str;
    XAttr a; a.type = best->type; a.data = best->data;
    return format_value(a, this);
}
bool Resources::resolve_bool(uint32_t id, bool& out) const {
    auto vals = values(id);
    for (auto& v : vals) if (v.type == RT_BOOL) { out = v.data != 0; return true; }
    return false;
}

// ---------------------------------------------------------------- ARSC
static std::string unpack_lang(const uint8_t* b, char base) {
    if (!b[0] && !b[1]) return "";
    if (b[0] & 0x80) {
        char c[4];
        c[0] = (char)(base + (b[1] & 0x1f));
        c[1] = (char)(base + (((b[1] & 0xe0) >> 5) | ((b[0] & 0x03) << 3)));
        c[2] = (char)(base + ((b[0] & 0x7c) >> 2)); c[3] = 0;
        return c;
    }
    std::string s; s += (char)b[0]; if (b[1]) s += (char)b[1];
    return s;
}

static ResConfig parse_config(Bytes c) {
    ResConfig r;
    uint8_t z[64] = { 0 };
    size_t sz = c.n >= 4 ? rd32(c.p) : 0;
    if (sz > c.n) sz = c.n;
    if (sz > 64) sz = 64;
    memcpy(z, c.p, sz);
    std::vector<std::string> q;
    uint16_t mcc = rd16(z + 4), mnc = rd16(z + 6);
    if (mcc) q.push_back(strf("mcc%u", mcc));
    if (mnc) q.push_back(strf("mnc%u", mnc));
    std::string lang = unpack_lang(z + 8, 'a'), reg = unpack_lang(z + 10, '0');
    std::string script, variant;
    if (sz >= 40 && z[36]) script.assign((const char*)z + 36, strnlen((const char*)z + 36, 4));
    if (sz >= 48 && z[40]) variant.assign((const char*)z + 40, strnlen((const char*)z + 40, 8));
    if (!lang.empty()) {
        if (!script.empty() || !variant.empty() || lang.size() == 3) {
            r.locale = "b+" + lang; if (!script.empty()) r.locale += "+" + script; if (!reg.empty()) r.locale += "+" + reg; if (!variant.empty()) r.locale += "+" + variant;
        } else { r.locale = lang; if (!reg.empty()) r.locale += "-r" + reg; }
        q.push_back(r.locale);
    }
    uint8_t sl = z[28], ui = z[29], sl2 = z[48], cm = z[49], inflags = z[18];
    if ((sl & 0xC0) == 0x40) q.push_back("ldltr"); else if ((sl & 0xC0) == 0x80) q.push_back("ldrtl");
    uint16_t sw = rd16(z + 30), wdp = rd16(z + 32), hdp = rd16(z + 34);
    if (sw) q.push_back(strf("sw%udp", sw));
    if (wdp) q.push_back(strf("w%udp", wdp));
    if (hdp) q.push_back(strf("h%udp", hdp));
    static const char* ssz[] = { "", "small", "normal", "large", "xlarge" };
    if ((sl & 0x0F) && (sl & 0x0F) <= 4) q.push_back(ssz[sl & 0x0F]);
    if ((sl & 0x30) == 0x10) q.push_back("notlong"); else if ((sl & 0x30) == 0x20) q.push_back("long");
    if ((sl2 & 3) == 1) q.push_back("notround"); else if ((sl2 & 3) == 2) q.push_back("round");
    if ((cm & 3) == 1) q.push_back("nowidecg"); else if ((cm & 3) == 2) q.push_back("widecg");
    if ((cm & 0xC) == 4) q.push_back("lowdr"); else if ((cm & 0xC) == 8) q.push_back("highdr");
    static const char* ori[] = { "", "port", "land", "square" };
    if (z[12] && z[12] <= 3) q.push_back(ori[z[12]]);
    static const char* uit[] = { "", "", "desk", "car", "television", "appliance", "watch", "vrheadset" };
    if ((ui & 0x0F) >= 2 && (ui & 0x0F) <= 7) q.push_back(uit[ui & 0x0F]);
    if ((ui & 0x30) == 0x10) q.push_back("notnight"); else if ((ui & 0x30) == 0x20) q.push_back("night");
    r.density = rd16(z + 14);
    if (r.density) q.push_back(density_name(r.density));
    static const char* ts[] = { "", "notouch", "stylus", "finger" };
    if (z[13] && z[13] <= 3) q.push_back(ts[z[13]]);
    static const char* kh[] = { "", "keysexposed", "keyshidden", "keyssoft" };
    if (inflags & 3) q.push_back(kh[inflags & 3]);
    static const char* kb[] = { "", "nokeys", "qwerty", "12key" };
    if (z[16] && z[16] <= 3) q.push_back(kb[z[16]]);
    if ((inflags & 0xC) == 4) q.push_back("navexposed"); else if ((inflags & 0xC) == 8) q.push_back("navhidden");
    static const char* nv[] = { "", "nonav", "dpad", "trackball", "wheel" };
    if (z[17] && z[17] <= 4) q.push_back(nv[z[17]]);
    uint16_t sw_ = rd16(z + 20), sh_ = rd16(z + 22);
    if (sw_ && sh_) q.push_back(strf("%ux%u", sw_, sh_));
    r.sdk = rd16(z + 24);
    if (r.sdk) q.push_back(strf("v%u", r.sdk));
    if (q.empty()) r.desc = "default";
    else { for (size_t i = 0; i < q.size(); i++) { if (i) r.desc += "-"; r.desc += q[i]; } }
    return r;
}

namespace {
struct TypeChunk { uint8_t id = 0, flags = 0; Bytes c; uint32_t count = 0, start = 0; uint16_t hs = 0; ResConfig cfg; };
struct APkg {
    uint32_t id = 0; std::string name; uint32_t typeIdOffset = 0;
    std::unique_ptr<StringPool> types, keys;
    std::vector<TypeChunk> chunks;
    std::map<uint8_t, std::vector<size_t>> by_type;
};

class Arsc : public Resources {
public:
    StringPool global;
    std::vector<std::unique_ptr<APkg>> pkgs;
    mutable std::map<uint32_t, std::string> name_cache;

    const APkg* pkg(uint32_t id) const { for (auto& p : pkgs) if (p->id == id) return p.get(); return nullptr; }
    std::string type_name(const APkg& p, uint8_t t) const {
        if (!p.types || t == 0) return strf("type%u", t);
        uint32_t idx = (uint32_t)t - 1 - p.typeIdOffset;
        const std::string& s = p.types->get(idx);
        return s.empty() ? strf("type%u", t) : s;
    }
    // returns pointer to entry inside chunk (or null)
    const uint8_t* entry(const TypeChunk& tc, uint32_t e, size_t& avail) const {
        const uint8_t* base = tc.c.p; size_t n = tc.c.n; uint32_t off;
        if (tc.flags & 0x01) { // sparse
            uint32_t lo = 0, hi = tc.count; bool found = false; off = 0;
            while (lo < hi) {
                uint32_t m = (lo + hi) / 2; size_t pp = tc.hs + (size_t)m * 4;
                if (pp + 4 > n) return nullptr;
                uint16_t idx = rd16(base + pp);
                if (idx < e) lo = m + 1; else if (idx > e) hi = m; else { off = (uint32_t)rd16(base + pp + 2) * 4; found = true; break; }
            }
            if (!found) return nullptr;
        } else {
            if (e >= tc.count) return nullptr;
            if (tc.flags & 0x02) {
                size_t pp = tc.hs + (size_t)e * 2; if (pp + 2 > n) return nullptr;
                uint16_t v = rd16(base + pp); if (v == 0xFFFF) return nullptr; off = (uint32_t)v * 4;
            } else {
                size_t pp = tc.hs + (size_t)e * 4; if (pp + 4 > n) return nullptr;
                off = rd32(base + pp); if (off == 0xFFFFFFFF) return nullptr;
            }
        }
        size_t ep = (size_t)tc.start + off;
        if (ep + 8 > n) return nullptr;
        avail = n - ep;
        return base + ep;
    }
    bool decode(const APkg& p, const uint8_t* ent, size_t avail, uint32_t& key, ResValue& v) const {
        uint16_t size = rd16(ent), flags = rd16(ent + 2);
        if (flags & 0x08) { key = size; v.type = (uint8_t)(flags >> 8); v.data = rd32(ent + 4); }
        else {
            key = rd32(ent + 4);
            if (flags & 0x01) { v.complex = true; v.type = 0; }
            else {
                if ((size_t)size + 8 > avail) return false;
                v.type = ent[size + 3]; v.data = rd32(ent + size + 4);
            }
        }
        if (!v.complex && v.type == RT_STRING) v.str = global.get(v.data);
        (void)p;
        return true;
    }
    std::string ref_name(uint32_t id) const override {
        auto it = name_cache.find(id); if (it != name_cache.end()) return it->second;
        std::string r;
        const APkg* p = pkg(id >> 24);
        if (p) {
            uint8_t t = (id >> 16) & 0xFF; uint32_t e = id & 0xFFFF;
            auto bt = p->by_type.find(t);
            if (bt != p->by_type.end()) {
                for (size_t ci : bt->second) {
                    size_t av; const uint8_t* en = entry(p->chunks[ci], e, av);
                    if (!en) continue;
                    uint32_t key; ResValue v;
                    if (!decode(*p, en, av, key, v)) continue;
                    std::string k = p->keys ? p->keys->get(key) : std::string();
                    if (k.empty()) k = strf("0x%08x", id);
                    r = type_name(*p, t) + "/" + k;
                    if (!pkgs.empty() && p != pkgs[0].get() && !p->name.empty()) r = p->name + ":" + r;
                    break;
                }
            }
        }
        if (name_cache.size() < 100000) name_cache[id] = r;
        return r;
    }
    std::vector<ResValue> values(uint32_t id) const override {
        std::vector<ResValue> out;
        const APkg* p = pkg(id >> 24);
        if (!p) return out;
        uint8_t t = (id >> 16) & 0xFF; uint32_t e = id & 0xFFFF;
        auto bt = p->by_type.find(t);
        if (bt == p->by_type.end()) return out;
        for (size_t ci : bt->second) {
            size_t av; const uint8_t* en = entry(p->chunks[ci], e, av);
            if (!en) continue;
            uint32_t key; ResValue v; v.cfg = p->chunks[ci].cfg;
            if (decode(*p, en, av, key, v)) out.push_back(std::move(v));
            if (out.size() > 4096) break;
        }
        return out;
    }
};
}

Resources* load_arsc(Bytes d, std::string& err) {
    if (d.n < 12 || rd16(d.p) != 0x0002) { err = "not a resources.arsc table"; return nullptr; }
    auto r = std::make_unique<Arsc>();
    r->kind = "resources.arsc";
    uint16_t hs = rd16(d.p + 2); uint32_t total = rd32(d.p + 4);
    if (total > d.n) total = (uint32_t)d.n;
    size_t pos = hs;
    int guard = 0;
    while (pos + 8 <= total && guard++ < 1000) {
        uint16_t ct = rd16(d.p + pos), chs = rd16(d.p + pos + 2); uint32_t cs = rd32(d.p + pos + 4);
        if (cs < 8 || cs > total - pos) break;
        Bytes c(d.p + pos, cs);
        if (ct == 0x0001) { r->global.load(c); r->string_pool_size = r->global.count; }
        else if (ct == 0x0200 && cs >= 284 && chs >= 284 && chs <= cs) {
            auto p = std::make_unique<APkg>();
            p->id = rd32(c.p + 8);
            size_t nl = 0; while (nl < 128 && rd16(c.p + 12 + nl * 2)) nl++;
            p->name = utf16le_to_utf8(c.p + 12, nl);
            uint32_t tso = rd32(c.p + 268), kso = rd32(c.p + 276);
            if (chs >= 288) p->typeIdOffset = rd32(c.p + 284);
            if (tso && tso < cs) p->types = std::make_unique<StringPool>(c.from(tso));
            if (kso && kso < cs) p->keys = std::make_unique<StringPool>(c.from(kso));
            size_t q = chs; int g2 = 0;
            while (q + 8 <= cs && g2++ < 2000000) {
                uint16_t t2 = rd16(c.p + q), h2 = rd16(c.p + q + 2); uint32_t s2 = rd32(c.p + q + 4);
                if (s2 < 8 || s2 > cs - q) break;
                Bytes cc(c.p + q, s2);
                if (t2 == 0x0202 && s2 >= 16) {
                    uint8_t id = cc.p[8]; uint32_t ec = rd32(cc.p + 12);
                    std::string tn = r->type_name(*p, id);
                    size_t& slot = r->type_entries[tn]; if (ec > slot) slot = ec;
                } else if (t2 == 0x0201 && s2 >= 20 && h2 <= s2 && h2 >= 20) {
                    TypeChunk tc; tc.c = cc; tc.id = cc.p[8]; tc.flags = cc.p[9];
                    tc.count = rd32(cc.p + 12); tc.start = rd32(cc.p + 16); tc.hs = h2;
                    tc.cfg = parse_config(cc.sub(20, h2 - 20));
                    if (tc.start <= s2) {
                        r->config_count++;
                        r->config_counts[r->type_name(*p, tc.id)]++;
                        if (!tc.cfg.locale.empty()) r->locales.insert(tc.cfg.locale);
                        if (tc.cfg.density) r->densities.insert(tc.cfg.density);
                        // count present entries
                        size_t present = 0;
                        if (tc.flags & 0x01) present = tc.count;
                        else for (uint32_t i = 0; i < tc.count; i++) {
                            size_t pp = h2 + (size_t)i * ((tc.flags & 2) ? 2 : 4);
                            if (pp + 4 > s2) break;
                            if (tc.flags & 2) { if (rd16(cc.p + pp) != 0xFFFF) present++; }
                            else if (rd32(cc.p + pp) != 0xFFFFFFFF) present++;
                        }
                        r->total_values += present;
                        p->by_type[tc.id].push_back(p->chunks.size());
                        p->chunks.push_back(tc);
                    }
                }
                q += s2;
            }
            r->packages.push_back({ p->id, p->name });
            r->pkgs.push_back(std::move(p));
        }
        pos += cs;
    }
    if (r->pkgs.empty()) { err = "resources.arsc has no packages"; return nullptr; }
    return r.release();
}

// ---------------------------------------------------------------- resources.pb (AAB)
namespace {
struct PbEntry { std::string type, name; std::vector<ResValue> vals; };
class PbRes : public Resources {
public:
    std::map<uint32_t, PbEntry> m;
    std::string ref_name(uint32_t id) const override {
        auto it = m.find(id); if (it == m.end()) return std::string();
        return it->second.type + "/" + it->second.name;
    }
    std::vector<ResValue> values(uint32_t id) const override {
        auto it = m.find(id); if (it == m.end()) return {};
        return it->second.vals;
    }
};
uint32_t pb_id(Bytes b) { PbReader r(b); PbField f; while (r.next(f)) if (f.num == 1 && f.wt == 0) return (uint32_t)f.v; return 0; }
std::string pb_str1(Bytes b) { PbReader r(b); PbField f; while (r.next(f)) if (f.num == 1 && f.wt == 2) return f.str(); return ""; }
}

// decode aapt2 Item message into a value (shared with proto manifest decoding)
void pb_item_to_value(Bytes item, uint8_t& type, uint32_t& data, std::string& str, std::string& refname) {
    PbReader r(item); PbField f;
    while (r.next(f)) {
        if (f.wt != 2) continue;
        switch (f.num) {
        case 1: { type = RT_REFERENCE; PbReader q(f.b); PbField g; while (q.next(g)) { if (g.num == 2 && g.wt == 0) data = (uint32_t)g.v; else if (g.num == 3 && g.wt == 2) refname = g.str(); else if (g.num == 1 && g.wt == 0 && g.v == 1) type = RT_ATTRIBUTE; } break; }
        case 2: case 3: case 4: type = RT_STRING; str = pb_str1(f.b); break;
        case 5: type = RT_STRING; str = pb_str1(f.b); break;
        case 6: type = RT_STRING; str = "@id"; break;
        case 7: {
            PbReader q(f.b); PbField g;
            while (q.next(g)) {
                switch (g.num) {
                case 1: type = RT_NULL; data = 0; break;
                case 2: type = RT_NULL; data = 1; break;
                case 3: type = RT_FLOAT; data = (uint32_t)g.v; break;
                case 13: type = RT_DIMENSION; data = (uint32_t)g.v; break;
                case 14: type = RT_FRACTION; data = (uint32_t)g.v; break;
                case 6: type = RT_INT_DEC; data = (uint32_t)g.v; break;
                case 7: type = RT_INT_HEX; data = (uint32_t)g.v; break;
                case 8: type = RT_BOOL; data = g.v ? 0xFFFFFFFF : 0; break;
                case 9: type = RT_COLOR_ARGB8; data = (uint32_t)g.v; break;
                case 10: type = RT_COLOR_RGB8; data = (uint32_t)g.v; break;
                case 11: type = RT_COLOR_ARGB4; data = (uint32_t)g.v; break;
                case 12: type = RT_COLOR_RGB4; data = (uint32_t)g.v; break;
                }
            }
            break;
        }
        }
    }
}

static ResConfig pb_config(Bytes b) {
    ResConfig c; std::vector<std::string> q;
    PbReader r(b); PbField f; std::string night, ori; uint32_t sw = 0;
    while (r.next(f)) {
        if (f.num == 3 && f.wt == 2) c.locale = f.str();
        else if (f.num == 18 && f.wt == 0) c.density = (uint16_t)f.v;
        else if (f.num == 24 && f.wt == 0) c.sdk = (uint16_t)f.v;
        else if (f.num == 9 && f.wt == 0) sw = (uint32_t)f.v;
        else if (f.num == 17 && f.wt == 0) night = f.v == 1 ? "night" : f.v == 2 ? "notnight" : "";
        else if (f.num == 15 && f.wt == 0) ori = f.v == 1 ? "port" : f.v == 2 ? "land" : "";
    }
    if (!c.locale.empty()) q.push_back(c.locale);
    if (sw) q.push_back(strf("sw%udp", sw));
    if (!ori.empty()) q.push_back(ori);
    if (!night.empty()) q.push_back(night);
    if (c.density) q.push_back(density_name(c.density));
    if (c.sdk) q.push_back(strf("v%u", c.sdk));
    if (q.empty()) c.desc = "default"; else for (size_t i = 0; i < q.size(); i++) c.desc += (i ? "-" : "") + q[i];
    return c;
}

Resources* load_resources_pb(Bytes d, std::string& err) {
    auto r = std::make_unique<PbRes>();
    r->kind = "resources.pb (aapt2 proto)";
    std::set<std::string> cfgs;
    PbReader top(d); PbField f;
    while (top.next(f)) {
        if (f.num != 2 || f.wt != 2) continue;
        uint32_t pid = 0; std::string pname;
        PbReader pr(f.b); PbField g;
        std::vector<Bytes> types;
        while (pr.next(g)) {
            if (g.num == 1 && g.wt == 2) pid = pb_id(g.b);
            else if (g.num == 2 && g.wt == 2) pname = g.str();
            else if (g.num == 3 && g.wt == 2) types.push_back(g.b);
        }
        r->packages.push_back({ pid, pname });
        for (Bytes tb : types) {
            uint32_t tid = 0; std::string tname; std::vector<Bytes> ents;
            PbReader tr(tb); PbField h;
            while (tr.next(h)) {
                if (h.num == 1 && h.wt == 2) tid = pb_id(h.b);
                else if (h.num == 2 && h.wt == 2) tname = h.str();
                else if (h.num == 3 && h.wt == 2) ents.push_back(h.b);
            }
            r->type_entries[tname] += ents.size();
            for (Bytes eb : ents) {
                uint32_t eid = 0; PbEntry pe; pe.type = tname;
                PbReader er(eb); PbField k;
                while (er.next(k)) {
                    if (k.num == 1 && k.wt == 2) eid = pb_id(k.b);
                    else if (k.num == 2 && k.wt == 2) pe.name = k.str();
                    else if (k.num == 6 && k.wt == 2) {
                        ResValue v; Bytes valb;
                        PbReader cr(k.b); PbField m;
                        while (cr.next(m)) {
                            if (m.num == 1 && m.wt == 2) v.cfg = pb_config(m.b);
                            else if (m.num == 2 && m.wt == 2) valb = m.b;
                        }
                        if (v.cfg.desc.empty()) v.cfg.desc = "default";
                        PbReader vr(valb); PbField vv;
                        while (vr.next(vv)) {
                            if (vv.num == 4 && vv.wt == 2) { std::string rn; pb_item_to_value(vv.b, v.type, v.data, v.str, rn); }
                            else if (vv.num == 5) v.complex = true;
                        }
                        if (!v.cfg.locale.empty()) r->locales.insert(v.cfg.locale);
                        if (v.cfg.density) r->densities.insert(v.cfg.density);
                        cfgs.insert(tname + "|" + v.cfg.desc);
                        r->total_values++;
                        pe.vals.push_back(std::move(v));
                    }
                }
                uint32_t full = ((pid & 0xFF) << 24) | ((tid & 0xFF) << 16) | (eid & 0xFFFF);
                r->m[full] = std::move(pe);
            }
        }
    }
    if (top.bad && r->m.empty()) { err = "corrupt resources.pb"; return nullptr; }
    r->config_count = cfgs.size();
    for (auto& s : cfgs) r->config_counts[s.substr(0, s.find('|'))]++;
    return r.release();
}
