// SPDX-License-Identifier: GPL-2.0-or-later
// Table-driven DEFLATE decoder written for this project; fully bounds checked.
#include "inflate.h"

namespace {
struct Huff { std::vector<uint16_t> tab; int maxlen = 0; };

bool build(Huff& h, const uint8_t* lens, int n) {
    int count[16] = { 0 };
    for (int i = 0; i < n; i++) { if (lens[i] > 15) return false; count[lens[i]]++; }
    count[0] = 0;
    int left = 1;
    for (int l = 1; l < 16; l++) { left <<= 1; left -= count[l]; if (left < 0) return false; }
    int maxlen = 0; for (int l = 1; l < 16; l++) if (count[l]) maxlen = l;
    if (maxlen == 0) maxlen = 1;
    int next[16] = { 0 }; int code = 0;
    for (int l = 1; l < 16; l++) { code = (code + count[l - 1]) << 1; next[l] = code; }
    h.maxlen = maxlen; h.tab.assign((size_t)1 << maxlen, 0);
    for (int s = 0; s < n; s++) {
        int l = lens[s]; if (!l) continue;
        int c = next[l]++; int r = 0;
        for (int i = 0; i < l; i++) { r = (r << 1) | (c & 1); c >>= 1; }
        for (int k = r; k < (1 << maxlen); k += 1 << l) h.tab[k] = (uint16_t)((s << 4) | l);
    }
    return true;
}

struct St {
    const uint8_t* src; size_t n, pos = 0; uint64_t bb = 0; int bc = 0; int pad = 0; bool bad = false;
    void fill() { while (bc <= 56) { uint64_t b; if (pos < n) b = src[pos++]; else { b = 0; pad++; } bb |= b << bc; bc += 8; } }
    uint32_t bits(int k) { if (bc < k) fill(); uint32_t v = (uint32_t)(bb & ((1ull << k) - 1)); bb >>= k; bc -= k; if (bc < pad * 8) bad = true; return v; }
    int sym(const Huff& h) {
        if (bc < h.maxlen) fill();
        uint16_t e = h.tab[bb & ((1u << h.maxlen) - 1)]; int l = e & 15;
        if (!l) { bad = true; return -1; }
        bb >>= l; bc -= l; if (bc < pad * 8) bad = true;
        return e >> 4;
    }
};
const uint16_t LBASE[29] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
const uint8_t LEXT[29] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
const uint16_t DBASE[30] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
const uint8_t DEXT[30] = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };
}

bool inflate_raw(const uint8_t* src, size_t n, std::vector<uint8_t>& out, size_t hint, size_t limit, bool* partial, std::string* err) {
    St s; s.src = src; s.n = n;
    if (partial) *partial = false;
    out.clear();
    try {
        out.reserve(hint < limit ? hint : limit);
    } catch (...) { if (err) *err = "out of memory"; return false; }
    auto fail = [&](const char* m) { if (err) *err = m; return false; };
    Huff fixL, fixD; bool fixBuilt = false;
    Huff L, D;
    int final_ = 0;
    try {
    do {
        final_ = (int)s.bits(1); int type = (int)s.bits(2);
        if (s.bad) return fail("truncated deflate stream");
        if (type == 0) {
            int drop = s.bc & 7; s.bb >>= drop; s.bc -= drop;
            int inbuf = s.bc / 8;
            if (s.pad > inbuf) return fail("truncated stored block");
            s.pos -= (size_t)(inbuf - s.pad); s.bb = 0; s.bc = 0; s.pad = 0;
            if (n - s.pos < 4) return fail("truncated stored block");
            unsigned len = src[s.pos] | (src[s.pos + 1] << 8), nlen = src[s.pos + 2] | (src[s.pos + 3] << 8);
            s.pos += 4;
            if ((len ^ 0xFFFF) != nlen) return fail("bad stored block length");
            if (n - s.pos < len) return fail("truncated stored block");
            size_t take = len; bool stop = false;
            if (out.size() + take >= limit) { take = limit - out.size(); stop = true; }
            out.insert(out.end(), src + s.pos, src + s.pos + take); s.pos += len;
            if (stop) { if (partial) *partial = true; return true; }
            continue;
        }
        const Huff* pl; const Huff* pd;
        if (type == 1) {
            if (!fixBuilt) {
                uint8_t l[288]; int i = 0;
                for (; i < 144; i++) l[i] = 8;
                for (; i < 256; i++) l[i] = 9;
                for (; i < 280; i++) l[i] = 7;
                for (; i < 288; i++) l[i] = 8;
                build(fixL, l, 288); uint8_t d[30]; for (i = 0; i < 30; i++) d[i] = 5; build(fixD, d, 30); fixBuilt = true;
            }
            pl = &fixL; pd = &fixD;
        } else if (type == 2) {
            int hlit = (int)s.bits(5) + 257, hdist = (int)s.bits(5) + 1, hclen = (int)s.bits(4) + 4;
            if (hlit > 286 || hdist > 30) return fail("bad dynamic header");
            static const uint8_t ord[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
            uint8_t cl[19] = { 0 };
            for (int i = 0; i < hclen; i++) cl[ord[i]] = (uint8_t)s.bits(3);
            Huff C; if (!build(C, cl, 19)) return fail("bad code lengths");
            uint8_t lens[320] = { 0 }; int i = 0;
            while (i < hlit + hdist) {
                int sy = s.sym(C); if (sy < 0 || s.bad) return fail("bad code length symbol");
                if (sy < 16) lens[i++] = (uint8_t)sy;
                else {
                    int rep, val = 0;
                    if (sy == 16) { if (!i) return fail("repeat with no previous"); val = lens[i - 1]; rep = 3 + (int)s.bits(2); }
                    else if (sy == 17) rep = 3 + (int)s.bits(3);
                    else rep = 11 + (int)s.bits(7);
                    if (i + rep > hlit + hdist) return fail("too many lengths");
                    while (rep--) lens[i++] = (uint8_t)val;
                }
            }
            if (!lens[256]) return fail("no end-of-block code");
            if (!build(L, lens, hlit) || !build(D, lens + hlit, hdist)) return fail("bad huffman table");
            pl = &L; pd = &D;
        } else return fail("invalid block type");
        for (;;) {
            int sy = s.sym(*pl);
            if (sy < 0 || s.bad) return fail("corrupt data");
            if (sy < 256) {
                out.push_back((uint8_t)sy);
                if (out.size() >= limit) { if (partial) *partial = true; return true; }
            } else if (sy == 256) break;
            else {
                sy -= 257; if (sy >= 29) return fail("bad length symbol");
                size_t len = LBASE[sy] + s.bits(LEXT[sy]);
                int ds = s.sym(*pd); if (ds < 0 || ds >= 30) return fail("bad distance symbol");
                size_t dist = DBASE[ds] + s.bits(DEXT[ds]);
                if (s.bad) return fail("truncated");
                if (dist > out.size()) return fail("distance too far back");
                bool stop = false;
                if (out.size() + len >= limit) { len = limit - out.size(); stop = true; }
                size_t from = out.size() - dist;
                for (size_t k = 0; k < len; k++) out.push_back(out[from + k]);
                if (stop) { if (partial) *partial = true; return true; }
            }
        }
    } while (!final_);
    } catch (...) { return fail("out of memory"); }
    return true;
}
