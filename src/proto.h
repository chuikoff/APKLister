// SPDX-License-Identifier: GPL-2.0-or-later
// Minimal protobuf wire-format reader.
#pragma once
#include "util.h"

struct PbField {
    uint32_t num = 0; int wt = 0; uint64_t v = 0; Bytes b;
    std::string str() const { return std::string((const char*)b.p, b.n); }
};
struct PbReader {
    Bytes d; size_t pos = 0; bool bad = false;
    explicit PbReader(Bytes b) : d(b) {}
    bool varint(uint64_t& v) {
        v = 0;
        for (int s = 0; s < 64; s += 7) {
            if (pos >= d.n) { bad = true; return false; }
            uint8_t c = d.p[pos++]; v |= (uint64_t)(c & 0x7F) << s;
            if (!(c & 0x80)) return true;
        }
        bad = true; return false;
    }
    bool next(PbField& f) {
        if (bad || pos >= d.n) return false;
        uint64_t key; if (!varint(key)) return false;
        f.num = (uint32_t)(key >> 3); f.wt = (int)(key & 7); f.v = 0; f.b = Bytes();
        switch (f.wt) {
        case 0: return varint(f.v);
        case 1: if (d.n - pos < 8) { bad = true; return false; } f.v = rd64(d.p + pos); pos += 8; return true;
        case 5: if (d.n - pos < 4) { bad = true; return false; } f.v = rd32(d.p + pos); pos += 4; return true;
        case 2: { uint64_t l; if (!varint(l) || l > d.n - pos) { bad = true; return false; } f.b = Bytes(d.p + pos, (size_t)l); pos += (size_t)l; return true; }
        default: bad = true; return false;
        }
    }
};
