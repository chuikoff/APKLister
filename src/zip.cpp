// SPDX-License-Identifier: GPL-2.0-or-later
#include "zip.h"
#include "inflate.h"

bool Zip::open(Bytes d, std::string& err) {
    data = d;
    if (d.n < 22) { err = "file too small for ZIP"; return false; }
    size_t minpos = d.n > 22 + 65535 ? d.n - 22 - 65535 : 0;
    size_t e = (size_t)-1;
    for (size_t p = d.n - 22 + 1; p-- > minpos;) {
        if (rd32(d.p + p) == 0x06054b50) {
            uint16_t clen = rd16(d.p + p + 20);
            if (p + 22 + clen <= d.n) { e = p; break; }
        }
    }
    if (e == (size_t)-1) { err = "ZIP end of central directory not found"; return false; }
    eocd_off = e;
    uint64_t total = rd16(d.p + e + 10);
    cd_size = rd32(d.p + e + 12);
    cd_off = rd32(d.p + e + 16);
    uint16_t clen = rd16(d.p + e + 20);
    comment.assign((const char*)d.p + e + 22, clen);
    if (e >= 20 && rd32(d.p + e - 20) == 0x07064b50) {
        uint64_t z64 = rd64(d.p + e - 20 + 8);
        if (d.has((size_t)z64, 56) && z64 < d.n && rd32(d.p + z64) == 0x06064b50) {
            zip64 = true;
            total = rd64(d.p + z64 + 32);
            cd_size = rd64(d.p + z64 + 40);
            cd_off = rd64(d.p + z64 + 48);
        }
    }
    if (cd_off > d.n || cd_size > d.n - cd_off) { err = "central directory out of range"; return false; }
    Reader r(d.sub((size_t)cd_off, (size_t)cd_size));
    if (total > 2000000) total = 2000000;
    entries.reserve((size_t)total);
    while (r.left() >= 46) {
        if (rd32(r.b.p + r.pos) != 0x02014b50) break;
        r.skip(4);
        ZipEntry z;
        z.made_by = r.u16(); z.need = r.u16(); z.flags = r.u16(); z.method = r.u16();
        z.mtime = r.u16(); z.mdate = r.u16(); z.crc = r.u32();
        uint32_t cs = r.u32(), us = r.u32();
        uint16_t nl = r.u16(), el = r.u16(), cl = r.u16();
        uint16_t disk = r.u16(); (void)disk;
        z.internal_attr = r.u16(); z.external_attr = r.u32();
        uint32_t lho = r.u32();
        Bytes nm = r.take(nl), ex = r.take(el), cm = r.take(cl);
        if (!r.ok) break;
        z.name.assign((const char*)nm.p, nm.n);
        z.comment.assign((const char*)cm.p, cm.n);
        z.extra_len = el;
        z.csize = cs; z.usize = us; z.lho = lho;
        Reader x(ex);
        while (x.left() >= 4) {
            uint16_t id = x.u16(), sz = x.u16();
            Bytes v = x.take(sz); if (!x.ok) break;
            if (id == 0x0001) {
                Reader y(v); z.zip64 = true;
                if (us == 0xFFFFFFFF) z.usize = y.u64();
                if (cs == 0xFFFFFFFF) z.csize = y.u64();
                if (lho == 0xFFFFFFFF) z.lho = y.u64();
            }
        }
        index.emplace(z.name, entries.size());
        entries.push_back(std::move(z));
    }
    if (entries.empty() && total) { err = "central directory is corrupt"; return false; }
    return true;
}

const ZipEntry* Zip::find(const std::string& name) const {
    auto it = index.find(name);
    return it == index.end() ? nullptr : &entries[it->second];
}

uint64_t Zip::data_offset(const ZipEntry& e) const {
    if (!data.has((size_t)e.lho, 30) || e.lho > data.n) return 0;
    const uint8_t* p = data.p + e.lho;
    if (rd32(p) != 0x04034b50) return 0;
    uint64_t off = e.lho + 30 + rd16(p + 26) + rd16(p + 28);
    if (off > data.n) return 0;
    return off;
}

bool Zip::read(const ZipEntry& e, std::vector<uint8_t>& buf, Bytes& out, size_t limit, std::string& err, bool* partial) const {
    if (partial) *partial = false;
    if (e.flags & 1) { err = "entry is encrypted"; return false; }
    uint64_t off = data_offset(e);
    if (!off) { err = "bad local header"; return false; }
    if (e.csize > data.n - off) { err = "entry data out of range"; return false; }
    Bytes c((const uint8_t*)data.p + off, (size_t)e.csize);
    if (e.method == 0) {
        size_t n = c.n;
        if (n > limit) { n = limit; if (partial) *partial = true; }
        out = Bytes(c.p, n);
        return true;
    }
    if (e.method == 8) {
        size_t hint = e.usize > (1u << 30) ? (1u << 30) : (size_t)e.usize;
        if (!inflate_raw(c.p, c.n, buf, hint, limit, partial, &err)) return false;
        out = Bytes(buf);
        return true;
    }
    err = strf("unsupported compression method %u", e.method);
    return false;
}

bool Zip::read_small(const std::string& name, std::vector<uint8_t>& buf, size_t limit) const {
    const ZipEntry* e = find(name);
    if (!e) return false;
    Bytes out; std::string err;
    if (!read(*e, buf, out, limit, err)) return false;
    if (out.p != buf.data()) buf.assign(out.p, out.p + out.n);
    return true;
}
