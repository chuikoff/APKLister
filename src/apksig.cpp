// SPDX-License-Identifier: GPL-2.0-or-later
// APK Signing Block (v2/v3/v3.1, source stamp) + JAR (v1) signature reader. No verification.
#include "apksig.h"
#include "hash.h"

const char* sig_block_name(uint32_t id) {
    switch (id) {
    case 0x7109871a: return "APK Signature Scheme v2";
    case 0xf05368c0: return "APK Signature Scheme v3";
    case 0x1b93ad61: return "APK Signature Scheme v3.1";
    case 0x42726577: return "Verity padding";
    case 0x6dff800d: return "Source stamp v2";
    case 0x2b09189e: return "Source stamp v1";
    case 0x504b4453: return "Dependency metadata (AGP, encrypted)";
    case 0x2146444e: return "Google Play metadata (frosting)";
    case 0x71777777: return "Walle channel info";
    case 0xff3b5998: return "Zero block (protection)";
    case 0x5ee6dabc: return "Unknown (Huawei?)";
    default: return "Unknown";
    }
}
std::string sig_alg_name(uint32_t id) {
    switch (id) {
    case 0x0101: return "RSASSA-PSS/SHA-256";
    case 0x0102: return "RSASSA-PSS/SHA-512";
    case 0x0103: return "RSASSA-PKCS1-v1_5/SHA-256";
    case 0x0104: return "RSASSA-PKCS1-v1_5/SHA-512";
    case 0x0201: return "ECDSA/SHA-256";
    case 0x0202: return "ECDSA/SHA-512";
    case 0x0301: return "DSA/SHA-256";
    case 0x0421: return "RSA-PKCS1/SHA-256 (verity)";
    case 0x0423: return "ECDSA/SHA-256 (verity)";
    case 0x0425: return "DSA/SHA-256 (verity)";
    default: return strf("0x%04x", id);
    }
}

static Bytes lp(Reader& r) { uint32_t n = r.u32(); return r.take(n); }

static void parse_lineage(Bytes v, std::vector<CertInfo>& out) {
    Reader r(v); r.u32(); // version
    int g = 0;
    while (r.left() >= 4 && g++ < 64) {
        Bytes node = lp(r); if (!r.ok) break;
        Reader n(node); Bytes sd = lp(n); Reader s(sd); Bytes cert = lp(s);
        if (cert.n) out.push_back(parse_cert(cert));
    }
}

static void parse_scheme(Bytes v, bool v3, std::vector<SigSigner>& out) {
    Reader r(v); Bytes signers = lp(r);
    Reader rs(signers); int g = 0;
    while (rs.left() >= 4 && g++ < 32) {
        Bytes sb = lp(rs); if (!rs.ok) break;
        SigSigner s; Reader q(sb);
        Bytes sd = lp(q);
        if (v3) { s.min_sdk = (int)q.u32(); s.max_sdk = (int)q.u32(); }
        Bytes sigs = lp(q), pk = lp(q);
        if (!q.ok) s.error = "truncated signer";
        if (pk.n) s.pubkey_sha256 = sha256_hex(pk.p, pk.n, ':');
        Reader sr(sigs); while (sr.left() >= 4) { Bytes x = lp(sr); if (!sr.ok) break; Reader xr(x); s.sig_algs.push_back(xr.u32()); }
        Reader d(sd);
        Bytes digests = lp(d), certs = lp(d);
        if (v3) { d.u32(); d.u32(); }
        Bytes attrs = lp(d);
        Reader dr(digests); while (dr.left() >= 4) { Bytes x = lp(dr); if (!dr.ok) break; Reader xr(x); s.digest_algs.push_back(xr.u32()); }
        Reader cr(certs); int gc = 0; while (cr.left() >= 4 && gc++ < 32) { Bytes c = lp(cr); if (!cr.ok) break; s.certs.push_back(parse_cert(c)); }
        Reader ar(attrs); int ga = 0;
        while (ar.left() >= 8 && ga++ < 64) {
            Bytes a = lp(ar); if (!ar.ok || a.n < 4) break;
            uint32_t id = rd32(a.p); s.attrs.push_back({ id, a.n - 4 });
            if (id == 0x3ba06f8c) parse_lineage(a.from(4), s.lineage);
        }
        out.push_back(std::move(s));
    }
}

static std::vector<std::pair<std::string, std::string>> mf_headers(const std::vector<uint8_t>& b, size_t* entries) {
    std::vector<std::pair<std::string, std::string>> h;
    std::string s((const char*)b.data(), b.size());
    auto lines = split_lines(s);
    bool main = true; size_t n = 0;
    for (size_t i = 0; i < lines.size(); i++) {
        const std::string& l = lines[i];
        if (l.empty()) { main = false; continue; }
        if (starts_with(l, "Name:")) n++;
        if (!main) continue;
        if (l[0] == ' ' && !h.empty()) { h.back().second += l.substr(1); continue; }
        size_t c = l.find(':'); if (c == std::string::npos) continue;
        h.push_back({ l.substr(0, c), trim(l.substr(c + 1)) });
        if (h.size() > 64) break;
    }
    if (entries) *entries = n;
    return h;
}

void analyze_signatures(const Zip& z, const std::string& prefix, SigInfo& si) {
    for (auto& p : z.sig_pairs) {
        si.blocks.push_back({ p.id, p.value.n });
        if (p.id == 0x7109871a) { si.v2 = true; parse_scheme(p.value, false, si.v2s); }
        else if (p.id == 0xf05368c0) { si.v3 = true; parse_scheme(p.value, true, si.v3s); }
        else if (p.id == 0x1b93ad61) { si.v31 = true; parse_scheme(p.value, true, si.v31s); }
        else if (p.id == 0x6dff800d || p.id == 0x2b09189e) {
            si.stamp = true;
            Reader r(p.value); Bytes a = lp(r);
            CertInfo c = parse_cert(a);
            if (!c.ok) { Reader q(a); Bytes b = lp(q); c = parse_cert(b); }
            if (c.ok) si.stamp_certs.push_back(c);
        }
    }
    std::vector<uint8_t> buf;
    if (z.read_small(prefix + "stamp-cert-sha256", buf, 4096)) si.stamp_file_sha256 = hexstr(buf.data(), buf.size());
    std::string mi = prefix + "META-INF/";
    for (auto& e : z.entries) {
        if (!starts_with(e.name, mi.c_str())) continue;
        std::string rest = e.name.substr(mi.size());
        if (rest.find('/') != std::string::npos) continue;
        std::string up = rest; for (auto& c : up) c = (char)toupper((unsigned char)c);
        if (up == "MANIFEST.MF") {
            if (z.read_small(e.name, buf, 32u << 20)) si.manifest_headers = mf_headers(buf, &si.manifest_entries);
            continue;
        }
        bool sf = ends_with(up, ".SF"), blk = ends_with(up, ".RSA") || ends_with(up, ".DSA") || ends_with(up, ".EC");
        if (!sf && !blk) continue;
        V1File f; f.name = e.name; f.kind = sf ? "signature file" : "signature block";
        if (z.read_small(e.name, buf, 8u << 20)) {
            if (sf) {
                f.headers = mf_headers(buf, nullptr);
            } else {
                std::vector<Bytes> certs;
                if (pkcs7_certs(Bytes(buf), certs, f.error)) for (auto& c : certs) f.certs.push_back(parse_cert(c));
                si.v1 = true;
            }
        } else f.error = "cannot read";
        si.v1files.push_back(std::move(f));
    }
}
