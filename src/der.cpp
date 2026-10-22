// SPDX-License-Identifier: GPL-2.0-or-later
// Small ASN.1 DER/BER reader for X.509 certificates and PKCS#7 SignedData.
#include "der.h"
#include "hash.h"

bool der_next(Bytes b, Tlv& t, int depth) {
    if (b.n < 2 || depth > 64) return false;
    t.tag = b.p[0];
    if ((t.tag & 0x1F) == 0x1F) return false; // high tag numbers not used here
    size_t pos = 2; uint8_t l0 = b.p[1];
    if (l0 < 0x80) {
        if (l0 > b.n - 2) return false;
        t.content = Bytes(b.p + 2, l0);
    } else if (l0 == 0x80) {
        if (!(t.tag & 0x20)) return false;
        size_t p = 2;
        for (;;) {
            if (p + 2 > b.n) return false;
            if (b.p[p] == 0 && b.p[p + 1] == 0) break;
            Tlv c; if (!der_next(b.from(p), c, depth + 1)) return false;
            p += c.whole.n;
        }
        t.content = Bytes(b.p + 2, p - 2);
        t.whole = Bytes(b.p, p + 2);
        return true;
    } else {
        int k = l0 & 0x7F; if (k > 4 || b.n < 2 + (size_t)k) return false;
        size_t len = 0; for (int i = 0; i < k; i++) len = (len << 8) | b.p[2 + i];
        pos = 2 + k;
        if (len > b.n - pos) return false;
        t.content = Bytes(b.p + pos, len);
    }
    t.whole = Bytes(b.p, (size_t)(t.content.p - b.p) + t.content.n);
    return true;
}

std::vector<Tlv> der_children(Bytes c) {
    std::vector<Tlv> v; size_t p = 0;
    while (p + 2 <= c.n) {
        if (c.p[p] == 0 && c.p[p + 1] == 0) break;
        Tlv t; if (!der_next(c.from(p), t)) break;
        v.push_back(t); p += t.whole.n;
        if (v.size() > 10000) break;
    }
    return v;
}

std::string oid_to_string(Bytes c) {
    if (!c.n) return "";
    std::string s = strf("%u.%u", c.p[0] / 40 > 2 ? 2 : c.p[0] / 40, c.p[0] / 40 > 2 ? c.p[0] - 80 : c.p[0] % 40);
    uint64_t v = 0;
    for (size_t i = 1; i < c.n; i++) {
        v = (v << 7) | (c.p[i] & 0x7F);
        if (!(c.p[i] & 0x80)) { s += strf(".%llu", (unsigned long long)v); v = 0; }
    }
    return s;
}

static const char* oid_name(const std::string& o) {
    static const struct { const char* oid; const char* n; } t[] = {
        {"2.5.4.3","CN"},{"2.5.4.4","SN"},{"2.5.4.5","SERIALNUMBER"},{"2.5.4.6","C"},{"2.5.4.7","L"},{"2.5.4.8","ST"},
        {"2.5.4.9","STREET"},{"2.5.4.10","O"},{"2.5.4.11","OU"},{"2.5.4.12","T"},{"2.5.4.42","GN"},{"2.5.4.43","I"},
        {"2.5.4.17","postalCode"},{"2.5.4.46","dnQualifier"},{"0.9.2342.19200300.100.1.25","DC"},{"0.9.2342.19200300.100.1.1","UID"},
        {"1.2.840.113549.1.9.1","E"},
        {"1.2.840.113549.1.1.1","RSA"},{"1.2.840.10045.2.1","EC"},{"1.2.840.10040.4.1","DSA"},{"1.3.101.112","Ed25519"},{"1.3.101.113","Ed448"},
        {"1.2.840.113549.1.1.4","MD5withRSA"},{"1.2.840.113549.1.1.5","SHA1withRSA"},{"1.2.840.113549.1.1.11","SHA256withRSA"},
        {"1.2.840.113549.1.1.12","SHA384withRSA"},{"1.2.840.113549.1.1.13","SHA512withRSA"},{"1.2.840.113549.1.1.14","SHA224withRSA"},
        {"1.2.840.113549.1.1.10","RSASSA-PSS"},
        {"1.2.840.10045.4.1","SHA1withECDSA"},{"1.2.840.10045.4.3.2","SHA256withECDSA"},{"1.2.840.10045.4.3.3","SHA384withECDSA"},{"1.2.840.10045.4.3.4","SHA512withECDSA"},
        {"1.2.840.10040.4.3","SHA1withDSA"},{"2.16.840.1.101.3.4.3.2","SHA256withDSA"},{"2.16.840.1.101.3.4.3.1","SHA224withDSA"},
        {"1.2.840.10045.3.1.7","P-256 (secp256r1)"},{"1.3.132.0.34","P-384 (secp384r1)"},{"1.3.132.0.35","P-521 (secp521r1)"},{"1.3.132.0.10","secp256k1"},
    };
    for (auto& e : t) if (o == e.oid) return e.n;
    return nullptr;
}

static std::string der_string(const Tlv& t) {
    switch (t.tag) {
    case 0x0C: case 0x13: case 0x16: case 0x12: case 0x1A: return sanitize_utf8(std::string((const char*)t.content.p, t.content.n));
    case 0x14: return latin1_to_utf8(t.content.p, t.content.n);
    case 0x1E: return utf16be_to_utf8(t.content.p, t.content.n / 2);
    case 0x1C: { std::string o; for (size_t i = 0; i + 4 <= t.content.n; i += 4) append_utf8(o, ((uint32_t)t.content.p[i] << 24) | (t.content.p[i + 1] << 16) | (t.content.p[i + 2] << 8) | t.content.p[i + 3]); return o; }
    default: return "#" + hexstr(t.content.p, t.content.n);
    }
}

static std::string parse_name(Bytes c) {
    // RFC 4514 order (most specific first, like apksigner/keytool): reverse the RDN sequence
    std::vector<std::string> rdns;
    for (auto& set : der_children(c)) {
        for (auto& atv : der_children(set.content)) {
            auto kv = der_children(atv.content);
            if (kv.size() < 2 || kv[0].tag != 0x06) continue;
            std::string oid = oid_to_string(kv[0].content);
            const char* n = oid_name(oid);
            std::string val = der_string(kv[1]);
            std::string esc;
            for (char ch : val) { if (ch == ',' || ch == '+' || ch == '"' || ch == '\\' || ch == ';' || ch == '<' || ch == '>') esc += '\\'; esc += ch; }
            rdns.push_back((n ? n : oid) + std::string("=") + esc);
        }
    }
    std::string out;
    for (size_t i = rdns.size(); i-- > 0;) { if (!out.empty()) out += ", "; out += rdns[i]; }
    return out;
}

static std::string parse_time(const Tlv& t) {
    std::string s((const char*)t.content.p, t.content.n);
    if (t.tag == 0x17 && s.size() >= 12) {
        int yy = (s[0] - '0') * 10 + (s[1] - '0');
        return strf("%04d-%c%c-%c%c %c%c:%c%c:%s UTC", yy < 50 ? 2000 + yy : 1900 + yy, s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s.size() >= 13 && s[10] != 'Z' ? s.substr(10, 2).c_str() : "00");
    }
    if (t.tag == 0x18 && s.size() >= 14)
        return s.substr(0, 4) + "-" + s.substr(4, 2) + "-" + s.substr(6, 2) + " " + s.substr(8, 2) + ":" + s.substr(10, 2) + ":" + s.substr(12, 2) + " UTC";
    return sanitize_utf8(s);
}

static int int_bits(Bytes c) {
    size_t i = 0; while (i < c.n && c.p[i] == 0) i++;
    if (i == c.n) return 0;
    int b = (int)(c.n - i) * 8; uint8_t top = c.p[i];
    while (!(top & 0x80)) { b--; top <<= 1; }
    return b;
}

static std::string big_dec(Bytes c) {
    std::vector<uint8_t> num(c.p, c.p + c.n);
    if (num.size() > 64) return "";
    std::string d;
    bool zero = false;
    while (!zero) {
        uint32_t rem = 0; zero = true;
        for (auto& b : num) { uint32_t cur = (rem << 8) | b; b = (uint8_t)(cur / 10); rem = cur % 10; if (b) zero = false; }
        d += (char)('0' + rem);
    }
    std::string r(d.rbegin(), d.rend());
    size_t nz = r.find_first_not_of('0'); return nz == std::string::npos ? "0" : r.substr(nz);
}

CertInfo parse_cert(Bytes der) {
    CertInfo ci; ci.der_size = der.n;
    Tlv cert; if (!der_next(der, cert) || cert.tag != 0x30) { ci.error = "not a DER certificate"; return ci; }
    ci.md5 = md5_hex(cert.whole.p, cert.whole.n, ':');
    ci.sha1 = sha1_hex(cert.whole.p, cert.whole.n, ':');
    ci.sha256 = sha256_hex(cert.whole.p, cert.whole.n, ':');
    auto top = der_children(cert.content);
    if (top.size() < 3) { ci.error = "truncated certificate"; return ci; }
    auto tbs = der_children(top[0].content);
    size_t i = 0;
    if (i < tbs.size() && tbs[i].tag == 0xA0) { auto v = der_children(tbs[i].content); if (!v.empty() && v[0].content.n) ci.version = v[0].content.p[v[0].content.n - 1] + 1; i++; }
    if (i < tbs.size() && tbs[i].tag == 0x02) {
        Bytes s = tbs[i].content;
        Bytes st = s; while (st.n > 1 && st.p[0] == 0) { st.p++; st.n--; }
        ci.serial_hex = hexstr(st.p, st.n); ci.serial_dec = big_dec(s); i++;
    }
    if (i < tbs.size()) i++; // signature alg (inner)
    if (i < tbs.size()) { ci.issuer = parse_name(tbs[i].content); i++; }
    if (i < tbs.size()) { auto v = der_children(tbs[i].content); if (v.size() >= 2) { ci.not_before = parse_time(v[0]); ci.not_after = parse_time(v[1]); } i++; }
    if (i < tbs.size()) { ci.subject = parse_name(tbs[i].content); i++; }
    if (i < tbs.size()) {
        const Tlv& spki = tbs[i];
        ci.pubkey_sha256 = sha256_hex(spki.whole.p, spki.whole.n, ':');
        auto sp = der_children(spki.content);
        if (sp.size() >= 2) {
            auto alg = der_children(sp[0].content);
            std::string oid = alg.size() ? oid_to_string(alg[0].content) : "";
            const char* nm = oid_name(oid);
            ci.key_alg = nm ? nm : oid;
            Bytes bits = sp[1].content; if (bits.n) { bits.p++; bits.n--; }
            if (ci.key_alg == "RSA") {
                Tlv k; if (der_next(bits, k)) { auto kk = der_children(k.content); if (!kk.empty()) ci.key_bits = int_bits(kk[0].content); }
            } else if (ci.key_alg == "EC") {
                if (alg.size() >= 2 && alg[1].tag == 0x06) { std::string c = oid_to_string(alg[1].content); const char* cn = oid_name(c); ci.curve = cn ? cn : c; }
                ci.key_bits = bits.n > 1 ? (int)((bits.n - 1) / 2 * 8) : 0;
            } else if (ci.key_alg == "DSA") {
                if (alg.size() >= 2) { auto pqg = der_children(alg[1].content); if (!pqg.empty()) ci.key_bits = int_bits(pqg[0].content); }
            } else if (ci.key_alg == "Ed25519") ci.key_bits = 256;
        }
    }
    {
        auto sa = der_children(top[1].content);
        std::string oid = sa.size() ? oid_to_string(sa[0].content) : "";
        const char* nm = oid_name(oid); ci.sig_alg = nm ? nm : oid;
    }
    ci.self_signed = !ci.subject.empty() && ci.subject == ci.issuer;
    ci.ok = true;
    return ci;
}

bool pkcs7_certs(Bytes d, std::vector<Bytes>& certs, std::string& err) {
    Tlv ci; if (!der_next(d, ci) || ci.tag != 0x30) { err = "not a PKCS#7 structure"; return false; }
    auto top = der_children(ci.content);
    if (top.size() < 2 || top[0].tag != 0x06 || oid_to_string(top[0].content) != "1.2.840.113549.1.7.2") { err = "not PKCS#7 SignedData"; return false; }
    auto ex = der_children(top[1].content);
    if (ex.empty()) { err = "empty SignedData"; return false; }
    auto sd = der_children(ex[0].content);
    for (auto& t : sd) {
        if (t.tag == 0xA0) { // [0] IMPLICIT certificates
            for (auto& c : der_children(t.content)) if (c.tag == 0x30) certs.push_back(c.whole);
        }
    }
    if (certs.empty()) { err = "no certificates in SignedData"; return false; }
    return true;
}
