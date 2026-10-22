// SPDX-License-Identifier: GPL-2.0-or-later
// Straightforward public-domain style implementations of MD5 (RFC 1321), SHA-1 and SHA-256 (FIPS 180-4).
#include "hash.h"
#include "util.h"
#include <cstring>

static inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
static inline uint32_t ror(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }
static inline uint32_t be32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

// ---- MD5
static const uint32_t K5[64] = {
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const int R5[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
Md5::Md5() : len(0), bl(0) { h[0] = 0x67452301; h[1] = 0xefcdab89; h[2] = 0x98badcfe; h[3] = 0x10325476; }
void Md5::block(const uint8_t* p) {
    uint32_t w[16]; for (int i = 0; i < 16; i++) w[i] = rd32(p + 4 * i);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (7 * i) & 15; }
        uint32_t t = d; d = c; c = b; b = b + rol(a + f + K5[i] + w[g], R5[i]); a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}
void Md5::update(const void* d, size_t n) {
    const uint8_t* p = (const uint8_t*)d; len += n;
    if (bl) { size_t k = 64 - bl; if (k > n) k = n; memcpy(buf + bl, p, k); bl += k; p += k; n -= k; if (bl == 64) { block(buf); bl = 0; } }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf, p, n); bl = n; }
}
void Md5::final(uint8_t out[16]) {
    uint64_t bits = len * 8; uint8_t pad = 0x80; update(&pad, 1); pad = 0;
    while (bl != 56) update(&pad, 1);
    uint8_t L[8]; for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (8 * i)); update(L, 8);
    for (int i = 0; i < 4; i++) for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(h[i] >> (8 * k));
}

// ---- SHA-1
Sha1::Sha1() : len(0), bl(0) { h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476; h[4] = 0xC3D2E1F0; }
void Sha1::block(const uint8_t* p) {
    uint32_t w[80]; for (int i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i]; e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
// expose private block() through friend-less trick: re-declare as public wrappers
void Sha1::update(const void* d, size_t n) {
    const uint8_t* p = (const uint8_t*)d; len += n;
    if (bl) { size_t k = 64 - bl; if (k > n) k = n; memcpy(buf + bl, p, k); bl += k; p += k; n -= k; if (bl == 64) { block(buf); bl = 0; } }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf, p, n); bl = n; }
}
void Sha1::final(uint8_t out[20]) {
    uint64_t bits = len * 8; uint8_t pad = 0x80; update(&pad, 1); pad = 0;
    while (bl != 56) update(&pad, 1);
    uint8_t L[8]; for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8 * i)); update(L, 8);
    for (int i = 0; i < 5; i++) for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(h[i] >> (24 - 8 * k));
}

// ---- SHA-256
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
Sha256::Sha256() : len(0), bl(0) {
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(h, iv, sizeof iv);
}
void Sha256::block(const uint8_t* p) {
    uint32_t w[64]; for (int i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25), ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22), mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
void Sha256::update(const void* d, size_t n) {
    const uint8_t* p = (const uint8_t*)d; len += n;
    if (bl) { size_t k = 64 - bl; if (k > n) k = n; memcpy(buf + bl, p, k); bl += k; p += k; n -= k; if (bl == 64) { block(buf); bl = 0; } }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf, p, n); bl = n; }
}
void Sha256::final(uint8_t out[32]) {
    uint64_t bits = len * 8; uint8_t pad = 0x80; update(&pad, 1); pad = 0;
    while (bl != 56) update(&pad, 1);
    uint8_t L[8]; for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8 * i)); update(L, 8);
    for (int i = 0; i < 8; i++) for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(h[i] >> (24 - 8 * k));
}

std::string md5_hex(const void* d, size_t n, char sep) { Md5 h; h.update(d, n); uint8_t o[16]; h.final(o); return hexstr(o, 16, sep, sep != 0); }
std::string sha1_hex(const void* d, size_t n, char sep) { Sha1 h; h.update(d, n); uint8_t o[20]; h.final(o); return hexstr(o, 20, sep, sep != 0); }
std::string sha256_hex(const void* d, size_t n, char sep) { Sha256 h; h.update(d, n); uint8_t o[32]; h.final(o); return hexstr(o, 32, sep, sep != 0); }

uint32_t crc32_calc(const void* d, size_t n, uint32_t crc) {
    static uint32_t T[256]; static bool init = false;
    if (!init) { for (uint32_t i = 0; i < 256; i++) { uint32_t c = i; for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1; T[i] = c; } init = true; }
    const uint8_t* p = (const uint8_t*)d; crc = ~crc;
    while (n--) crc = T[(crc ^ *p++) & 255] ^ (crc >> 8);
    return ~crc;
}
