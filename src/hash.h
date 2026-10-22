// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

struct Md5 { uint32_t h[4]; uint64_t len; uint8_t buf[64]; size_t bl; Md5(); void update(const void* d, size_t n); void final(uint8_t out[16]); private: void block(const uint8_t* p); };
struct Sha1 { uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t bl; Sha1(); void update(const void* d, size_t n); void final(uint8_t out[20]); private: void block(const uint8_t* p); };
struct Sha256 { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t bl; Sha256(); void update(const void* d, size_t n); void final(uint8_t out[32]); private: void block(const uint8_t* p); };

std::string md5_hex(const void* d, size_t n, char sep = 0);
std::string sha1_hex(const void* d, size_t n, char sep = 0);
std::string sha256_hex(const void* d, size_t n, char sep = 0);
uint32_t crc32_calc(const void* d, size_t n, uint32_t crc = 0);
