// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "util.h"
#include <map>

struct ZipEntry {
    std::string name;
    uint16_t made_by = 0, need = 0, flags = 0, method = 0, mtime = 0, mdate = 0, internal_attr = 0;
    uint32_t crc = 0, external_attr = 0;
    uint64_t csize = 0, usize = 0, lho = 0;
    uint64_t data_off = 0; // resolved lazily (0 = unknown)
    bool zip64 = false;
    std::string comment;
    uint16_t extra_len = 0;
};

struct SigBlockPair { uint32_t id; Bytes value; };

class Zip {
public:
    bool open(Bytes data, std::string& err);
    Bytes data;
    std::vector<ZipEntry> entries;
    std::map<std::string, size_t> index;
    uint64_t eocd_off = 0, cd_off = 0, cd_size = 0;
    bool zip64 = false;
    std::string comment;
    // APK Signing Block
    bool has_sig_block = false;
    uint64_t sig_block_off = 0, sig_block_size = 0;
    std::vector<SigBlockPair> sig_pairs;

    const ZipEntry* find(const std::string& name) const;
    // returns data offset of entry payload (0 on error)
    uint64_t data_offset(const ZipEntry& e) const;
    // Read (and inflate) an entry. If stored and buf not needed, `out` points into the archive.
    bool read(const ZipEntry& e, std::vector<uint8_t>& buf, Bytes& out, size_t limit, std::string& err, bool* partial = nullptr) const;
    bool read_small(const std::string& name, std::vector<uint8_t>& buf, size_t limit = 64u << 20) const;
};
