// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <string>
#include <cstdint>
struct MappedFile {
    const uint8_t* p = nullptr; uint64_t size = 0;
    void* h1 = nullptr; void* h2 = nullptr; int fd = -1;
    bool open(const std::string& utf8path, std::string& err);
    void close();
    ~MappedFile() { close(); }
};
bool file_exists_utf8(const std::string& p);
