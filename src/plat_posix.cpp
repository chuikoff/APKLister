// SPDX-License-Identifier: GPL-2.0-or-later
#include "plat.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
bool MappedFile::open(const std::string& path, std::string& err) {
    fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) { err = strerror(errno); return false; }
    struct stat st; fstat(fd, &st); size = (uint64_t)st.st_size;
    if (!size) { p = (const uint8_t*)""; return true; }
    void* m = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { err = strerror(errno); return false; }
    p = (const uint8_t*)m; h1 = m;
    return true;
}
void MappedFile::close() { if (h1) munmap(h1, size); h1 = nullptr; if (fd >= 0) ::close(fd); fd = -1; p = nullptr; }
bool file_exists_utf8(const std::string& p) { struct stat st; return stat(p.c_str(), &st) == 0; }
