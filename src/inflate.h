// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
// Raw DEFLATE (RFC 1951) decoder. Stops after `limit` output bytes (partial=true then).
// Returns false on corrupt data; err gets a reason.
bool inflate_raw(const uint8_t* src, size_t n, std::vector<uint8_t>& out, size_t size_hint, size_t limit, bool* partial, std::string* err);
