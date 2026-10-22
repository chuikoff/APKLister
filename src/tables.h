// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <string>
#include <cstdint>
const char* android_version_name(int api);
// "dangerous", "special", "signature", "normal" or nullptr
const char* permission_class(const std::string& perm);
std::string protection_level_string(uint32_t v);
