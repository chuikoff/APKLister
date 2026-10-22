// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "util.h"
#include <map>
#include <set>

struct StringPool {
    StringPool() {}
    explicit StringPool(Bytes chunk);
    bool load(Bytes chunk);
    const std::string& get(uint32_t i) const;
    uint32_t count = 0; bool utf8 = false;
    const uint8_t* offsets = nullptr; Bytes strings;
    mutable std::vector<std::string> cache; mutable std::vector<uint8_t> have;
};

struct ResConfig {
    std::string desc;     // e.g. "default", "ru-rRU", "xxhdpi-v26"
    std::string locale;   // "" for default
    uint16_t density = 0; // 0 = any
    uint16_t sdk = 0;
};

struct ResValue {
    ResConfig cfg;
    uint8_t type = 0; uint32_t data = 0;
    std::string str;      // resolved string value (strings, file paths)
    bool complex = false; // bag/style/array
};

class Resources {
public:
    virtual ~Resources() {}
    std::string kind;
    struct Pkg { uint32_t id; std::string name; };
    std::vector<Pkg> packages;
    std::map<std::string, size_t> type_entries; // type name -> number of entries
    std::set<std::string> locales;
    std::set<uint16_t> densities;
    size_t config_count = 0, total_values = 0, string_pool_size = 0;
    std::map<std::string, size_t> config_counts; // per-type number of configs
    // "type/name" or "pkg:type/name" for foreign packages
    virtual std::string ref_name(uint32_t id) const = 0;
    virtual std::vector<ResValue> values(uint32_t id) const = 0;
    // resolve references (up to depth) and return the default/best string value
    std::string best_string(uint32_t id, int depth = 0) const;
    bool resolve_bool(uint32_t id, bool& out) const;
};

Resources* load_arsc(Bytes data, std::string& err);
Resources* load_resources_pb(Bytes data, std::string& err);
std::string density_name(uint16_t d);
