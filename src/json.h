// SPDX-License-Identifier: GPL-2.0-or-later
// Tiny tolerant JSON reader (for XAPK manifest.json / APKM info.json).
#pragma once
#include <string>
#include <vector>
#include <memory>

struct JVal {
    enum T { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
    std::string s; // string / number text / bool text
    std::vector<std::pair<std::string, std::unique_ptr<JVal>>> obj;
    std::vector<std::unique_ptr<JVal>> arr;
    const JVal* get(const char* k) const { for (auto& p : obj) if (p.first == k) return p.second.get(); return nullptr; }
    std::string str(const char* k) const { const JVal* v = get(k); return v && v->t != OBJ && v->t != ARR ? v->s : std::string(); }
};
std::unique_ptr<JVal> json_parse(const std::string& text, std::string& err);
// "a.b[0].c = value" lines
void json_flatten(const JVal& v, const std::string& prefix, std::vector<std::pair<std::string, std::string>>& out, size_t max_items = 2000);
