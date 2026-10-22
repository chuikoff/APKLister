// SPDX-License-Identifier: GPL-2.0-or-later
#include "json.h"
#include "util.h"
#include <cstdlib>
#include <cstring>
#include <cctype>

namespace {
struct P {
    const std::string& s; size_t i = 0; int depth = 0; std::string err;
    explicit P(const std::string& x) : s(x) {}
    void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++; }
    bool str(std::string& o) {
        if (i >= s.size() || s[i] != '"') return false;
        i++;
        while (i < s.size() && s[i] != '"') {
            char c = s[i++];
            if (c == '\\' && i < s.size()) {
                char e = s[i++];
                switch (e) {
                case 'n': o += '\n'; break; case 't': o += '\t'; break; case 'r': o += '\r'; break;
                case 'b': o += '\b'; break; case 'f': o += '\f'; break;
                case 'u': {
                    if (i + 4 > s.size()) return false;
                    uint32_t cp = (uint32_t)strtoul(s.substr(i, 4).c_str(), nullptr, 16); i += 4;
                    if (cp >= 0xD800 && cp < 0xDC00 && i + 6 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                        uint32_t lo = (uint32_t)strtoul(s.substr(i + 2, 4).c_str(), nullptr, 16);
                        if (lo >= 0xDC00 && lo < 0xE000) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); i += 6; }
                    }
                    append_utf8(o, cp); break;
                }
                default: o += e;
                }
            } else o += c;
        }
        if (i >= s.size()) return false;
        i++; return true;
    }
    std::unique_ptr<JVal> val() {
        if (++depth > 100) { err = "too deep"; return nullptr; }
        ws(); auto v = std::make_unique<JVal>();
        if (i >= s.size()) { err = "unexpected end"; return nullptr; }
        char c = s[i];
        if (c == '{') {
            v->t = JVal::OBJ; i++; ws();
            if (i < s.size() && s[i] == '}') { i++; depth--; return v; }
            for (;;) {
                ws(); std::string k; if (!str(k)) { err = "bad key"; return nullptr; }
                ws(); if (i >= s.size() || s[i] != ':') { err = "expected ':'"; return nullptr; } i++;
                auto x = val(); if (!x) return nullptr;
                v->obj.push_back({ k, std::move(x) });
                ws(); if (i < s.size() && s[i] == ',') { i++; continue; }
                if (i < s.size() && s[i] == '}') { i++; break; }
                err = "expected ',' or '}'"; return nullptr;
            }
        } else if (c == '[') {
            v->t = JVal::ARR; i++; ws();
            if (i < s.size() && s[i] == ']') { i++; depth--; return v; }
            for (;;) {
                auto x = val(); if (!x) return nullptr;
                v->arr.push_back(std::move(x));
                ws(); if (i < s.size() && s[i] == ',') { i++; continue; }
                if (i < s.size() && s[i] == ']') { i++; break; }
                err = "expected ',' or ']'"; return nullptr;
            }
        } else if (c == '"') { v->t = JVal::STR; if (!str(v->s)) { err = "bad string"; return nullptr; } }
        else if (s.compare(i, 4, "true") == 0) { v->t = JVal::BOOL; v->s = "true"; i += 4; }
        else if (s.compare(i, 5, "false") == 0) { v->t = JVal::BOOL; v->s = "false"; i += 5; }
        else if (s.compare(i, 4, "null") == 0) { v->t = JVal::NUL; v->s = "null"; i += 4; }
        else {
            size_t a = i; while (i < s.size() && (isdigit((unsigned char)s[i]) || strchr("+-.eE", s[i]))) i++;
            if (a == i) { err = "unexpected character"; return nullptr; }
            v->t = JVal::NUM; v->s = s.substr(a, i - a);
        }
        depth--;
        return v;
    }
};
}

std::unique_ptr<JVal> json_parse(const std::string& text, std::string& err) {
    P p(text);
    if (text.size() >= 3 && (uint8_t)text[0] == 0xEF && (uint8_t)text[1] == 0xBB && (uint8_t)text[2] == 0xBF) p.i = 3;
    auto v = p.val();
    if (!v) err = p.err.empty() ? "parse error" : p.err;
    return v;
}

void json_flatten(const JVal& v, const std::string& pre, std::vector<std::pair<std::string, std::string>>& out, size_t mx) {
    if (out.size() >= mx) return;
    if (v.t == JVal::OBJ) { for (auto& p : v.obj) json_flatten(*p.second, pre.empty() ? p.first : pre + "." + p.first, out, mx); }
    else if (v.t == JVal::ARR) {
        if (v.arr.empty()) out.push_back({ pre, "[]" });
        bool scalars = true; for (auto& x : v.arr) if (x->t == JVal::OBJ || x->t == JVal::ARR) scalars = false;
        if (scalars && v.arr.size() <= 64) {
            std::string j; for (auto& x : v.arr) { if (!j.empty()) j += ", "; j += x->s; }
            if (!v.arr.empty()) out.push_back({ pre, j });
        } else for (size_t i = 0; i < v.arr.size(); i++) json_flatten(*v.arr[i], strf("%s[%zu]", pre.c_str(), i), out, mx);
    } else out.push_back({ pre, sanitize_utf8(v.s) });
}
