// SPDX-License-Identifier: GPL-2.0-or-later
// Tiny UI-string localization (English source strings -> Russian).
#pragma once
#include <string>

enum class Lang { En, Ru };
void set_lang(Lang l);   // per thread (the analyzer runs on TC's UI thread or a thumbnail thread)
Lang get_lang();
// Returns the translation of an English UI string for the current language (or the string itself).
const char* T(const char* en);
std::string T(const std::string& en);
// "ru", "en", "auto"/"" -> parsed language; returns false for auto/unknown
bool parse_lang(const std::string& s, Lang& out);
// number of displayed characters of a UTF-8 string (code points)
size_t u8len(const std::string& s);
