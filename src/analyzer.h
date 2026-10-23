// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "util.h"

struct Report {
    bool ok = false;
    std::string kind;            // APK, AAB, XAPK, APKS, APKM, APEX, ZIP
    std::string title, subtitle; // app label; "package · version"
    std::string summary, manifest, files;
    std::vector<uint8_t> icon;   // raw PNG/WebP/JPEG bytes of the best launcher icon
    std::string icon_path;
    std::string error;
};

struct AnalyzeOptions {
    bool hashes = true;
    uint64_t hash_limit = 1024ull << 20;   // skip whole-file hashes above this size
    bool icon_only = false;                // fast path for thumbnails
    bool summary_only = false;             // skip manifest XML and file list (plugin shows only the summary)
};

// path: UTF-8 display path (used for extension)
void analyze(const std::string& path, Bytes data, const AnalyzeOptions& opt, Report& rep);
const char* apklister_version();
