// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "util.h"
#include "i18n.h"

// Structured form of the summary (same content as Report::summary), for the owner-drawn view.
struct ReportItem {
    enum Kind { Section, KV, Line, Blank };
    enum Tag { TagNone, TagDanger, TagSpecial, TagNormal, TagSignature, TagOk, TagBad, TagInfo, TagMuted };
    Kind kind = Line;
    int ind = 2;              // indentation in the text report (2 = top level)
    std::string key, value;   // Section: key = title; KV: key/value; Line: value = text
    std::string note;         // muted suffix (evidence etc.)
    std::string tag; int tag_kind = TagNone; // right-aligned pill
    bool strong = false;      // sub-header line
    bool mono = false;        // value is code-like (class/package/paths/tables)
    std::string plain;        // the exact line(s) of the text report
};

// Key facts for the hero band and the tiles.
struct ReportFacts {
    bool have = false;
    std::string package, version, version_code;
    int min_sdk = -1, target_sdk = -1;
    int arch_state = 0;           // 0 any (no native code), 1 ABIs known, 2 in splits (unknown), 3 .so outside lib/ only
    std::vector<std::string> abis;
    int page16 = 0;               // 0 n/a, 1 ready, 2 not ready
    uint64_t size = 0, usize = 0; int apk_count = 0;
    int perms = -1, perms_danger = 0;
    int dex_files = 0; uint64_t dex_classes = 0, dex_methods = 0;
    std::string compiler, agp;    // "R8 release", "9.2.1"
};

struct Report {
    bool ok = false;
    std::string kind;            // APK, AAB, XAPK, APKS, APKM, APEX, ZIP
    std::string title, subtitle; // app label; "package · version"
    std::string summary, manifest, files;
    std::vector<uint8_t> icon;   // raw PNG/WebP/JPEG bytes of the best launcher icon
    std::string icon_path;
    std::string arch;            // "Architecture: arm64-v8a, ..." (header line)
    std::vector<ReportItem> items;
    ReportFacts facts;
    std::string error;
};

struct AnalyzeOptions {
    Lang lang = Lang::En;                  // language of the report
    bool icon_only = false;                // fast path for thumbnails
    bool summary_only = false;             // skip manifest XML and file list (plugin shows only the summary)
};

// path: UTF-8 display path (used for extension)
void analyze(const std::string& path, Bytes data, const AnalyzeOptions& opt, Report& rep);
const char* apklister_version();
