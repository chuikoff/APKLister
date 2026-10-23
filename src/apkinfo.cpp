// SPDX-License-Identifier: GPL-2.0-or-later
// apkinfo: command-line front-end of the APK Lister core (used for testing).
#include "analyzer.h"
#include "plat.h"
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#endif

static int run(int argc, char** argv) {
    const char* tab = "summary"; const char* file = nullptr; const char* icon_out = nullptr; Lang lang = Lang::En;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-m")) tab = "manifest";
        else if (!strcmp(argv[i], "-f")) tab = "files";
        else if (!strcmp(argv[i], "-a")) tab = "all";
        else if (!strcmp(argv[i], "--nohash")) {} // accepted for compatibility (hashing was removed in 0.1.2)
        else if (!strcmp(argv[i], "--lang") && i + 1 < argc) { if (!parse_lang(argv[++i], lang)) { fprintf(stderr, "--lang: ru or en\n"); return 2; } }
        else if (!strcmp(argv[i], "--items")) tab = "items"; // debug: structured view items and facts
        else if (!strcmp(argv[i], "--icon") && i + 1 < argc) icon_out = argv[++i];
        else file = argv[i];
    }
    if (!file) {
        fprintf(stderr, "APK Lister %s - apkinfo\nusage: apkinfo [-m|-f|-a] [--lang ru|en] [--icon out.png] FILE\n"
                        "  FILE: .apk .aab .xapk .apks .apkm .apex\n  default: summary; -m decoded AndroidManifest.xml; -f file list; -a everything\n", apklister_version());
        return 2;
    }
    MappedFile mf; std::string err;
    if (!mf.open(file, err)) { fprintf(stderr, "%s: %s\n", file, err.c_str()); return 1; }
    AnalyzeOptions opt; opt.lang = lang;
    Report r;
    analyze(file, Bytes(mf.p, (size_t)mf.size), opt, r);
    std::string out;
    if (!strcmp(tab, "summary") || !strcmp(tab, "all")) out += "# " + r.title + "\n# " + r.subtitle + "\n" + (r.arch.empty() ? std::string() : "# " + r.arch + "\n") + "\n" + r.summary;
    if (!strcmp(tab, "manifest") || !strcmp(tab, "all")) out += r.manifest;
    if (!strcmp(tab, "files") || !strcmp(tab, "all")) out += r.files;
    if (!strcmp(tab, "items")) {
        const ReportFacts& f = r.facts;
        out += strf("facts have=%d pkg=%s ver=%s code=%s api=%d..%d arch=%d abis=%zu p16=%d size=%llu usize=%llu apks=%d perms=%d/%d dex=%d/%llu/%llu comp=%s agp=%s\n",
            f.have, f.package.c_str(), f.version.c_str(), f.version_code.c_str(), f.min_sdk, f.target_sdk, f.arch_state, f.abis.size(), f.page16,
            (unsigned long long)f.size, (unsigned long long)f.usize, f.apk_count, f.perms, f.perms_danger, f.dex_files, (unsigned long long)f.dex_classes, (unsigned long long)f.dex_methods, f.compiler.c_str(), f.agp.c_str());
        for (auto& it : r.items) out += strf("%d %d %c%c [%s] [%s] {%s} <%s:%d>\n", it.kind, it.ind, it.mono ? 'M' : '-', it.strong ? 'S' : '-', it.key.c_str(), it.value.c_str(), it.note.c_str(), it.tag.c_str(), it.tag_kind);
    }
    fwrite(out.data(), 1, out.size(), stdout);
    if (icon_out && !r.icon.empty()) { FILE* f = fopen(icon_out, "wb"); if (f) { fwrite(r.icon.data(), 1, r.icon.size(), f); fclose(f); } }
    return r.ok ? 0 : 1;
}

#ifdef _WIN32
int wmain(int argc, wchar_t** wargv) {
    std::vector<std::string> a; std::vector<char*> p;
    for (int i = 0; i < argc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 0 ? n - 1 : 0, '\0');
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], n, nullptr, nullptr);
        a.push_back(s);
    }
    for (auto& s : a) p.push_back(&s[0]);
    _setmode(_fileno(stdout), _O_BINARY);
    return run(argc, p.data());
}
#else
int main(int argc, char** argv) { return run(argc, argv); }
#endif
