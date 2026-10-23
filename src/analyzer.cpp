// SPDX-License-Identifier: GPL-2.0-or-later
// Builds the text report for APK / AAB / XAPK / APKS / APKM / APEX files.
#include "analyzer.h"
#include "zip.h"
#include "xml.h"
#include "arsc.h"
#include "version.h"
#include "i18n.h"
#include "json.h"
#include "proto.h"
#include "tables.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <set>

const char* apklister_version() { return APKL_VER_STR; }

namespace {

const size_t KW = 32;
bool code_like(const std::string& v) {
    if (v.empty() || v.size() > 200) return false;
    bool sep = false;
    for (unsigned char c : v) {
        if (c == ' ' || c >= 0x80) return false;
        if (c == '.' || c == '/' || c == '@' || c == '_' || c == '$') sep = true;
    }
    return sep;
}
struct Out {
    std::string s;
    std::vector<ReportItem> items;
    void push(ReportItem::Kind k, int ind, const std::string& key, const std::string& value, const std::string& plain) {
        ReportItem it; it.kind = k; it.ind = ind; it.key = key; it.value = value; it.plain = plain;
        if (k == ReportItem::KV) it.mono = code_like(value);
        if (k == ReportItem::Line) { it.strong = !value.empty() && value.back() == ':'; it.mono = !it.strong; }
        if (it.mono && value.find_first_not_of("0123456789.") == std::string::npos) it.mono = false;
        items.push_back(std::move(it));
    }
    void sec(const std::string& t) {
        if (!s.empty()) s += "\n";
        std::string h = "== " + T(t) + " "; size_t w = u8len(h); while (w++ < 78) h += '=';
        s += h + "\n";
        push(ReportItem::Section, 0, T(t), "", h);
    }
    void kv(const std::string& k, const std::string& v, int ind = 2) {
        std::string l((size_t)ind, ' '); l += T(k);
        size_t w = u8len(l);
        if (w < KW) l.append(KW - w, ' '); else l += ' ';
        s += l + v + "\n";
        push(ReportItem::KV, ind, T(k), v, l + v);
    }
    void line(const std::string& t, int ind = 2) {
        std::string l = std::string((size_t)ind, ' ') + t;
        s += l + "\n";
        push(ReportItem::Line, ind, "", t, l);
    }
    void blank() { s += "\n"; push(ReportItem::Blank, 0, "", "", ""); }
    // refine how the last item is shown in the drawn view (text report unchanged)
    ReportItem& last() { static ReportItem dummy; return items.empty() ? dummy : items.back(); }
    void view(const std::string& text, const std::string& tag = "", int tag_kind = ReportItem::TagNone) {
        ReportItem& it = last(); it.value = text; it.tag = tag; it.tag_kind = tag_kind;
    }
    void view_kv(const std::string& key, const std::string& value, const std::string& note) {
        ReportItem& it = last(); it.kind = ReportItem::KV; it.key = key; it.value = value; it.note = note; it.mono = false;
    }
};

std::string pad(const std::string& s, size_t w) { size_t n = u8len(s); return n >= w ? s + " " : s + std::string(w - n, ' '); }
std::string lpad(const std::string& s, size_t w) { size_t n = u8len(s); return n >= w ? s : std::string(w - n, ' ') + s; }
std::string short_size(uint64_t n) {
    bool ru = get_lang() == Lang::Ru;
    if (n < 1024) return strf("%llu %s", (unsigned long long)n, ru ? "Б" : "B");
    if (n < 1024 * 1024) return strf("%.1f %s", n / 1024.0, ru ? "КиБ" : "KiB");
    if (n < 1024ull * 1024 * 1024) return strf("%.2f %s", n / 1048576.0, ru ? "МиБ" : "MiB");
    return strf("%.2f %s", n / 1073741824.0, ru ? "ГиБ" : "GiB");
}
std::string api_str(int api) {
    if (api < 0) return "-";
    const char* n = android_version_name(api);
    return n ? strf("%d (Android %s)", api, T(n)) : strf("%d", api);
}
std::string basename_of(const std::string& p) { size_t k = p.find_last_of("/\\"); return k == std::string::npos ? p : p.substr(k + 1); }
std::string ext_of(const std::string& p) { std::string b = basename_of(p); size_t k = b.rfind('.'); return k == std::string::npos ? "" : lower(b.substr(k + 1)); }

struct Layout {
    std::string manifest, resources, dex, lib, root, assets, res, file_prefix;
    bool proto = false;
};
Layout apk_layout() { Layout l; l.manifest = "AndroidManifest.xml"; l.resources = "resources.arsc"; l.lib = "lib/"; l.assets = "assets/"; l.res = "res/"; return l; }
Layout aab_layout(const std::string& m) {
    Layout l; l.manifest = m + "manifest/AndroidManifest.xml"; l.resources = m + "resources.pb"; l.dex = m + "dex/"; l.lib = m + "lib/";
    l.root = m + "root/"; l.assets = m + "assets/"; l.res = m + "res/"; l.file_prefix = m; l.proto = true; return l;
}

// ---- ELF quick look
struct ElfInfo { bool ok = false; int cls = 0; int machine = 0; uint64_t min_align = 0; bool have_align = false; std::string ndk; int api = -1; };
ElfInfo elf_info(Bytes b) {
    ElfInfo e;
    if (b.n < 52 || memcmp(b.p, "\x7f" "ELF", 4) != 0) return e;
    e.cls = b.p[4]; if (b.p[5] != 1) return e; // little endian only
    e.machine = rd16(b.p + 18);
    uint64_t phoff; uint16_t phent, phnum;
    if (e.cls == 2) { if (b.n < 64) return e; phoff = rd64(b.p + 32); phent = rd16(b.p + 54); phnum = rd16(b.p + 56); }
    else { phoff = rd32(b.p + 28); phent = rd16(b.p + 42); phnum = rd16(b.p + 44); }
    e.ok = true;
    if (phnum > 256) return e;
    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t o = phoff + (uint64_t)i * phent;
        if (o > b.n || !b.has((size_t)o, e.cls == 2 ? 56 : 32)) break;
        const uint8_t* p = b.p + o;
        uint32_t type = rd32(p); uint64_t off, fsz, al;
        if (e.cls == 2) { off = rd64(p + 8); fsz = rd64(p + 32); al = rd64(p + 48); }
        else { off = rd32(p + 4); fsz = rd32(p + 16); al = rd32(p + 28); }
        if (type == 1) { if (!e.have_align || al < e.min_align) e.min_align = al; e.have_align = true; }
        if (type == 4 && off < b.n && fsz < b.n && b.has((size_t)off, (size_t)fsz)) {
            Reader r(b.sub((size_t)off, (size_t)fsz));
            while (r.left() >= 12) {
                uint32_t nsz = r.u32(), dsz = r.u32(), nt = r.u32();
                Bytes nm = r.take((nsz + 3) & ~3u), ds = r.take((dsz + 3) & ~3u);
                if (!r.ok) break;
                if (nsz == 8 && memcmp(nm.p, "Android", 8) == 0 && nt == 1 && dsz >= 4) {
                    e.api = (int)rd32(ds.p);
                    if (dsz >= 4 + 64) { const char* v = (const char*)ds.p + 4; e.ndk = sanitize_utf8(std::string(v, strnlen(v, 64))); }
                    if (dsz >= 4 + 128) { const char* v = (const char*)ds.p + 68; std::string bn(v, strnlen(v, 64)); if (!bn.empty()) e.ndk += " (build " + sanitize_utf8(bn) + ")"; }
                }
            }
        }
    }
    return e;
}
const char* elf_machine(int m) {
    switch (m) { case 40: return "ARM"; case 183: return "AArch64"; case 3: return "x86"; case 62: return "x86-64"; case 8: return "MIPS"; case 243: return "RISC-V"; default: return "?"; }
}

// ---- ABIs
const char* abi_desc(const std::string& a) {
    if (a == "arm64-v8a") return "64-bit ARM";
    if (a == "armeabi-v7a") return "32-bit ARM";
    if (a == "armeabi") return "32-bit ARM, ARMv5/v6, legacy";
    if (a == "x86_64") return "64-bit x86";
    if (a == "x86") return "32-bit x86";
    if (a == "riscv64") return "64-bit RISC-V";
    if (a == "mips64") return "64-bit MIPS, legacy";
    if (a == "mips") return "32-bit MIPS, legacy";
    return nullptr;
}
int abi_rank(const std::string& a) {
    static const char* o[] = { "arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "riscv64", "mips64", "mips" };
    for (int i = 0; i < 8; i++) if (a == o[i]) return i;
    return 100;
}
struct AbiLess { bool operator()(const std::string& a, const std::string& b) const { int x = abi_rank(a), y = abi_rank(b); return x != y ? x < y : a < b; } };
typedef std::set<std::string, AbiLess> AbiSet;
// lib/<abi>/<file> (APK) or <module>/lib/<abi>/<file> (AAB)
const char* abi_from_elf(int cls, int machine) {
    switch (machine) { case 183: return "arm64-v8a"; case 40: return "armeabi-v7a"; case 62: return "x86_64"; case 3: return "x86"; case 243: return cls == 2 ? "riscv64" : nullptr; case 8: return cls == 2 ? "mips64" : "mips"; }
    return nullptr;
}
// native code that is not in lib/<abi>/: .so in assets/ or nested folders, loaded by the app itself.
// ABI comes from a path component (".../arm64-v8a/x.so") or from the ELF header.
void collect_other_abis(const Zip& z, bool aab, AbiSet& out) {
    size_t probed = 0;
    for (auto& e : z.entries) {
        std::string n = lower(e.name);
        if (!ends_with(n, ".so") && n.find(".so.") == std::string::npos) continue;
        size_t p = 0;
        if (aab) { size_t k = n.find('/'); if (k == std::string::npos) continue; p = k + 1; }
        if (n.compare(p, 4, "lib/") == 0) continue;
        bool found = false;
        size_t a = 0;
        while (a < n.size()) {
            size_t b = n.find('/', a); if (b == std::string::npos) break;
            std::string comp = n.substr(a, b - a); std::replace(comp.begin(), comp.end(), '_', '-');
            if (abi_desc(comp)) { out.insert(comp); found = true; break; }
            a = b + 1;
        }
        if (found || probed >= 64 || e.usize < 64) continue;
        probed++;
        std::vector<uint8_t> buf; Bytes v; std::string err;
        if (z.read(e, buf, v, 64, err) && v.n >= 20 && memcmp(v.p, "\x7f" "ELF", 4) == 0 && v.p[5] == 1)
            if (const char* ab = abi_from_elf(v.p[4], rd16(v.p + 18))) out.insert(ab);
    }
}
void collect_abis(const Zip& z, bool aab, AbiSet& out) {
    for (auto& e : z.entries) {
        size_t p = 0;
        if (aab) { size_t k = e.name.find('/'); if (k == std::string::npos) continue; p = k + 1; }
        if (e.name.compare(p, 4, "lib/") != 0) continue;
        size_t s = e.name.find('/', p + 4);
        if (s == std::string::npos || s == p + 4 || s + 1 >= e.name.size() || s - p - 4 > 32) continue;
        out.insert(sanitize_utf8(e.name.substr(p + 4, s - p - 4)));
    }
}
// "config.arm64_v8a" -> "arm64-v8a"
std::string abi_from_split(const std::string& split) {
    std::string n = lower(split);
    if (starts_with(n, "split_")) n = n.substr(6);
    if (!starts_with(n, "config.")) return "";
    n = n.substr(7);
    std::replace(n.begin(), n.end(), '_', '-');
    return abi_desc(n) ? n : "";
}
bool abi_is64(const std::string& a) { return a == "arm64-v8a" || a == "x86_64" || a == "riscv64" || a == "mips64"; }
// desc=false: "arm64-v8a, armeabi-v7a"; desc=true: "64-bit: arm64-v8a, x86_64; 32-bit: armeabi-v7a, x86"
std::string abi_list(const AbiSet& a, bool desc) {
    std::string s;
    if (!desc) { for (auto& x : a) s += (s.empty() ? "" : ", ") + x; return s; }
    std::string g64, g32, oth;
    for (auto& x : a) {
        std::string n = x;
        if (x == "armeabi" || x == "mips" || x == "mips64") n += T(" (legacy)");
        std::string& g = !abi_desc(x) ? oth : abi_is64(x) ? g64 : g32;
        g += (g.empty() ? "" : ", ") + n;
    }
    if (!g64.empty()) s += std::string(T("64-bit: ")) + g64;
    if (!g32.empty()) s += (s.empty() ? "" : "; ") + std::string(T("32-bit: ")) + g32;
    if (!oth.empty()) s += (s.empty() ? "" : "; ") + std::string(T("other: ")) + oth;
    return s;
}

struct TechRule { const char* group; const char* name; char kind; const char* pat; }; // kind: s=suffix, c=contains, p=prefix, d=dex string
const TechRule kTech[] = {
    {"Framework","Flutter",'s',"/libflutter.so"},{"Framework","Flutter",'c',"flutter_assets/"},{"Framework","Flutter",'d',"Lio/flutter/embedding/"},
    {"Framework","React Native",'s',"/libreactnativejni.so"},{"Framework","React Native",'s',"/libreactnative.so"},{"Framework","React Native",'p',"assets/index.android.bundle"},{"Framework","React Native",'d',"Lcom/facebook/react/"},
    {"Framework","Hermes JS engine",'s',"/libhermes.so"},{"Framework","JavaScriptCore",'s',"/libjsc.so"},{"Framework","Expo",'d',"Lexpo/modules/"},
    {"Framework","Xamarin / .NET for Android",'s',"/libmonodroid.so"},{"Framework","Xamarin / .NET for Android",'s',"/libmonosgen-2.0.so"},{"Framework","Xamarin / .NET for Android",'p',"assemblies/"},
    {"Framework",".NET MAUI",'c',"microsoft.maui"},{"Framework","Xamarin / .NET for Android",'d',"Lmono/android/"},
    {"Framework","Unity",'s',"/libunity.so"},{"Framework","Unity (IL2CPP)",'s',"/libil2cpp.so"},{"Framework","Unity (Mono)",'p',"assets/bin/data/managed/"},{"Framework","Unity",'d',"Lcom/unity3d/player/"},
    {"Framework","Unreal Engine",'s',"/libue4.so"},{"Framework","Unreal Engine",'s',"/libunreal.so"},
    {"Framework","Godot",'s',"/libgodot_android.so"},{"Framework","Cocos2d-x",'s',"/libcocos2dcpp.so"},{"Framework","Cocos2d-x",'s',"/libcocos2djs.so"},{"Framework","Cocos",'s',"/libcocos.so"},
    {"Framework","Defold",'s',"/libdmengine.so"},{"Framework","Solar2D (Corona)",'s',"/libcorona.so"},{"Framework","GameMaker",'s',"/libyoyo.so"},
    {"Framework","Apache Cordova",'p',"assets/www/cordova.js"},{"Framework","Apache Cordova",'d',"Lorg/apache/cordova/"},
    {"Framework","Capacitor (Ionic)",'p',"assets/capacitor.config.json"},{"Framework","Capacitor (Ionic)",'d',"Lcom/getcapacitor/"},
    {"Framework","NativeScript",'s',"/libnativescript.so"},{"Framework","Qt",'c',"libqt5core"},{"Framework","Qt",'c',"libqt6core"},
    {"Framework","Python (python-for-android/Kivy)",'c',"/libpython"},{"Framework","Python (Chaquopy)",'c',"chaquopy"},
    {"Framework","Go (gomobile)",'s',"/libgojni.so"},{"Framework","Compose Multiplatform",'d',"Lorg/jetbrains/compose/"},
    {"Framework","B4A (Basic4Android)",'d',"Lanywheresoftware/b4a/"},
    {"Language","Kotlin",'p',"kotlin/"},{"Language","Kotlin",'s',".kotlin_module"},{"Language","Kotlin",'d',"Lkotlin/Metadata;"},
    {"Language","C/C++ (NDK)",'s',".so"},
    {"Jetpack","Jetpack Compose",'c',"meta-inf/androidx.compose."},{"Jetpack","Jetpack Compose",'d',"Landroidx/compose/runtime/"},
    {"Jetpack","Room",'d',"Landroidx/room/"},{"Jetpack","WorkManager",'d',"Landroidx/work/"},{"Jetpack","Navigation",'d',"Landroidx/navigation/"},
    {"Jetpack","Media3 / ExoPlayer",'d',"Landroidx/media3/"},{"Library","ExoPlayer 2",'d',"Lcom/google/android/exoplayer2/"},
    {"Google","Firebase",'c',"firebase-"},{"Google","Firebase",'d',"Lcom/google/firebase/"},{"Google","Firebase Crashlytics",'d',"Lcom/google/firebase/crashlytics/"},
    {"Google","Google Play Services",'c',"play-services-"},{"Google","Google Play Services",'d',"Lcom/google/android/gms/common/"},
    {"Google","Google Mobile Ads (AdMob)",'d',"Lcom/google/android/gms/ads/"},{"Google","Play Core / In-app updates",'d',"Lcom/google/android/play/core/"},
    {"Google","Material Components",'d',"Lcom/google/android/material/"},
    {"Library","Kotlin Coroutines",'d',"Lkotlinx/coroutines/"},{"Library","kotlinx.serialization",'d',"Lkotlinx/serialization/"},
    {"Library","OkHttp",'d',"Lokhttp3/"},{"Library","Retrofit",'d',"Lretrofit2/"},{"Library","Ktor",'d',"Lio/ktor/"},
    {"Library","Gson",'d',"Lcom/google/gson/"},{"Library","Moshi",'d',"Lcom/squareup/moshi/"},{"Library","Jackson",'d',"Lcom/fasterxml/jackson/"},
    {"Library","RxJava",'d',"Lio/reactivex/"},{"Library","Dagger",'d',"Ldagger/"},{"Library","Hilt",'d',"Ldagger/hilt/"},{"Library","Koin",'d',"Lorg/koin/"},
    {"Library","Glide",'d',"Lcom/bumptech/glide/"},{"Library","Coil",'d',"Lcoil/"},{"Library","Coil 3",'d',"Lcoil3/"},{"Library","Picasso",'d',"Lcom/squareup/picasso/"},{"Library","Fresco",'d',"Lcom/facebook/drawee/"},
    {"Library","Lottie",'d',"Lcom/airbnb/lottie/"},{"Library","ZXing",'d',"Lcom/google/zxing/"},{"Library","Bouncy Castle",'d',"Lorg/bouncycastle/"},
    {"Library","Realm",'d',"Lio/realm/"},{"Library","SQLCipher",'d',"Lnet/sqlcipher/"},{"Library","EventBus",'d',"Lorg/greenrobot/eventbus/"},
    {"Library","Timber",'d',"Ltimber/log/"},{"Library","Apache Commons",'d',"Lorg/apache/commons/"},
    {"SDK","Sentry",'d',"Lio/sentry/"},{"SDK","AppsFlyer",'d',"Lcom/appsflyer/"},{"SDK","Adjust",'d',"Lcom/adjust/sdk/"},{"SDK","OneSignal",'d',"Lcom/onesignal/"},
    {"SDK","Branch",'d',"Lio/branch/"},{"SDK","Amplitude",'d',"Lcom/amplitude/"},{"SDK","Mixpanel",'d',"Lcom/mixpanel/"},{"SDK","Facebook SDK",'d',"Lcom/facebook/FacebookSdk;"},
    {"SDK","AppLovin",'d',"Lcom/applovin/"},{"SDK","ironSource",'d',"Lcom/ironsource/"},{"SDK","Unity Ads",'d',"Lcom/unity3d/ads/"},{"SDK","myTarget",'d',"Lcom/my/target/"},
    {"SDK","Yandex Mobile Ads",'d',"Lcom/yandex/mobile/ads/"},{"SDK","AppMetrica",'d',"Lio/appmetrica/"},{"SDK","AppMetrica (legacy)",'d',"Lcom/yandex/metrica/"},
    {"SDK","VK SDK",'d',"Lcom/vk/api/sdk/"},{"SDK","Huawei HMS",'d',"Lcom/huawei/hms/"},{"SDK","RuStore SDK",'d',"Lru/rustore/sdk/"},
    {"SDK","Microsoft App Center",'d',"Lcom/microsoft/appcenter/"},{"SDK","Bugsnag",'d',"Lcom/bugsnag/"},{"SDK","Datadog",'d',"Lcom/datadog/"},
    {"Protector","Qihoo 360 Jiagu",'c',"libjiagu"},{"Protector","Bangcle / SecNeo",'s',"/libsecexe.so"},{"Protector","Bangcle / SecNeo",'s',"/libdexhelper.so"},
    {"Protector","Tencent Legu",'c',"libshella"},{"Protector","Tencent Legu",'c',"libshellx"},{"Protector","Ijiami",'p',"assets/ijiami"},{"Protector","Baidu protect",'s',"/libbaiduprotect.so"},
    {"Protector","NetEase Yidun",'s',"/libnesec.so"},{"Protector","DexProtector",'c',"libdexprotector"},{"Protector","AppSealing",'c',"appsealing"},
    {"Protector","Promon SHIELD",'c',"libshield"},
};

class ApkAnalyzer {
public:
    const Zip& z; Layout L; const AnalyzeOptions& opt; Report& rep;
    XDoc doc; std::unique_ptr<Resources> res; std::vector<uint8_t> res_store;
    std::string pkg, label, version_name, version_code, manifest_err, res_err;
    int min_sdk = -1, target_sdk = -1, max_sdk = -1, compile_sdk = -1;
    std::set<std::string> dex_hits;
    AbiSet abis, other_abis; std::string abi_note; bool split_app = false, base_of_container = false;
    // the architecture line used in the header and in PACKAGE
    std::string arch_text(bool desc) const {
        if (!abis.empty()) {
            std::string s = abi_list(abis, desc);
            if (desc) s += T(abi_note);
            if (!other_abis.empty()) s += strf(T("   (+ .so outside lib/: %s)"), abi_list(other_abis, false).c_str());
            return s;
        }
        if (!other_abis.empty()) return strf(T("%s (.so outside lib/, loaded by the app itself)"), abi_list(other_abis, desc).c_str());
        if (split_app && !base_of_container) return desc ? T("unknown: base APK of a split app, native code (if any) is in config splits") : T("in config splits");
        return desc ? T("any (no native code)") : T("any");
    }
    // manifest says the app is delivered as split APKs (Play), so this base APK alone does not carry the ABI
    bool detect_split_app() const {
        const XNode* m = root(); if (!m) return false;
        if (bval(m, "isSplitRequired") == 1 || A(m, "requiredSplitTypes") || A(m, "splitTypes")) return true;
        if (const XNode* a = app()) {
            if (bval(a, "isSplitRequired") == 1) return true;
            for (auto* md : a->children("meta-data")) {
                std::string n = val(md, "name", false);
                if (n == "com.android.vending.splits.required" || n == "com.android.vending.splits" || n == "com.android.dynamic.apk.fused.modules") return true;
            }
        }
        return false;
    }
    std::vector<std::string> norm_names; // lower-cased names normalized to APK layout

    ApkAnalyzer(const Zip& zz, Layout l, const AnalyzeOptions& o, Report& r) : z(zz), L(l), opt(o), rep(r) {}

    const XNode* root() const { return doc.root.get(); }
    const XNode* app() const { return doc.root ? doc.root->child("application") : nullptr; }

    bool load() {
        std::vector<uint8_t> buf;
        const ZipEntry* me = z.find(L.manifest);
        if (!me) { manifest_err = L.manifest + " not found"; return false; }
        Bytes mb; std::string err;
        if (!z.read(*me, buf, mb, 64u << 20, err)) { manifest_err = "cannot read manifest: " + err; return false; }
        bool okm = L.proto ? parse_proto_xml(mb, doc) : parse_axml(mb, doc);
        if (!okm) {
            XDoc d2; bool ok2 = L.proto ? parse_axml(mb, d2) : parse_proto_xml(mb, d2);
            if (ok2) doc = std::move(d2);
            else { manifest_err = doc.error.empty() ? "cannot decode manifest" : doc.error; return false; }
        }
        const ZipEntry* re = z.find(L.resources);
        if (re) {
            std::vector<uint8_t> rb; Bytes rv;
            if (z.read(*re, rb, rv, 256u << 20, err)) {
                if (rv.p == rb.data()) { res_store.swap(rb); rv = Bytes(res_store); }
                res.reset(L.proto ? load_resources_pb(rv, res_err) : load_arsc(rv, res_err));
            } else res_err = err;
        }
        const XNode* m = root();
        pkg = val(m, "package");
        version_name = val(m, "versionName");
        version_code = val(m, "versionCode", false);
        if (const XAttr* vm = m->attr("versionCodeMajor")) {
            uint64_t full = ((uint64_t)vm->data << 32) | (uint32_t)strtoul(version_code.c_str(), nullptr, 10);
            version_code = strf("%llu", (unsigned long long)full);
        }
        label = app() ? val(app(), "label") : std::string();
        if (const XNode* us = m->child("uses-sdk")) {
            min_sdk = ival(us, "minSdkVersion", -1); target_sdk = ival(us, "targetSdkVersion", -1); max_sdk = ival(us, "maxSdkVersion", -1);
        }
        if (min_sdk < 0) min_sdk = 1;
        if (target_sdk < 0) target_sdk = min_sdk;
        compile_sdk = ival(m, "compileSdkVersion", -1);
        for (auto& e : z.entries) norm_names.push_back(lower(norm(e.name)));
        return true;
    }

    std::string norm(const std::string& n) const {
        if (L.file_prefix.empty()) return n;
        if (!L.root.empty() && starts_with(n, L.root.c_str())) return n.substr(L.root.size());
        if (!L.dex.empty() && starts_with(n, L.dex.c_str())) return n.substr(L.dex.size());
        if (starts_with(n, L.file_prefix.c_str())) return n.substr(L.file_prefix.size());
        return n;
    }

    const XAttr* A(const XNode* n, const char* nm) const { return n ? n->attr(nm) : nullptr; }
    std::string val(const XNode* n, const char* nm, bool resolve = true) const {
        const XAttr* a = A(n, nm); if (!a) return "";
        if (resolve && res && (a->type == RT_REFERENCE || a->type == RT_DYN_REF) && a->data && (a->data >> 24) != 0x01) {
            std::string s = res->best_string(a->data); if (!s.empty()) return sanitize_utf8(s);
        }
        return sanitize_utf8(format_value(*a, res.get()));
    }
    std::string valr(const XNode* n, const char* nm) const { // "resolved   (@type/name)"
        const XAttr* a = A(n, nm); if (!a) return "";
        std::string raw = format_value(*a, res.get());
        if (a->type == RT_REFERENCE || a->type == RT_DYN_REF) {
            std::string r = val(n, nm);
            if (r != raw) return r + "   (" + raw + ")";
        }
        return sanitize_utf8(raw);
    }
    int ival(const XNode* n, const char* nm, int def) const {
        const XAttr* a = A(n, nm); if (!a) return def;
        if (a->type == RT_INT_DEC || a->type == RT_INT_HEX) return (int)a->data;
        if (a->type == RT_REFERENCE && res) { for (auto& v : res->values(a->data)) if (v.type == RT_INT_DEC || v.type == RT_INT_HEX) return (int)v.data; }
        if (!a->str.empty() && (isdigit((unsigned char)a->str[0]) || a->str[0] == '-')) return atoi(a->str.c_str());
        if (!a->str.empty()) return 10000; // preview codename
        return def;
    }
    int bval(const XNode* n, const char* nm) const { // -1 absent, -2 unresolvable
        const XAttr* a = A(n, nm); if (!a) return -1;
        if (a->type == RT_BOOL) return a->data ? 1 : 0;
        if (a->type == RT_REFERENCE && res) { bool b; if (res->resolve_bool(a->data, b)) return b ? 1 : 0; }
        if (a->str == "true") return 1;
        if (a->str == "false") return 0;
        return -2;
    }
    std::string bstr(const XNode* n, const char* nm, const char* def_note) const {
        int b = bval(n, nm);
        if (b == 1) return "true";
        if (b == 0) return "false";
        if (b == -2) return valr(n, nm);
        return def_note ? strf(T("(not set; default %s)"), def_note) : std::string(T("(not set)"));
    }
    std::string cls(const std::string& n) const {
        if (n.empty()) return n;
        if (n[0] == '.') return pkg + n;
        if (n.find('.') == std::string::npos) return pkg + "." + n;
        return n;
    }

    // ------------------------------------------------------------ icon
    void find_icon() {
        const XNode* a = app();
        if (!a || !res) { fallback_icon(); return; }
        std::vector<uint32_t> ids;
        for (const char* nm : { "icon", "roundIcon" }) {
            const XAttr* x = A(a, nm);
            if (x && (x->type == RT_REFERENCE || x->type == RT_DYN_REF) && x->data) ids.push_back(x->data);
        }
        for (uint32_t id : ids) {
            std::vector<uint32_t> todo{ id }; std::set<uint32_t> seen;
            while (!todo.empty() && seen.size() < 16) {
                uint32_t cur = todo.back(); todo.pop_back();
                if (!seen.insert(cur).second) continue;
                auto vals = res->values(cur);
                int best = -1; uint16_t bd = 0;
                for (size_t i = 0; i < vals.size(); i++) {
                    auto& v = vals[i];
                    if (v.type == RT_REFERENCE && v.data) { todo.push_back(v.data); continue; }
                    std::string e = ext_of(v.str);
                    if (e != "png" && e != "webp" && e != "jpg" && e != "jpeg") continue;
                    uint16_t d = v.cfg.density >= 0xFFFE ? 1 : v.cfg.density;
                    if (best < 0 || d > bd) { best = (int)i; bd = d; }
                }
                if (best >= 0) {
                    std::string path = L.file_prefix + vals[best].str;
                    if (z.read_small(path, rep.icon, 16u << 20)) { rep.icon_path = vals[best].str + " (" + vals[best].cfg.desc + ")"; return; }
                }
                // adaptive icon XML: follow its foreground drawable
                for (auto& v : vals) {
                    if (ext_of(v.str) != "xml") continue;
                    std::vector<uint8_t> xb;
                    if (!z.read_small(L.file_prefix + v.str, xb, 1u << 20)) continue;
                    XDoc xd; bool ok = L.proto ? parse_proto_xml(Bytes(xb), xd) : parse_axml(Bytes(xb), xd);
                    if (!ok) continue;
                    for (auto& k : xd.root->kids) {
                        if (k->name != "foreground") continue;
                        const XAttr* d = k->attr("drawable");
                        if (d && d->type == RT_REFERENCE) todo.insert(todo.begin(), d->data);
                    }
                }
            }
        }
        fallback_icon();
    }
    void fallback_icon() {
        const ZipEntry* best = nullptr; int bestScore = -100;
        for (auto& e : z.entries) {
            std::string n = lower(e.name);
            if (n.find("ic_launcher") == std::string::npos && n.find("app_icon") == std::string::npos) continue;
            std::string ex = ext_of(n);
            if (ex != "png" && ex != "webp") continue;
            int sc = n.find("xxxhdpi") != std::string::npos ? 5 : n.find("xxhdpi") != std::string::npos ? 4 : n.find("xhdpi") != std::string::npos ? 3 : n.find("hdpi") != std::string::npos ? 2 : 1;
            if (n.find("foreground") != std::string::npos || n.find("background") != std::string::npos) sc -= 10;
            if (sc > bestScore) { bestScore = sc; best = &e; }
        }
        if (best && z.read_small(best->name, rep.icon, 16u << 20)) rep.icon_path = best->name + " (by file name)";
    }

    // ------------------------------------------------------------ PACKAGE
    void package_section(Out& o) {
        const XNode* m = root(); const XNode* a = app();
        o.sec("PACKAGE");
        o.kv("Package name", pkg.empty() ? "-" : pkg);
        o.kv("Application label", a && A(a, "label") ? valr(a, "label") : "-");
        if (res && a && A(a, "label") && A(a, "label")->type == RT_REFERENCE) {
            auto vals = res->values(A(a, "label")->data);
            std::string loc; int c = 0;
            for (auto& v : vals) { if (v.cfg.locale.empty() || v.str.empty()) continue; if (c++ < 12) loc += (loc.empty() ? "" : ", ") + v.cfg.locale + "=" + sanitize_utf8(v.str); }
            if (c) o.kv("Localized labels", strf("%d", c) + ": " + loc + (c > 12 ? ", ..." : ""));
        }
        o.kv("Version name", version_name.empty() ? "-" : (A(m, "versionName") && A(m, "versionName")->type == RT_REFERENCE ? valr(m, "versionName") : version_name));
        o.kv("Version code", version_code.empty() ? "-" : version_code);
        o.kv("Architecture", arch_text(true));
        o.kv("Min SDK", api_str(min_sdk));
        o.kv("Target SDK", api_str(target_sdk));
        o.kv("Max SDK", max_sdk < 0 ? "-" : api_str(max_sdk));
        std::string cs = A(m, "compileSdkVersion") ? api_str(compile_sdk) : "-";
        if (A(m, "compileSdkVersionCodename")) cs += "  codename " + val(m, "compileSdkVersionCodename");
        o.kv("Compile SDK", cs);
        if (A(m, "platformBuildVersionCode") || A(m, "platformBuildVersionName"))
            o.kv("Platform build version", val(m, "platformBuildVersionCode") + " / " + val(m, "platformBuildVersionName"));
        int il = ival(m, "installLocation", -1);
        o.kv("Install location", il < 0 ? T("(not set; default internalOnly)") : il == 0 ? "auto" : il == 1 ? "internalOnly" : il == 2 ? "preferExternal" : strf("%d", il));
        o.kv("Shared user ID", A(m, "sharedUserId") ? val(m, "sharedUserId") : "-");
        if (A(m, "sharedUserLabel")) o.kv("Shared user label", valr(m, "sharedUserLabel"));
        if (A(m, "sharedUserMaxSdkVersion")) o.kv("sharedUserMaxSdkVersion", val(m, "sharedUserMaxSdkVersion"));
        if (A(m, "split")) o.kv("Split name", val(m, "split"));
        if (A(m, "isFeatureSplit")) o.kv("Feature split", val(m, "isFeatureSplit"));
        if (A(m, "isSplitRequired")) o.kv("Split required", val(m, "isSplitRequired"));
        if (A(m, "requiredSplitTypes")) o.kv("Required split types", val(m, "requiredSplitTypes"));
        if (A(m, "splitTypes")) o.kv("Split types", val(m, "splitTypes"));
        if (!a) { o.line(T("(no <application> element)")); return; }
        o.blank();
        o.kv("Application class", A(a, "name") ? cls(val(a, "name")) : T("(default android.app.Application)"));
        o.kv("appComponentFactory", A(a, "appComponentFactory") ? val(a, "appComponentFactory") : "-");
        o.kv("Icon", A(a, "icon") ? valr(a, "icon") : "-");
        if (A(a, "roundIcon")) o.kv("Round icon", valr(a, "roundIcon"));
        if (!rep.icon_path.empty()) o.kv("Icon file used", rep.icon_path);
        o.kv("Theme", A(a, "theme") ? valr(a, "theme") : "-");
        o.kv("debuggable", bstr(a, "debuggable", "false"));
        o.kv("allowBackup", bstr(a, "allowBackup", "true"));
        o.kv("usesCleartextTraffic", bstr(a, "usesCleartextTraffic", target_sdk >= 28 ? "false (targetSdk>=28)" : "true (targetSdk<28)"));
        o.kv("networkSecurityConfig", A(a, "networkSecurityConfig") ? valr(a, "networkSecurityConfig") : "-");
        o.kv("extractNativeLibs", bstr(a, "extractNativeLibs", "true"));
        o.kv("largeHeap", bstr(a, "largeHeap", "false"));
        o.kv("testOnly", bstr(a, "testOnly", "false"));
        o.kv("requestLegacyExternalStorage", bstr(a, "requestLegacyExternalStorage", "false"));
        o.kv("hasCode", bstr(a, "hasCode", "true"));
        o.kv("supportsRtl", bstr(a, "supportsRtl", "false"));
        if (A(a, "fullBackupContent")) o.kv("fullBackupContent", valr(a, "fullBackupContent"));
        if (A(a, "dataExtractionRules")) o.kv("dataExtractionRules", valr(a, "dataExtractionRules"));
        if (A(a, "localeConfig")) o.kv("localeConfig", valr(a, "localeConfig"));
        if (A(a, "process")) o.kv("process", val(a, "process"));
        static const char* known[] = { "name","label","icon","roundIcon","theme","debuggable","allowBackup","usesCleartextTraffic","networkSecurityConfig",
            "extractNativeLibs","largeHeap","testOnly","requestLegacyExternalStorage","hasCode","supportsRtl","fullBackupContent","dataExtractionRules",
            "localeConfig","process","appComponentFactory", nullptr };
        std::vector<std::pair<std::string, std::string>> other;
        for (auto& x : a->attrs) {
            bool k = false; for (int i = 0; known[i]; i++) if (x.name == known[i]) k = true;
            if (!k) other.push_back({ x.name, sanitize_utf8(format_value(x, res.get())) });
        }
        if (!other.empty()) { o.line(T("Other <application> attributes:")); for (auto& p : other) o.kv(p.first, p.second, 4); }
        static const char* mknown[] = { "package","versionCode","versionName","versionCodeMajor","compileSdkVersion","compileSdkVersionCodename",
            "platformBuildVersionCode","platformBuildVersionName","installLocation","sharedUserId","sharedUserLabel","sharedUserMaxSdkVersion",
            "split","isFeatureSplit","isSplitRequired","requiredSplitTypes","splitTypes", nullptr };
        other.clear();
        for (auto& x : m->attrs) {
            bool k = false; for (int i = 0; mknown[i]; i++) if (x.name == mknown[i]) k = true;
            if (!k) other.push_back({ x.name, sanitize_utf8(format_value(x, res.get())) });
        }
        if (!other.empty()) { o.line(T("Other <manifest> attributes:")); for (auto& p : other) o.kv(p.first, p.second, 4); }
    }

    // ------------------------------------------------------------ PERMISSIONS / FEATURES
    void perms_section(Out& o) {
        const XNode* m = root();
        std::vector<const XNode*> up = m->children("uses-permission");
        for (auto* x : m->children("uses-permission-sdk-23")) up.push_back(x);
        for (auto* x : m->children("uses-permission-sdk-m")) up.push_back(x);
        o.sec(strf(T("PERMISSIONS (%zu requested)"), up.size()));
        rep.facts.perms = (int)up.size(); rep.facts.perms_danger = 0;
        std::map<std::string, int> cnt;
        for (auto* p : up) {
            std::string n = val(p, "name");
            const char* c = permission_class(n);
            cnt[T(c ? c : "other/custom")]++;
            std::string ex;
            if (p->name != "uses-permission") ex += "  [" + p->name + "]";
            if (A(p, "maxSdkVersion")) ex += "  maxSdkVersion=" + val(p, "maxSdkVersion");
            if (A(p, "minSdkVersion")) ex += "  minSdkVersion=" + val(p, "minSdkVersion");
            if (const XAttr* f = A(p, "usesPermissionFlags")) ex += (f->data & 0x10000) ? std::string("  neverForLocation") : "  usesPermissionFlags=" + val(p, "usesPermissionFlags");
            if (A(p, "requiredFeature")) ex += "  requiredFeature=" + val(p, "requiredFeature");
            std::string ln = pad(n, 58) + pad(c ? T(c) : "", 21) + ex;
            while (!ln.empty() && ln.back() == ' ') ln.pop_back();
            o.line(ln);
            int tk = !c ? ReportItem::TagMuted : !strcmp(c, "DANGEROUS") ? ReportItem::TagDanger : !strcmp(c, "special access") ? ReportItem::TagSpecial :
                     !strcmp(c, "signature/privileged") ? ReportItem::TagSignature : ReportItem::TagNormal;
            o.view(n + ex, T(c ? c : "other/custom"), tk);
            if (c && !strcmp(c, "DANGEROUS")) rep.facts.perms_danger++;
        }
        if (!cnt.empty()) {
            std::string s; for (auto& kv : cnt) s += (s.empty() ? "" : ", ") + strf("%d %s", kv.second, kv.first.c_str());
            o.kv("By protection class", s);
        }
        auto decl = m->children("permission");
        if (!decl.empty()) {
            o.line(strf(T("Declared permissions (%zu):"), decl.size()));
            for (auto* p : decl) {
                const XAttr* pl = A(p, "protectionLevel");
                std::string plv = pl ? protection_level_string(pl->data) : std::string("normal");
                std::string grp = A(p, "permissionGroup") ? "  group=" + val(p, "permissionGroup") : "";
                o.line(pad(val(p, "name"), 58) + plv + grp, 4);
                o.view(val(p, "name") + grp, plv, plv.find("dangerous") != std::string::npos ? ReportItem::TagDanger : plv.find("signature") != std::string::npos ? ReportItem::TagSignature : ReportItem::TagNormal);
            }
        }
        for (const char* t : { "permission-group", "permission-tree" }) {
            auto v = m->children(t);
            if (!v.empty()) { o.line(strf("<%s> (%zu):", t, v.size())); for (auto* p : v) o.line(val(p, "name"), 4); }
        }
    }

    std::string attr_list(const XNode* x) const {
        std::string s; for (auto& a : x->attrs) s += (s.empty() ? "" : "  ") + a.name + "=" + sanitize_utf8(format_value(a, res.get()));
        return s;
    }

    void features_section(Out& o) {
        const XNode* m = root();
        auto f = m->children("uses-feature");
        o.sec(strf(T("FEATURES (%zu)"), f.size()));
        for (auto* x : f) {
            std::string reqs = T(bval(x, "required") == 0 ? "optional" : "required");
            if (A(x, "glEsVersion")) {
                uint32_t v = A(x, "glEsVersion")->data;
                o.line(pad(strf("OpenGL ES %u.%u", v >> 16, v & 0xFFFF), 58) + reqs);
                o.view(strf("OpenGL ES %u.%u", v >> 16, v & 0xFFFF), reqs, bval(x, "required") == 0 ? ReportItem::TagMuted : ReportItem::TagInfo);
            } else {
                std::string ver = A(x, "version") ? "  version=" + val(x, "version") : "";
                o.line(pad(val(x, "name"), 58) + reqs + ver);
                o.view(val(x, "name") + ver, reqs, bval(x, "required") == 0 ? ReportItem::TagMuted : ReportItem::TagInfo);
            }
        }
        for (const char* t : { "supports-screens", "compatible-screens", "uses-configuration", "supports-gl-texture" }) {
            for (auto* x : m->children(t)) {
                std::string s = attr_list(x);
                o.kv("<" + std::string(t) + ">", s.empty() ? std::string(T("(no attributes)")) : s);
                for (auto& k : x->kids) o.line("<" + k->name + "> " + attr_list(k.get()), 4);
            }
        }
    }

    void meta_section(Out& o) {
        const XNode* m = root(); const XNode* a = app();
        if (a) {
            auto md = a->children("meta-data");
            o.sec(strf(T("APPLICATION META-DATA (%zu)"), md.size()));
            for (auto* x : md) o.line(pad(val(x, "name", false), 56) + (A(x, "value") ? valr(x, "value") : A(x, "resource") ? "resource " + valr(x, "resource") : std::string()));
            for (auto* p : a->children("property")) o.line(pad("property " + val(p, "name", false), 56) + (A(p, "value") ? valr(p, "value") : valr(p, "resource")));
            auto ul = a->children("uses-library"); auto unl = a->children("uses-native-library");
            auto usl = a->children("uses-static-library"); auto usdk = a->children("uses-sdk-library");
            if (!ul.empty() || !unl.empty() || !usl.empty() || !usdk.empty()) {
                o.sec("LIBRARIES (uses-library)");
                for (auto* x : ul) o.line(pad(val(x, "name"), 56) + T(bval(x, "required") == 0 ? "optional" : "required"));
                for (auto* x : unl) o.line(pad(val(x, "name"), 56) + T(bval(x, "required") == 0 ? "optional" : "required") + "  [native]");
                for (auto* x : usl) o.line(pad(val(x, "name"), 56) + "static  version=" + val(x, "version"));
                for (auto* x : usdk) o.line(pad(val(x, "name"), 56) + "sdk  versionMajor=" + val(x, "versionMajor"));
            }
            if (const XNode* pf = a->child("profileable")) o.kv("<profileable>", attr_list(pf));
        }
        auto q = m->children("queries");
        if (!q.empty()) {
            o.sec("PACKAGE VISIBILITY (<queries>)");
            for (auto* qq : q) for (auto& k : qq->kids) {
                if (k->name == "package") o.line("package   " + val(k.get(), "name"));
                else if (k->name == "provider") o.line("provider  " + val(k.get(), "authorities"));
                else if (k->name == "intent") {
                    std::string s;
                    for (auto& c : k->kids) s += (s.empty() ? "" : "; ") + (c->name == "data" ? "data " + attr_list(c.get()) : c->name + " " + val(c.get(), "name"));
                    o.line("intent    " + s);
                } else o.line(k->name + " " + attr_list(k.get()));
            }
        }
        static const char* handled[] = { "uses-sdk","application","uses-permission","uses-permission-sdk-23","uses-permission-sdk-m","permission","permission-group","permission-tree",
            "uses-feature","supports-screens","compatible-screens","uses-configuration","supports-gl-texture","queries", nullptr };
        std::vector<const XNode*> rest;
        for (auto& k : m->kids) { bool h = false; for (int i = 0; handled[i]; i++) if (k->name == handled[i]) h = true; if (!h && !k->is_text) rest.push_back(k.get()); }
        if (!rest.empty()) {
            o.sec("OTHER MANIFEST ELEMENTS");
            for (auto* r : rest) o.line("<" + r->name + "> " + attr_list(r));
        }
    }

    // ------------------------------------------------------------ NATIVE / DEX
    void native_section(Out& o) {
        struct Lib { std::string name; const ZipEntry* e; };
        std::map<std::string, std::vector<Lib>> abis;
        for (auto& e : z.entries) {
            if (!starts_with(e.name, L.lib.c_str())) continue;
            std::string r = e.name.substr(L.lib.size());
            size_t sl = r.find('/'); if (sl == std::string::npos || sl + 1 >= r.size()) continue;
            abis[r.substr(0, sl)].push_back({ r.substr(sl + 1), &e });
        }
        o.sec(strf(T("NATIVE LIBRARIES (%zu ABIs)"), abis.size()));
        if (abis.empty()) { o.line(T("none (pure Java/Kotlin, or native code is in split APKs)")); return; }
        std::string list; for (auto& a : abis) list += (list.empty() ? "" : ", ") + a.first;
        o.kv("ABIs", list);
        size_t checked = 0;
        for (auto& a : abis) {
            uint64_t tot = 0; for (auto& l : a.second) tot += l.e->usize;
            bool is64 = a.first == "arm64-v8a" || a.first == "x86_64" || a.first == "riscv64";
            o.line(strf(T("%s: %zu files, %s"), a.first.c_str(), a.second.size(), short_size(tot).c_str()));
            o.last().strong = true; o.last().mono = false;
            int bad16 = 0, so_count = 0;
            for (auto& l : a.second) {
                std::string info; int tag16 = 0;
                std::string meth = l.e->method == 0 ? T("stored") : l.e->method == 8 ? T("deflated") : strf("m%u", l.e->method);
                if (ends_with(lower(l.name), ".so") && checked < 400) {
                    checked++; so_count++;
                    std::vector<uint8_t> buf; Bytes v; std::string err;
                    if (z.read(*l.e, buf, v, 256 * 1024, err)) {
                        ElfInfo ei = elf_info(v);
                        if (ei.ok) {
                            info = strf("ELF%d %s", ei.cls == 2 ? 64 : 32, elf_machine(ei.machine));
                            if (ei.have_align) {
                                info += strf("  align %lluK", (unsigned long long)ei.min_align / 1024);
                                if (is64 && ei.min_align < 16384) { info += T(" (not 16KB-ready)"); bad16++; tag16 = 2; }
                                else if (is64) tag16 = 1;
                            }
                            if (ei.api >= 0) info += strf("  NDK api %d", ei.api);
                            if (!ei.ndk.empty()) info += " " + ei.ndk;
                        } else info = T("not an ELF file");
                    } else info = T("unreadable: ") + err;
                    if (l.e->method == 0) {
                        uint64_t off = z.data_offset(*l.e);
                        info += off % 16384 == 0 ? "  zip-aligned 16K" : off % 4096 == 0 ? "  zip-aligned 4K" : "  zip-unaligned";
                    }
                }
                o.line(pad(l.name, 34) + lpad(short_size(l.e->usize), 11) + "  " + pad(meth, 9) + info, 4);
                if (tag16) o.view(o.last().value, tag16 == 1 ? T("16 KB ✓") : T("16 KB ✗"), tag16 == 1 ? ReportItem::TagOk : ReportItem::TagBad);
            }
            if (is64 && so_count) rep.facts.page16 = (bad16 || rep.facts.page16 == 2) ? 2 : 1;
            if (is64 && so_count) o.kv("16 KB page size", bad16 ? strf(T("NOT ready: %d of %d libraries have LOAD alignment < 16 KB"), bad16, so_count) : std::string(T("ready (all LOAD segments >= 16 KB aligned)")), 4);
        }
    }

    void dex_section(Out& o) {
        struct D { int num; const ZipEntry* e; };
        std::vector<D> dex;
        for (auto& e : z.entries) {
            if (!starts_with(e.name, L.dex.c_str())) continue;
            std::string r = e.name.substr(L.dex.size());
            if (!starts_with(r, "classes") || !ends_with(r, ".dex") || r.find('/') != std::string::npos) continue;
            std::string mid = r.substr(7, r.size() - 11);
            int n = mid.empty() ? 1 : atoi(mid.c_str());
            if (!mid.empty() && n <= 0) continue;
            dex.push_back({ n, &e });
        }
        std::sort(dex.begin(), dex.end(), [](const D& a, const D& b) { return a.num < b.num; });
        o.sec(strf(T("DEX (%zu files)"), dex.size()));
        if (dex.empty()) { o.line(T("no classes*.dex")); return; }
        uint64_t tc = 0, tm = 0, tf = 0, ts = 0, tsz = 0, scanned = 0;
        std::set<std::string> markers;
        o.line(pad(T("File"), 18) + lpad(T("Size"), 11) + "  " + pad(T("Ver"), 5) + lpad(T("Classes"), 8) + lpad(T("Methods"), 9) + lpad(T("Fields"), 9) + lpad(T("Strings"), 9) + lpad(T("Types"), 8));
        for (auto& d : dex) {
            std::vector<uint8_t> buf; Bytes v; std::string err;
            bool full = scanned < (160u << 20);
            size_t limit = full ? (size_t)(256u << 20) : 0x70;
            std::string name = basename_of(d.e->name);
            if (!z.read(*d.e, buf, v, limit, err)) { o.line(pad(name, 18) + T("error: ") + err); continue; }
            if (v.n < 0x70 || memcmp(v.p, "dex\n", 4) != 0) { o.line(pad(name, 18) + T("not a DEX file")); continue; }
            std::string ver = sanitize_utf8(std::string((const char*)v.p + 4, 3));
            uint32_t strs = rd32(v.p + 56), types = rd32(v.p + 64), fields = rd32(v.p + 80), methods = rd32(v.p + 88), classes = rd32(v.p + 96);
            tc += classes; tm += methods; tf += fields; ts += strs; tsz += d.e->usize;
            o.line(pad(name, 18) + lpad(short_size(d.e->usize), 11) + "  " + ver + "  " + lpad(with_commas(classes), 8) + lpad(with_commas(methods), 9) + lpad(with_commas(fields), 9) + lpad(with_commas(strs), 9) + lpad(with_commas(types), 8));
            if (full && v.n > 0x70) {
                scanned += v.n;
                for (const char* mk : { "~~R8{", "~~D8{", "~~L8{" }) {
                    const uint8_t* p = memfind(v.p, v.n, mk, 5);
                    if (p) { const uint8_t* e = (const uint8_t*)memchr(p, '}', v.n - (p - v.p)); if (e && e - p < 400) markers.insert(sanitize_utf8(std::string((const char*)p, e - p + 1))); }
                }
                for (auto& t : kTech) if (t.kind == 'd' && !dex_hits.count(t.pat) && memfind(v.p, v.n, t.pat, strlen(t.pat))) dex_hits.insert(t.pat);
            }
        }
        o.kv("Total", strf(T("%s classes, %s methods, %s fields, %s strings, %s"), with_commas(tc).c_str(), with_commas(tm).c_str(), with_commas(tf).c_str(), with_commas(ts).c_str(), short_size(tsz).c_str()));
        o.kv("Multidex", T(dex.size() > 1 ? "yes" : "no"));
        rep.facts.dex_files = (int)dex.size(); rep.facts.dex_classes = tc; rep.facts.dex_methods = tm;
        for (auto& m : markers) if (rep.facts.compiler.empty()) {
            std::string c = m.compare(0, 4, "~~R8") == 0 ? "R8" : m.compare(0, 4, "~~D8") == 0 ? "D8" : "L8";
            size_t k = m.find("\"compilation-mode\":\"");
            if (k != std::string::npos) { size_t e = m.find('"', k + 20); if (e != std::string::npos) c += " " + m.substr(k + 20, e - k - 20); }
            rep.facts.compiler = c;
        }
        for (auto& m : markers) o.kv("Compiler marker", m);
        if (markers.empty() && scanned) o.kv("Compiler marker", T("none found (dx / old D8, or marker stripped)"));
        if (scanned < tsz) o.line(strf(T("(library/marker scan covered the first %s of DEX code)"), short_size(scanned).c_str()));
        std::vector<std::string> extra;
        for (auto& e : z.entries) {
            std::string n = lower(e.name);
            if ((ends_with(n, ".dex") && n.find("classes") == std::string::npos) || ends_with(n, ".jar") || ends_with(n, ".odex") || ends_with(n, ".vdex") || ends_with(n, ".oat"))
                if (extra.size() < 30) extra.push_back(e.name + "  " + short_size(e.usize));
        }
        if (!extra.empty()) { o.line(T("Other code files (dynamic loading / packer?):")); for (auto& x : extra) o.line(x, 4); }
    }

    void tech_section(Out& o) {
        std::map<std::string, std::vector<std::string>> groups;
        std::map<std::string, std::string> evidence;
        for (auto& t : kTech) {
            bool hit = false; std::string ev;
            if (t.kind == 'd') { hit = dex_hits.count(t.pat) > 0; ev = std::string("DEX: ") + t.pat; }
            else {
                std::string pat = lower(t.pat);
                for (auto& n : norm_names) {
                    bool m = t.kind == 's' ? ends_with(n, pat.c_str()) : t.kind == 'p' ? starts_with(n, pat.c_str()) : n.find(pat) != std::string::npos;
                    if (m) { hit = true; ev = n; break; }
                }
            }
            if (!hit) continue;
            auto& g = groups[t.group];
            if (std::find(g.begin(), g.end(), t.name) == g.end()) { g.push_back(t.name); evidence[t.name] = ev; }
        }
        o.sec("FRAMEWORKS & TECHNOLOGIES (heuristic)");
        if (groups.empty()) o.line(T("nothing specific detected (plain Android/Java)"));
        for (const char* gname : { "Framework", "Language", "Jetpack", "Google", "Library", "SDK", "Protector" }) {
            auto it = groups.find(gname); if (it == groups.end()) continue;
            for (auto& n : it->second) {
                o.line(pad(std::string(T(gname)) + ":", 14) + pad(n, 34) + "<- " + evidence[n]);
                o.view_kv(T(gname), n, "← " + evidence[n]);
            }
        }
        auto fw = groups.find("Framework");
        if (fw != groups.end() && std::find(fw->second.begin(), fw->second.end(), "Flutter") != fw->second.end()) {
            bool aot = false, jit = false;
            for (auto& n : norm_names) { if (ends_with(n, "/libapp.so")) aot = true; if (n.find("kernel_blob.bin") != std::string::npos) jit = true; }
            o.kv("Flutter build", aot ? "release/profile (Dart AOT libapp.so)" : jit ? "debug (JIT kernel_blob.bin)" : T("unknown"));
        }
    }

    void build_section(Out& o) {
        std::vector<std::pair<std::string, std::string>> libs, props, info;
        std::string mi = L.root + "META-INF/";
        size_t kmods = 0;
        for (auto& e : z.entries) {
            if (starts_with(e.name, mi.c_str())) {
                std::string r = e.name.substr(mi.size());
                if (ends_with(r, ".kotlin_module")) { kmods++; continue; }
                if (ends_with(r, ".version") && r.find('/') == std::string::npos && e.usize < 256) {
                    std::vector<uint8_t> b; if (z.read_small(e.name, b, 256)) libs.push_back({ r.substr(0, r.size() - 8), trim(sanitize_utf8(std::string(b.begin(), b.end()))) });
                } else if (r == "com/android/build/gradle/app-metadata.properties" || r == "version-control-info.textproto" || r == "kotlin-tooling-metadata.json") {
                    std::vector<uint8_t> b;
                    if (z.read_small(e.name, b, 64 * 1024)) {
                        std::string s = sanitize_utf8(std::string(b.begin(), b.end()));
                        if (r == "kotlin-tooling-metadata.json") {
                            std::string err; auto j = json_parse(s, err);
                            if (j) { std::vector<std::pair<std::string, std::string>> fl; json_flatten(*j, "", fl, 60);
                                for (auto& p : fl) if (lower(p.first).find("version") != std::string::npos || p.first == "buildSystem") info.push_back({ "kotlin " + p.first, p.second }); }
                        } else if (r == "version-control-info.textproto") {
                            std::string v;
                            for (auto& l : split_lines(s)) { l = trim(l); if (l.find(':') != std::string::npos) v += (v.empty() ? "" : "; ") + l; }
                            info.push_back({ "VCS info", v });
                        } else for (auto& l : split_lines(s)) { l = trim(l); if (!l.empty() && l[0] != '#') { info.push_back({ "app-metadata", l }); if (starts_with(l, "androidGradlePluginVersion=")) rep.facts.agp = l.substr(27); } }
                    }
                }
            } else if (starts_with(e.name, L.root.c_str())) {
                std::string r = e.name.substr(L.root.size());
                if (r.find('/') == std::string::npos && ends_with(r, ".properties") && e.usize < 4096) {
                    std::vector<uint8_t> b;
                    if (z.read_small(e.name, b, 4096)) {
                        std::string ver;
                        for (auto& l : split_lines(std::string(b.begin(), b.end()))) if (starts_with(l, "version=")) ver = trim(l.substr(8));
                        props.push_back({ r.substr(0, r.size() - 11), ver.empty() ? "?" : sanitize_utf8(ver) });
                    }
                }
            }
        }
        o.sec("BUILD INFO & BUNDLED LIBRARY VERSIONS");
        for (auto& p : info) o.kv(p.first, p.second);
        if (kmods) o.kv("Kotlin modules", strf(T("%zu *.kotlin_module files"), kmods));
        if (info.empty() && libs.empty() && props.empty() && !kmods) { o.line(T("no build metadata files found")); return; }
        if (!libs.empty()) {
            o.line(strf("META-INF/*.version (%zu):", libs.size()));
            std::sort(libs.begin(), libs.end());
            for (auto& l : libs) o.line(pad(l.first, 56) + l.second, 4);
        }
        if (!props.empty()) {
            o.line(strf(T("Root *.properties (Play services / Firebase) (%zu):"), props.size()));
            std::sort(props.begin(), props.end());
            for (auto& l : props) o.line(pad(l.first, 56) + l.second, 4);
        }
    }

    void res_section(Out& o) {
        o.sec("RESOURCES");
        if (!res) o.kv("Resource table", res_err.empty() ? std::string(T("not present")) : T("error: ") + res_err);
        else {
            o.kv("Resource table", res->kind);
            for (auto& p : res->packages) o.kv("Package", strf("0x%02x %s", p.id, p.name.c_str()));
            if (res->string_pool_size) o.kv("Global string pool", strf(T("%s strings"), with_commas(res->string_pool_size).c_str()));
            o.kv("Configurations", strf(T("%s (%s values)"), with_commas(res->config_count).c_str(), with_commas(res->total_values).c_str()));
            std::string t;
            for (auto& kv : res->type_entries) t += (t.empty() ? "" : ", ") + kv.first + strf(" %zu", kv.second);
            o.kv("Types (entries)", t);
            std::string loc; for (auto& l : res->locales) loc += (loc.empty() ? "" : " ") + l;
            o.kv("Locales", strf("%zu", res->locales.size()) + (loc.empty() ? "" : ": " + loc));
            std::string den; for (auto d : res->densities) den += (den.empty() ? "" : " ") + density_name(d);
            o.kv("Densities", den.empty() ? "-" : den);
        }
        std::map<std::string, size_t> dirs; size_t assets = 0, tot = 0; uint64_t asz = 0;
        for (auto& e : z.entries) {
            if (starts_with(e.name, L.res.c_str())) {
                std::string r = e.name.substr(L.res.size()); size_t sl = r.find('/');
                std::string d = sl == std::string::npos ? T("(root)") : r.substr(0, sl);
                dirs[d.substr(0, d.find('-'))]++; tot++;
            } else if (starts_with(e.name, L.assets.c_str())) { assets++; asz += e.usize; }
        }
        if (!dirs.empty()) {
            std::string s; for (auto& d : dirs) s += (s.empty() ? "" : ", ") + d.first + strf(" %zu", d.second);
            o.kv("res/ files", strf("%zu: ", tot) + s);
        }
        o.kv("assets/", strf(T("%zu files, %s"), assets, short_size(asz).c_str()));
        o.kv("Manifest XML", L.proto ? std::string("protobuf (aapt2)") : strf(T("binary, %d strings%s, resource map %d ids"), doc.string_count, doc.utf8_pool ? " UTF-8" : " UTF-16", doc.res_map_count));
    }
};

// ---------------------------------------------------------------- helpers outside the APK analyzer
std::string files_list(const Zip& z, const std::string& title) {
    std::string o = title + strf("  (%zu entries)\n", z.entries.size());
    o += pad("Method", 9) + lpad("Compressed", 13) + lpad("Size", 13) + lpad("Ratio", 7) + "  CRC32     Modified             " + lpad("Offset", 11) + "  Name\n";
    for (auto& e : z.entries) {
        std::string m = e.method == 0 ? "Stored" : e.method == 8 ? "Deflate" : strf("m%u", e.method);
        if (e.flags & 1) m += "*";
        std::string ratio = e.usize ? strf("%d%%", (int)(100.0 - 100.0 * (double)e.csize / (double)e.usize)) : "-";
        o += pad(m, 9) + lpad(with_commas(e.csize), 13) + lpad(with_commas(e.usize), 13) + lpad(ratio, 7) + "  " + strf("%08x", e.crc) + "  " +
             dos_datetime(e.mdate, e.mtime) + "  " + lpad(strf("%llu", (unsigned long long)e.lho), 11) + "  " + sanitize_utf8(e.name) + "\n";
    }
    return o;
}

void zip_section(Out& o, const Zip& z, const std::string& title, bool container = false, ReportFacts* facts = nullptr) {
    o.sec(title);
    std::map<uint16_t, size_t> meth; uint64_t cs = 0, us = 0; size_t enc = 0, dd = 0, dirs = 0, stored = 0, misaligned = 0, utf8 = 0;
    std::string mn = "9999", mx = "0000";
    for (auto& e : z.entries) {
        meth[e.method]++; cs += e.csize; us += e.usize;
        if (e.flags & 1) enc++;
        if (e.flags & 8) dd++;
        if (e.flags & 0x800) utf8++;
        if (!e.name.empty() && e.name.back() == '/') dirs++;
        if (e.method == 0 && e.usize) { stored++; if (z.data_offset(e) % 4) misaligned++; }
        std::string d = dos_datetime(e.mdate, e.mtime); if (d < mn) mn = d; if (d > mx) mx = d;
    }
    o.kv("Entries", strf(T("%zu (%zu directories)"), z.entries.size(), dirs));
    std::string m; for (auto& kv : meth) m += (m.empty() ? "" : ", ") + (kv.first == 0 ? std::string(T("stored")) : kv.first == 8 ? std::string(T("deflated")) : strf("method%u", kv.first)) + strf(" %zu", kv.second);
    o.kv("Compression methods", m);
    o.kv("Compressed total", human_size(cs));
    if (facts) facts->usize = us;
    o.kv("Uncompressed total", human_size(us) + (us ? strf(T("  (ratio %.1f%%)"), 100.0 * (double)cs / (double)us) : ""));
    o.kv("ZIP64", T(z.zip64 ? "yes" : "no"));
    o.kv("Central directory", strf(T("offset %llu, %s"), (unsigned long long)z.cd_off, short_size(z.cd_size).c_str()));
    if (!z.comment.empty()) o.kv("Archive comment", sanitize_utf8(z.comment));
    if (enc) o.kv("Encrypted entries", strf("%zu", enc));
    if (dd) o.kv("Data descriptors", strf(T("%zu entries"), dd));
    if (utf8) o.kv("UTF-8 name flag", strf(T("%zu entries"), utf8));
    if (!z.entries.empty()) o.kv("Timestamps", mn == mx ? mn + (mn.compare(0, 10, "1981-01-01") == 0 ? T("  (fixed: reproducible AGP/bundletool build)") : "") : mn + " .. " + mx);
    if (stored && !container) o.kv("zipalign (4-byte)", misaligned ? strf(T("%zu of %zu stored entries NOT aligned"), misaligned, stored) : strf(T("all %zu stored entries aligned"), stored));
}

void file_section(Out& o, const std::string& path, Bytes data, const std::string& kind) {
    o.sec("FILE");
    o.kv("Path", path);
    o.kv("Type", kind);
    o.kv("Size", human_size(data.n));
}

void set_titles(Report& rep, const ApkAnalyzer& a) {
    rep.title = a.label.empty() ? a.pkg : a.label;
    std::string sub = a.pkg;
    if (!a.version_name.empty() || !a.version_code.empty()) sub += "   v" + a.version_name + (a.version_code.empty() ? "" : " (" + a.version_code + ")");
    if (a.min_sdk > 0) sub += strf("   API %d..%d", a.min_sdk, a.target_sdk);
    sub += "   " + rep.kind;
    rep.subtitle = sub;
    rep.arch = strf(T("Architecture: %s"), a.arch_text(false).c_str());
    ReportFacts& f = rep.facts;
    f.have = true; f.package = a.pkg; f.version = a.version_name; f.version_code = a.version_code;
    f.min_sdk = a.min_sdk; f.target_sdk = a.target_sdk;
    f.abis.assign(a.abis.begin(), a.abis.end());
    if (!a.abis.empty()) f.arch_state = 1;
    else if (!a.other_abis.empty()) { f.arch_state = 3; f.abis.assign(a.other_abis.begin(), a.other_abis.end()); }
    else f.arch_state = (a.split_app && !a.base_of_container) ? 2 : 0;
}

void run_apk(ApkAnalyzer& a, Out& o, bool aab, const AbiSet* split_abis = nullptr) {
    a.find_icon();
    collect_abis(a.z, aab, a.abis);
    collect_other_abis(a.z, aab, a.other_abis);
    for (auto& x : a.abis) a.other_abis.erase(x);
    a.split_app = a.detect_split_app();
    a.base_of_container = split_abis != nullptr;
    if (split_abis && !split_abis->empty()) {
        bool extra = false;
        for (auto& x : *split_abis) if (a.abis.insert(x).second) extra = true;
        if (extra) a.abi_note = "   (incl. config splits)";
    }
    if (aab && !a.abis.empty()) a.abi_note = "   (all modules)";
    a.package_section(o);
    a.perms_section(o);
    a.features_section(o);
    a.meta_section(o);
    a.native_section(o);
    a.dex_section(o);
    a.tech_section(o);
    a.build_section(o);
    a.res_section(o);
}

std::string split_kind(const std::string& file, const std::string& split, bool have_manifest) {
    std::string n = lower(split);
    if (!have_manifest) { // derive from file name: config.xx / split_config.xx / base-xx
        std::string b = lower(basename_of(file));
        if (ends_with(b, ".apk")) b = b.substr(0, b.size() - 4);
        if (starts_with(b, "split_")) b = b.substr(6);
        if (starts_with(b, "base-")) { b = b.substr(5); if (b == "master" || starts_with(b, "master_")) return "base"; b = "config." + b; }
        if (b == "base") return "base";
        n = b;
    }
    if (n.empty()) return "base";
    if (!starts_with(n, "config.")) return "feature";
    std::string c = n.substr(7);
    for (const char* abi : { "arm64_v8a", "armeabi_v7a", "armeabi", "x86_64", "x86", "riscv64", "mips", "mips64" }) if (c == abi) return "ABI";
    for (const char* d : { "ldpi", "mdpi", "tvdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "nodpi", "anydpi" }) if (c == d) return "density";
    if (c.size() == 2 || c.size() == 3 || c.find("-r") != std::string::npos || starts_with(c, "b+")) return "language";
    return "config";
}

void apex_section(Out& o, const Zip& z) {
    o.sec("APEX");
    std::vector<uint8_t> b;
    if (z.read_small("apex_manifest.pb", b, 1 << 20)) {
        PbReader r{ Bytes(b) }; PbField f;
        while (r.next(f)) { if (f.num == 1 && f.wt == 2) o.kv("Name", sanitize_utf8(f.str())); else if (f.num == 2 && f.wt == 0) o.kv("Version", strf("%lld", (long long)f.v)); }
    }
    if (z.read_small("apex_manifest.json", b, 1 << 20)) {
        std::string e2; auto j = json_parse(std::string(b.begin(), b.end()), e2);
        if (j) { std::vector<std::pair<std::string, std::string>> fl; json_flatten(*j, "", fl); for (auto& p : fl) o.kv(p.first, p.second); }
    }
    for (const char* n : { "apex_payload.img", "apex_pubkey", "apex_build_info.pb", "original_apex" }) if (const ZipEntry* e = z.find(n)) o.kv(n, short_size(e->usize));
}

void aab_section(Out& o, const Zip& z) {
    o.sec("APP BUNDLE");
    std::vector<std::string> modules;
    for (auto& e : z.entries) { size_t k = e.name.find("/manifest/AndroidManifest.xml"); if (k != std::string::npos && e.name.find('/') == k) modules.push_back(e.name.substr(0, k)); }
    std::string ml; for (auto& m : modules) ml += (ml.empty() ? "" : ", ") + m;
    o.kv("Modules", strf("%zu: ", modules.size()) + ml);
    std::vector<uint8_t> b;
    if (z.read_small("BundleConfig.pb", b, 4 << 20)) {
        static const char* dim[] = { "unspecified", "ABI", "screen density", "language", "texture compression", "device tier", "country set", "SDK runtime" };
        PbReader r{ Bytes(b) }; PbField f;
        while (r.next(f)) {
            if (f.num == 1 && f.wt == 2) { PbReader q(f.b); PbField g; while (q.next(g)) if (g.num == 2 && g.wt == 2) o.kv("Built by bundletool", sanitize_utf8(g.str())); }
            else if (f.num == 2 && f.wt == 2) {
                // Optimizations.splits_config(1).split_dimension(1){value(1), negate(2)}
                PbReader q(f.b); PbField g; std::string dims;
                while (q.next(g)) if (g.num == 1 && g.wt == 2) {
                    PbReader s(g.b); PbField h;
                    while (s.next(h)) if (h.num == 1 && h.wt == 2) {
                        PbReader d(h.b); PbField x; uint64_t v = 0; bool neg = false;
                        while (d.next(x)) { if (x.num == 1 && x.wt == 0) v = x.v; if (x.num == 2 && x.wt == 0) neg = x.v != 0; }
                        dims += (dims.empty() ? "" : ", ") + std::string(neg ? T("no ") : "") + (v < 8 ? T(dim[v]) : "?");
                    }
                }
                if (!dims.empty()) o.kv("Split dimensions", dims);
            }
        }
    }
    size_t meta = 0;
    for (auto& e : z.entries) if (starts_with(e.name, "BUNDLE-METADATA/") && e.name.back() != '/') { if (meta++ < 20) o.kv("Bundle metadata", e.name.substr(16) + "  " + short_size(e.usize)); }
    for (const char* n : { "base/assets.pb", "base/native.pb" }) if (z.find(n)) o.kv("Config", n);
}

} // namespace

void analyze(const std::string& path, Bytes data, const AnalyzeOptions& opt, Report& rep) {
    auto t0 = std::chrono::steady_clock::now();
    rep = Report();
    set_lang(opt.lang);
    try {
        Zip z; std::string err;
        Out o;
        if (!z.open(data, err)) {
            rep.kind = "unknown";
            file_section(o, path, data, T("not a ZIP archive"));
            o.line(T("ERROR: ") + err);
            rep.error = err; rep.summary = o.s; rep.items = std::move(o.items); rep.title = basename_of(path); rep.subtitle = T("cannot read: ") + err;
            rep.manifest = rep.files = "(not available)\n";
            return;
        }
        std::string ext = ext_of(path);
        std::vector<const ZipEntry*> apks;
        for (auto& e : z.entries) if (ends_with(lower(e.name), ".apk")) apks.push_back(&e);
        if (z.find("AndroidManifest.xml")) rep.kind = (z.find("apex_manifest.pb") || z.find("apex_manifest.json")) ? "APEX" : "APK";
        else if (z.find("base/manifest/AndroidManifest.xml")) rep.kind = "AAB";
        else if (!apks.empty()) rep.kind = ext == "xapk" ? "XAPK" : ext == "apks" ? "APKS" : ext == "apkm" ? "APKM" : z.find("manifest.json") ? "XAPK" : z.find("toc.pb") ? "APKS" : z.find("info.json") ? "APKM" : "APK set";
        else rep.kind = "ZIP";

        auto pick_base = [&](const std::string& pkgname) -> const ZipEntry* {
            const ZipEntry* base = nullptr;
            auto pick = [&](const std::string& n) -> const ZipEntry* { for (auto* e : apks) if (lower(e->name) == lower(n)) return e; return nullptr; };
            for (const std::string& c : { std::string("base.apk"), pkgname + ".apk", std::string("splits/base-master.apk"), std::string("base-master.apk") }) if (!base) base = pick(c);
            if (!base) for (auto* e : apks) if (starts_with(e->name, "standalones/")) { base = e; break; }
            if (!base) for (auto* e : apks) if (lower(basename_of(e->name)).find("config.") == std::string::npos && (!base || e->usize > base->usize)) base = e;
            if (!base && !apks.empty()) base = apks[0];
            return base;
        };

        if (opt.icon_only) {
            if (rep.kind == "APK" || rep.kind == "APEX") { ApkAnalyzer a(z, apk_layout(), opt, rep); if (a.load()) a.find_icon(); }
            else if (rep.kind == "AAB") { ApkAnalyzer a(z, aab_layout("base/"), opt, rep); if (a.load()) a.find_icon(); }
            else if (!apks.empty() && !z.read_small("icon.png", rep.icon, 8u << 20)) {
                const ZipEntry* base = pick_base("");
                std::vector<uint8_t> ib; Bytes iv;
                if (base && z.read(*base, ib, iv, (size_t)1 << 30, err)) { Zip in; if (in.open(iv, err)) { ApkAnalyzer a(in, apk_layout(), opt, rep); if (a.load()) a.find_icon(); } }
            }
            rep.ok = !rep.icon.empty();
            return;
        }

        file_section(o, path, data, rep.kind);
        rep.facts.size = data.n;
        if (rep.kind == "APK" || rep.kind == "APEX" || rep.kind == "AAB") {
            bool aab = rep.kind == "AAB";
            if (rep.kind == "APEX") apex_section(o, z);
            if (aab) aab_section(o, z);
            ApkAnalyzer a(z, aab ? aab_layout("base/") : apk_layout(), opt, rep);
            if (a.load()) { run_apk(a, o, aab); set_titles(rep, a); if (!opt.summary_only) rep.manifest = to_xml(a.doc, a.res.get()); }
            else { o.line(T("ERROR: ") + a.manifest_err); rep.error = a.manifest_err; rep.title = basename_of(path); rep.subtitle = a.manifest_err; }
            zip_section(o, z, "ZIP STRUCTURE", false, &rep.facts);
            if (!opt.summary_only) rep.files = files_list(z, basename_of(path));
        } else if (!apks.empty()) {
            o.sec(strf(T("%s CONTAINER"), rep.kind.c_str()));
            std::string pkgname;
            for (const char* jn : { "manifest.json", "info.json" }) {
                std::vector<uint8_t> b;
                if (!z.read_small(jn, b, 8 << 20)) continue;
                std::string e2; auto j = json_parse(std::string(b.begin(), b.end()), e2);
                if (!j) { o.kv(jn, T("invalid JSON: ") + e2); continue; }
                o.line(std::string(jn) + ":");
                std::vector<std::pair<std::string, std::string>> fl; json_flatten(*j, "", fl, 300);
                for (auto& p : fl) o.kv(p.first, p.second, 4);
                if (pkgname.empty()) pkgname = j->str("package_name");
                if (pkgname.empty()) pkgname = j->str("pname");
            }
            if (const ZipEntry* t = z.find("toc.pb")) o.kv("toc.pb", strf(T("%s (bundletool BuildApksResult)"), short_size(t->usize).c_str()));
            const ZipEntry* base = pick_base(pkgname);
            o.line(strf(T("APK files (%zu):"), apks.size()));
            uint64_t tot = 0; AbiSet split_abis;
            for (auto* e : apks) {
                tot += e->usize;
                std::string extra, splitname; bool have_m = false;
                // stored splits are zero-copy views; deflated ones are only inflated when small (big ones: name only)
                if (e != base && (e->method == 0 || e->usize < (8u << 20))) {
                    std::vector<uint8_t> sb; Bytes sv; std::string se;
                    if (z.read(*e, sb, sv, 64u << 20, se)) {
                        Zip sz;
                        std::vector<uint8_t> mb; XDoc d;
                        bool zok = sz.open(sv, se);
                        if (zok && e != base) collect_abis(sz, false, split_abis);
                        if (zok && sz.read_small("AndroidManifest.xml", mb, 8u << 20) && parse_axml(Bytes(mb), d)) {
                            const XAttr* sp = d.root->attr("split"); const XAttr* cf = d.root->attr("configForSplit");
                            have_m = true; if (sp) splitname = sp->str;
                            extra = sp ? "split=" + sp->str : std::string("(base)");
                            if (cf && !cf->str.empty()) extra += " configForSplit=" + cf->str;
                            const XAttr* fs = d.root->attr("isFeatureSplit"); if (fs && fs->data) extra += " feature";
                        }
                    }
                }
                if (e == base) extra = "(base)";
                if (e != base) { std::string ab = abi_from_split(have_m ? splitname : basename_of(e->name).substr(0, basename_of(e->name).size() - 4)); if (!ab.empty()) split_abis.insert(ab); }
                o.line(pad(e->name, 46) + lpad(short_size(e->usize), 11) + "  " + pad(T(split_kind(e->name, splitname, e == base || have_m)), 10) + sanitize_utf8(extra) + (e == base ? T("  <= analyzed below") : ""), 4);
            }
            o.kv("APK total", short_size(tot));
            rep.facts.apk_count = (int)apks.size();
            std::vector<std::string> other;
            for (auto& e : z.entries) {
                std::string n = lower(e.name);
                if (!ends_with(n, ".apk") && !n.empty() && n.back() != '/' && other.size() < 40)
                    other.push_back(sanitize_utf8(e.name) + "  " + short_size(e.usize) + (ends_with(n, ".obb") ? T("  (OBB expansion file)") : ""));
            }
            if (!other.empty()) { o.line(T("Other files:")); for (auto& x : other) o.line(x, 4); }
            zip_section(o, z, "CONTAINER ZIP STRUCTURE", true);
            if (!opt.summary_only) rep.files = files_list(z, basename_of(path));
            std::vector<uint8_t> ib; Bytes iv;
            if (!z.read(*base, ib, iv, (size_t)1 << 31, err)) { o.line(T("ERROR: ") + base->name + ": " + err); rep.error = err; }
            else {
                Zip in;
                if (!in.open(iv, err)) { o.line(T("ERROR: ") + base->name + ": " + err); rep.error = err; }
                else {
                    o.sec(strf(T("BASE APK: %s"), base->name.c_str()));
                    o.kv("Size", human_size(iv.n));
                    ApkAnalyzer a(in, apk_layout(), opt, rep);
                    if (a.load()) { run_apk(a, o, false, &split_abis); set_titles(rep, a); if (!opt.summary_only) rep.manifest = to_xml(a.doc, a.res.get()); }
                    else { o.line(T("ERROR: ") + a.manifest_err); rep.error = a.manifest_err; }
                    zip_section(o, in, "BASE APK ZIP STRUCTURE");
                    if (!opt.summary_only) rep.files += "\n" + files_list(in, base->name);
                }
            }
            if (rep.icon.empty()) z.read_small("icon.png", rep.icon, 8u << 20);
            if (rep.title.empty()) { rep.title = basename_of(path); rep.subtitle = rep.kind; }
        } else {
            o.line(T("This ZIP archive contains neither AndroidManifest.xml nor .apk files."));
            zip_section(o, z, "ZIP STRUCTURE");
            if (!opt.summary_only) rep.files = files_list(z, basename_of(path));
            rep.title = basename_of(path); rep.subtitle = T("not an Android package");
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        o.blank();
        o.line(strf(T("APK Lister %s, analysis took %lld ms"), apklister_version(), (long long)ms), 0);
        rep.summary = o.s;
        rep.items = std::move(o.items);
        if (!opt.summary_only && rep.manifest.empty()) rep.manifest = "(no decodable AndroidManifest.xml)\n";
        rep.ok = true;
    } catch (const std::bad_alloc&) {
        rep.error = "out of memory"; rep.summary += T("\nERROR: out of memory while analyzing\n");
    } catch (...) {
        rep.error = "internal error"; rep.summary += T("\nERROR: internal error while analyzing\n");
    }
}
