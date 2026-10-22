// SPDX-License-Identifier: GPL-2.0-or-later
// aapt2 proto XmlNode (used for AndroidManifest.xml inside .aab) -> XDoc
#include "xml.h"
#include "proto.h"

void pb_item_to_value(Bytes item, uint8_t& type, uint32_t& data, std::string& str, std::string& refname);

static bool node(Bytes b, XNode& out, XDoc& doc, int depth) {
    if (depth > 256) return false;
    PbReader r(b); PbField f;
    while (r.next(f)) {
        if (f.num == 2 && f.wt == 2) { out.is_text = true; out.text = sanitize_utf8(f.str()); }
        else if (f.num == 3 && f.wt == 2) { PbReader q(f.b); PbField g; while (q.next(g)) if (g.num == 1 && g.wt == 0) out.line = (int)g.v; }
        else if (f.num == 1 && f.wt == 2) {
            PbReader e(f.b); PbField g;
            while (e.next(g)) {
                if (g.wt != 2) continue;
                if (g.num == 1) {
                    std::string pre, uri; PbReader q(g.b); PbField h;
                    while (q.next(h)) { if (h.num == 1 && h.wt == 2) pre = h.str(); else if (h.num == 2 && h.wt == 2) uri = h.str(); }
                    out.ns_decls.push_back({ pre, uri });
                    if (!uri.empty() && !doc.prefixes.count(uri)) doc.prefixes[uri] = pre;
                } else if (g.num == 2) out.ns = g.str();
                else if (g.num == 3) out.name = sanitize_utf8(g.str());
                else if (g.num == 4) {
                    XAttr a; PbReader q(g.b); PbField h; Bytes item; bool has_item = false;
                    while (q.next(h)) {
                        if (h.wt == 0 && h.num == 5) a.res_id = (uint32_t)h.v;
                        if (h.wt != 2) continue;
                        if (h.num == 1) a.ns = h.str();
                        else if (h.num == 2) a.name = sanitize_utf8(h.str());
                        else if (h.num == 3) a.str = sanitize_utf8(h.str());
                        else if (h.num == 6) { item = h.b; has_item = true; }
                    }
                    a.type = RT_STRING;
                    if (has_item) {
                        std::string s, rn; uint8_t t = RT_STRING; uint32_t dd = 0;
                        pb_item_to_value(item, t, dd, s, rn);
                        a.type = t; a.data = dd; a.ref_name = rn;
                        if (t == RT_STRING && !s.empty()) a.str = s;
                    }
                    if (a.name.empty() && a.res_id) { const char* an = android_attr_name(a.res_id); if (an) a.name = an; }
                    out.attrs.push_back(std::move(a));
                } else if (g.num == 5) {
                    auto k = std::make_unique<XNode>();
                    if (!node(g.b, *k, doc, depth + 1)) return false;
                    out.kids.push_back(std::move(k));
                }
            }
        }
    }
    return !r.bad;
}

bool parse_proto_xml(Bytes d, XDoc& doc) {
    doc.root = std::make_unique<XNode>();
    if (!node(d, *doc.root, doc, 0) || doc.root->name.empty()) {
        doc.error = "cannot decode protobuf XML";
        doc.root.reset();
        return false;
    }
    return true;
}
