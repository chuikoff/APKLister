// SPDX-License-Identifier: GPL-2.0-or-later
// Common XML DOM produced by both the binary AXML decoder and the AAB protobuf decoder.
#pragma once
#include "util.h"
#include <memory>
#include <map>

class Resources;

enum ResType : uint8_t {
    RT_NULL = 0x00, RT_REFERENCE = 0x01, RT_ATTRIBUTE = 0x02, RT_STRING = 0x03, RT_FLOAT = 0x04,
    RT_DIMENSION = 0x05, RT_FRACTION = 0x06, RT_DYN_REF = 0x07, RT_DYN_ATTR = 0x08,
    RT_INT_DEC = 0x10, RT_INT_HEX = 0x11, RT_BOOL = 0x12,
    RT_COLOR_ARGB8 = 0x1c, RT_COLOR_RGB8 = 0x1d, RT_COLOR_ARGB4 = 0x1e, RT_COLOR_RGB4 = 0x1f
};

struct XAttr {
    std::string ns, name;   // ns = namespace URI
    uint32_t res_id = 0;
    uint8_t type = RT_STRING;
    uint32_t data = 0;
    std::string str;        // raw string value / textual value
    std::string ref_name;   // e.g. "string/app_name" (proto manifests carry it)
};

struct XNode {
    std::string ns, name, text;
    bool is_text = false;
    int line = 0;
    std::vector<XAttr> attrs;
    std::vector<std::unique_ptr<XNode>> kids;
    std::vector<std::pair<std::string, std::string>> ns_decls; // prefix, uri
    const XAttr* attr(const char* name) const; // android-namespace or plain name
    std::vector<const XNode*> children(const char* name) const;
    const XNode* child(const char* name) const;
};

struct XDoc {
    std::unique_ptr<XNode> root;
    std::map<std::string, std::string> prefixes; // uri -> prefix
    std::string error;
    int string_count = 0; bool utf8_pool = false; int res_map_count = 0;
};

extern const char* ANDROID_NS;
const char* android_attr_name(uint32_t id);
std::string format_value(const XAttr& a, const Resources* res);
std::string to_xml(const XDoc& d, const Resources* res);
bool parse_axml(Bytes data, XDoc& doc);
bool parse_proto_xml(Bytes data, XDoc& doc);
float u32_as_float(uint32_t v);
std::string complex_to_string(uint32_t data, bool fraction);
