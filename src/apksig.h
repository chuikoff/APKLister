// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "zip.h"
#include "der.h"

struct SigSigner {
    std::vector<CertInfo> certs;
    std::vector<uint32_t> sig_algs, digest_algs;
    int min_sdk = -1, max_sdk = -1;
    std::string pubkey_sha256;
    std::vector<std::pair<uint32_t, size_t>> attrs; // additional attributes id,size
    std::vector<CertInfo> lineage;
    std::string error;
};
struct V1File { std::string name, kind; std::vector<CertInfo> certs; std::string error; std::vector<std::pair<std::string, std::string>> headers; };
struct SigInfo {
    bool v1 = false, v2 = false, v3 = false, v31 = false, v4 = false, stamp = false;
    std::vector<SigSigner> v2s, v3s, v31s;
    std::vector<V1File> v1files;
    std::vector<std::pair<std::string, std::string>> manifest_headers;
    size_t manifest_entries = 0;
    std::vector<CertInfo> stamp_certs;
    std::string stamp_file_sha256;
    std::vector<std::pair<uint32_t, uint64_t>> blocks; // id, size
    std::string idsig_note;
};
void analyze_signatures(const Zip& z, const std::string& prefix, SigInfo& si);
const char* sig_block_name(uint32_t id);
std::string sig_alg_name(uint32_t id);
