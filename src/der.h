// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "util.h"

struct Tlv { uint8_t tag = 0; Bytes content; Bytes whole; bool constructed() const { return (tag & 0x20) != 0; } };
// parses one TLV at the beginning of b (DER, plus BER indefinite lengths); returns false on error
bool der_next(Bytes b, Tlv& t, int depth = 0);
std::vector<Tlv> der_children(Bytes content);
std::string oid_to_string(Bytes c);

struct CertInfo {
    bool ok = false;
    std::string error;
    int version = 1;
    std::string serial_hex, serial_dec;
    std::string subject, issuer;
    std::string not_before, not_after;
    std::string sig_alg, key_alg;
    int key_bits = 0;
    std::string curve;
    std::string md5, sha1, sha256;     // of DER certificate
    std::string pubkey_sha256;         // of SubjectPublicKeyInfo
    bool self_signed = false;
    size_t der_size = 0;
};
CertInfo parse_cert(Bytes der);
// PKCS#7 SignedData -> certificates (DER blobs)
bool pkcs7_certs(Bytes data, std::vector<Bytes>& certs, std::string& err);
