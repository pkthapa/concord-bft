// Concord
//
// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the sub-component's license, as noted in the LICENSE
// file.
#pragma once

#include <string>
#include <memory>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "crypto_interface.hpp"
#include "crypto_utils.hpp"

using std::string;
using std::unique_ptr;
using concord::util::crypto::KeyFormat;
using concord::util::cryptointerface::ISigner;
using concord::util::cryptointerface::IVerifier;

namespace concord::util::openssl_utils {

class CertificateUtils {
 public:
  static std::string generateSelfSignedCert(const std::string& origin_cert_path,
                                            const std::string& pub_key,
                                            const std::string& signing_key);
  static bool verifyCertificate(X509* cert, const std::string& pub_key);
  static bool verifyCertificate(X509* cert_to_verify,
                                const std::string& cert_root_directory,
                                uint32_t& remote_peer_id,
                                std::string& conn_type,
                                bool use_unified_certs);
};

// This class implements OpenSSL's EdDSA signer.
class EdDSA_Signer : public ISigner {
 public:
  EdDSA_Signer(const string& str_priv_key, KeyFormat fmt);
  string sign(const string& data) override;
  uint32_t signatureLength() const override;
  string getPrivKey() const override { return key_str_; }
  ~EdDSA_Signer() = default;

 private:
  class Impl;
  unique_ptr<Impl> impl_;
  string key_str_;
};

// This class implements OpenSSL's EdDSA verifier.
class EdDSA_Verifier : public IVerifier {
 public:
  EdDSA_Verifier(const string& str_pub_key, KeyFormat fmt);
  bool verify(const string& data, const string& sig) const override;
  uint32_t signatureLength() const override;
  string getPubKey() const override {
    return "";
    // return key_str_;
  }
  ~EdDSA_Verifier() = default;

 private:
  class Impl;
  unique_ptr<Impl> impl_;
  string key_str_;
};
}  // namespace concord::util::openssl_utils
