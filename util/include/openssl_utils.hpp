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
#include <fstream>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "crypto_interface.hpp"
#include "crypto_utils.hpp"

using std::pair;
using std::make_pair;
using std::string;
using std::unique_ptr;
using std::ofstream;
using concord::util::crypto::KeyFormat;
using concord::crypto::ISigner;
using concord::crypto::IVerifier;

namespace concord::crypto::openssl {

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

class OpenSSLCryptoImpl {
 public:
  static OpenSSLCryptoImpl& instance() {
    static OpenSSLCryptoImpl crypto;
    return crypto;
  }

  OpenSSLCryptoImpl() = default;
  ~OpenSSLCryptoImpl() = default;

  /**
   * @brief Generates an EdDSA asymmetric key pair (private-public key pair).
   *
   * @param fmt Output key format.
   * @return pair<string, string> Private-Public key pair.
   */
  pair<string, string> generateEdDSAKeyPair(const KeyFormat fmt = KeyFormat::HexaDecimalStrippedFormat) const;

  /**
   * @brief Generates an EdDSA PEM file from hexadecimal key pair (private-public key pair).
   *
   * @param key_pair Key pair in hexa-decimal format.
   * @return pair<string, string>
   */
  pair<string, string> EdDSAHexToPem(const std::pair<std::string, std::string>& hex_key_pair) const;

  /**
   * @brief Returns the key's format.
   *
   * @param key
   * @return KeyFormat
   */
  KeyFormat getFormat(const std::string& key) const;
};
}  // namespace concord::crypto::openssl
