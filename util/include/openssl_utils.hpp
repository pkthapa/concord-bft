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
using concord::util::cryptointerface::ISigner;
using concord::util::cryptointerface::IVerifier;

namespace concord::crypto::openssl {

constexpr static size_t EdDSA_SIG_LENGTH{64};

// Deleter classes.
class EVP_PKEY_Deleter {
 public:
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

class EVP_MD_CTX_Deleter {
 public:
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};

class EVP_PKEY_CTX_Deleter {
 public:
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};

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
class EdDSASigner : public ISigner {
 public:
  /*
   * Constructor to initialize a signer.
   * @param strPrivKey Private key.
   * @param fmt Format of the private key (HexaDecimalStrippedFormat & PemFormat).
   */
  EdDSASigner(const string& strPrivKey, KeyFormat fmt);

  /*
   * Signs and returns the signature.
   * @param dataToSign Data to sign.
   * @return Generated signature in string format.
   */
  string sign(const string& dataToSign) override;

  /*
   * Gets the signature length.
   * @return Length of the signature.
   */
  uint32_t signatureLength() const override;

  /*
   * Gets the private key in string format.
   * @return Private key in string format.
   */
  string getPrivKey() const override;

 private:
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> edPkey_;
  size_t sigLen_{EdDSA_SIG_LENGTH};
  string keyStr_;
};

// This class implements OpenSSL's EdDSA verifier.
class EdDSAVerifier : public IVerifier {
 public:
  /*
   * Constructor to initialize a verifier.
   * @param strPubKey Public key.
   * @param fmt Format of the public key (HexaDecimalStrippedFormat & PemFormat).
   */
  EdDSAVerifier(const string& strPubKey, KeyFormat fmt);

  /*
   * Verifies the signature.
   * @param dataToVerify Data to verify with 'sigToVerify'.
   * @param sigToVerify Generated signature to verify with 'dataToVerify'.
   * @return Verification result.
   */
  bool verify(const string& dataToVerify, const string& sigToVerify) const override;

  /*
   * Gets the signature length.
   * @return Length of the signature.
   */
  uint32_t signatureLength() const override;

  /*
   * Gets the public key in string format.
   * @return Public key in string format.
   */
  string getPubKey() const override;

 private:
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> edPkey_;
  mutable size_t sigLen_{EdDSA_SIG_LENGTH};
  string keyStr_;
};

class Crypto {
 public:
  static Crypto& instance() {
    static Crypto crypto;
    return crypto;
  }

  Crypto() = default;
  ~Crypto() = default;

  /**
   * @brief Generates an EdDSA asymmetric key pair (private-public key pair).
   *
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
};
}  // namespace concord::crypto::openssl
