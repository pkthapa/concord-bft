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
#include "crypto_interface.hpp"

namespace concord::util::openssl_utils {
enum class KeyFormat : std::uint16_t { HexaDecimalStrippedFormat, PemFormat };

// This class implements OpenSSL's EdDSA signer.
class EdDSA_Signer : public concord::util::cryptointerface::ISigner {
 public:
  EdDSA_Signer(const std::string& str_priv_key, KeyFormat fmt);
  std::string sign(const std::string& data) override;
  uint32_t signatureLength() const override;
  std::string getPrivKey() const override { return key_str_; }
  ~EdDSA_Signer();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
  std::string key_str_;
};

// This class implements OpenSSL's EdDSA verifier.
class EdDSA_Verifier : public concord::util::cryptointerface::IVerifier {
 public:
  EdDSA_Verifier(const std::string& str_pub_key, KeyFormat fmt);
  bool verify(const std::string& data, const std::string& sig) const override;
  uint32_t signatureLength() const override;
  std::string getPubKey() const override { return key_str_; }
  ~EdDSA_Verifier();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
  std::string key_str_;
};
}  // namespace concord::util::openssl_utils