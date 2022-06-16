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
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.
//

#include "gtest/gtest.h"
#include "openssl_utils.hpp"
#include "Logger.hpp"

namespace {

using concord::crypto::openssl::Crypto;
using concord::crypto::openssl::EdDSASigner;
using concord::crypto::openssl::EdDSAVerifier;

TEST(openssl_utils, generate_eddsa_keys_hex_format) {
  ASSERT_NO_THROW(Crypto::instance().generateEdDSAKeyPair());
  auto keys = Crypto::instance().generateEdDSAKeyPair();
  LOG_INFO(GL, keys.first << " | " << keys.second);
}

TEST(openssl_utils, generate_eddsa_keys_pem_format) {
  ASSERT_NO_THROW(Crypto::instance().generateEdDSAKeyPair());
  auto keys = Crypto::instance().generateEdDSAKeyPair(KeyFormat::PemFormat);
  LOG_INFO(GL, keys.first << " | " << keys.second);
}

TEST(openssl_utils, generate_ECDSA_keys_pem_format) {
  ASSERT_NO_THROW(Crypto::instance().generateEdDSAKeyPair(KeyFormat::PemFormat));
  auto keys = Crypto::instance().generateEdDSAKeyPair(KeyFormat::PemFormat);
  LOG_INFO(GL, keys.first << " | " << keys.second);
}

TEST(openssl_utils, generate_ECDSA_keys_hex_format) {
  ASSERT_NO_THROW(Crypto::instance().generateEdDSAKeyPair(KeyFormat::HexaDecimalStrippedFormat));
  auto keys = Crypto::instance().generateEdDSAKeyPair(KeyFormat::HexaDecimalStrippedFormat);
  LOG_INFO(GL, keys.first << " | " << keys.second);
}

TEST(openssl_utils, test_eddsa_keys_hex) {
  auto keys = Crypto::instance().generateEdDSAKeyPair();
  EdDSASigner signer(keys.first, KeyFormat::HexaDecimalStrippedFormat);
  EdDSAVerifier verifier(keys.second, KeyFormat::HexaDecimalStrippedFormat);
  std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_pem) {
  auto keys = Crypto::instance().generateEdDSAKeyPair(KeyFormat::PemFormat);
  EdDSASigner signer(keys.first, KeyFormat::PemFormat);
  EdDSAVerifier verifier(keys.second, KeyFormat::PemFormat);
  std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_a) {
  auto keys = Crypto::instance().generateEdDSAKeyPair();
  auto pemKeys = Crypto::instance().EdDSAHexToPem(keys);
  EdDSASigner signer(keys.first, KeyFormat::HexaDecimalStrippedFormat);
  EdDSAVerifier verifier(pemKeys.second, KeyFormat::PemFormat);
  std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}

TEST(openssl_utils, test_eddsa_keys_combined_b) {
  auto keys = Crypto::instance().generateEdDSAKeyPair();
  auto pemKeys = Crypto::instance().EdDSAHexToPem(keys);
  EdDSASigner signer(pemKeys.first, KeyFormat::PemFormat);
  EdDSAVerifier verifier(keys.second, KeyFormat::HexaDecimalStrippedFormat);
  std::string data = "Hello VMworld";
  auto sig = signer.sign(data);
  ASSERT_TRUE(verifier.verify(data, sig));
}
}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
