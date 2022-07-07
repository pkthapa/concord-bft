// Concord
//
// Copyright (c) 2018-2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
#pragma once
#include "SerializableByteArray.hpp"
#include "crypto_utils.hpp"
#include "openssl_crypto.hpp"
#include "hex_tools.h"

using concord::util::crypto::KeyFormat;
using concord::util::openssl_utils::UniquePKEY;
using concord::util::openssl_utils::OPENSSL_SUCCESS;

static constexpr const size_t EdDSAPrivateKeyByteSize = 32UL;
static constexpr const size_t EdDSAPublicKeyByteSize = 32UL;
static constexpr const size_t EdDSASignatureByteSize = 64UL;

class EdDSAPrivateKey : public SerializableByteArray<EdDSAPrivateKeyByteSize> {
 public:
  EdDSAPrivateKey(const EdDSAPrivateKey::ByteArray& arr) : SerializableByteArray<EdDSAPrivateKeyByteSize>(arr) {}
};

class EdDSAPublicKey : public SerializableByteArray<EdDSAPublicKeyByteSize> {
 public:
  EdDSAPublicKey(const EdDSAPublicKey::ByteArray& arr) : SerializableByteArray<EdDSAPublicKeyByteSize>(arr) {}
};

/**
 * @brief Generate hex format key from pem file.
 *
 * @tparam ByteArrayKeyClass
 * @tparam KeyLength
 * @param pemKey
 * @return std::vector<uint8_t> Generated key.
 */
template <typename ByteArrayKeyClass, size_t KeyLength>
static std::vector<uint8_t> extractHexKeyFromPem(const std::string& pemKey) {
  UniquePKEY pkey;
  const std::string temp{"/tmp/concordTempKey.pem"};

  std::ofstream out(temp.data());
  out << pemKey;
  out.close();

  auto deleter = [](FILE* fp) {
    if (nullptr != fp) {
      fclose(fp);
    }
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(fopen(temp.data(), "r"), deleter);
  if (nullptr == fp) {
    LOG_ERROR(EDDSA_SIG_LOG, "Unable to open private key file to initialize signer." << KVLOG(fp.get(), pemKey));
    std::terminate();
  }

  size_t keyLen{KeyLength};
  unsigned char extractedKey[KeyLength]{'\0'};

  if constexpr (std::is_same_v<ByteArrayKeyClass, EdDSAPrivateKey>) {
    pkey.reset(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(
        EVP_PKEY_get_raw_private_key(pkey.get(), extractedKey, &keyLen),  // Extract private key in 'extractedKey'.
        OPENSSL_SUCCESS);
  } else if constexpr (std::is_same_v<ByteArrayKeyClass, EdDSAPublicKey>) {
    pkey.reset(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(
        EVP_PKEY_get_raw_public_key(pkey.get(), extractedKey, &keyLen),  // Extract public key in 'extractedKey'.
        OPENSSL_SUCCESS);
  }

  const std::vector<uint8_t> key(extractedKey, extractedKey + keyLen);
  remove(temp.data());
  return key;
}

/**
 * @brief Get the ByteArray Key Class object
 *
 * @tparam ByteArrayKeyClass
 * @tparam KeyLength
 * @param key
 * @param format
 * @return ByteArrayKeyClass
 */
template <typename ByteArrayKeyClass, size_t KeyLength>
static ByteArrayKeyClass getByteArrayKeyClass(const std::string& key, KeyFormat format) {
  std::vector<uint8_t> extractedKey;

  if (KeyFormat::PemFormat == format) {
    extractedKey = extractHexKeyFromPem<ByteArrayKeyClass, KeyLength>(key);
  } else if (KeyFormat::HexaDecimalStrippedFormat == format) {
    extractedKey = concordUtils::unhex(key);
  }
  ConcordAssertEQ(extractedKey.size(), KeyLength);

  typename ByteArrayKeyClass::ByteArray resultBytes;
  std::memcpy(resultBytes.data(), extractedKey.data(), extractedKey.size());
  return ByteArrayKeyClass{resultBytes};
}
