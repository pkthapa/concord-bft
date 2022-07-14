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
 * @param pemKey
 * @param KeyLength
 * @return std::vector<uint8_t> Generated key.
 */
template <typename ByteArrayKeyClass>
static std::vector<uint8_t> extractHexKeyFromPem(const std::string& pemKey, size_t KeyLength) {
  using concord::util::openssl_utils::UniquePKEY;
  using concord::util::openssl_utils::OPENSSL_SUCCESS;

  UniquePKEY pkey;
  auto deleter = [](FILE* fp) {
    if (nullptr != fp) {
      fclose(fp);
    }
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(tmpfile(), deleter);
  ConcordAssert(nullptr != fp);

  fputs(pemKey.data(), fp.get());
  rewind(fp.get());

  size_t keyLen{KeyLength};
  std::vector<uint8_t> key(KeyLength);

  if constexpr (std::is_same_v<ByteArrayKeyClass, EdDSAPrivateKey>) {
    pkey.reset(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(EVP_PKEY_get_raw_private_key(pkey.get(), &key[0], &keyLen), OPENSSL_SUCCESS);
  } else if constexpr (std::is_same_v<ByteArrayKeyClass, EdDSAPublicKey>) {
    pkey.reset(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(EVP_PKEY_get_raw_public_key(pkey.get(), &key[0], &keyLen), OPENSSL_SUCCESS);
  }
  return key;
}

/**
 * @brief Get the ByteArray Key Class object
 *
 * @tparam ByteArrayKeyClass
 * @param key
 * @param format
 * @return ByteArrayKeyClass
 */
template <typename ByteArrayKeyClass>
static ByteArrayKeyClass getByteArrayKeyClass(const std::string& key, concord::util::crypto::KeyFormat format) {
  using concord::util::crypto::KeyFormat;

  constexpr size_t keyLength = ByteArrayKeyClass::ByteSize;

  if (KeyFormat::PemFormat == format) {
    typename ByteArrayKeyClass::ByteArray resultBytes;
    std::memcpy(resultBytes.data(), extractHexKeyFromPem<ByteArrayKeyClass>(key, keyLength).data(), keyLength);
    return ByteArrayKeyClass{resultBytes};
  }
  return fromHexString<ByteArrayKeyClass>(key);
}
