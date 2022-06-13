// Concord
//
// Copyright (c) 2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the
// "License").  You may not use this product except in compliance with the
// Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.
//
// This convenience header combines different block implementations.

#include "aes.h"

#include <cryptopp/filters.h>

#include "assertUtils.hpp"

namespace concord::secretsmanager {

class EVP_CIPHER_CTX_Deleter {
 public:
  void operator()(EVP_CIPHER_CTX* p) { EVP_CIPHER_CTX_free(p); }
};

class BIO_Deleter {
 public:
  void operator()(BIO* p) { BIO_free_all(p); }
};

AES_CBC::AES_CBC(const KeyParams& params) {
#ifdef USE_CRYPTOPP
  ConcordAssertEQ(params.key.size(), 256 / 8);
  aesEncryption = CryptoPP::AES::Encryption(params.key.data(), params.key.size());
  aesDecryption = CryptoPP::AES::Decryption(params.key.data(), params.key.size());
  enc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aesEncryption, params.iv.data());
  dec = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aesDecryption, params.iv.data());
#elif USE_EDDSA_OPENSSL
  key = params.key;
  iv = params.iv;
#endif
}

vector<uint8_t> AES_CBC::encrypt(const string& input) const {
#ifdef USE_CRYPTOPP
  vector<uint8_t> cipher;
  CryptoPP::StringSource ss(
      input, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(cipher)));
  return cipher;
#elif USE_EDDSA_OPENSSL
  if (input.empty()) {
    return {};
  }

  auto deleter = [](unsigned char* p) {
    if (nullptr != p) {
      delete[] p;
    }
  };
  unique_ptr<unsigned char, decltype(deleter)> ciphertext(new unsigned char[input.size() + AES_BLOCK_SIZE], deleter);
  unique_ptr<unsigned char, decltype(deleter)> plaintext(new unsigned char[input.size() + 1], deleter);

  for (size_t i{0UL}; i < input.size(); ++i) {
    plaintext.get()[i] = (unsigned char)input[i];
  }

  unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
  ConcordAssert(nullptr != ctx);

  int c_len{0};
  int f_len{0};

  ConcordAssert(1 == EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()));
  ConcordAssert(1 == EVP_EncryptUpdate(ctx.get(), ciphertext.get(), &c_len, plaintext.get(), input.size()));
  ConcordAssert(1 == EVP_EncryptFinal_ex(ctx.get(), ciphertext.get() + c_len, &f_len));

  const int encryptedMsgLen = c_len + f_len;
  vector<uint8_t> cipher(encryptedMsgLen);
  for (int i = 0; i < encryptedMsgLen; ++i) {
    cipher[i] = (unsigned char)ciphertext.get()[i];  // Copy one character at a time.
  }
  return cipher;
#endif
}

string AES_CBC::decrypt(const vector<uint8_t>& cipher) const {
#ifdef USE_CRYPTOPP
  string pt;
  CryptoPP::VectorSource ss(cipher, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(pt)));
  return pt;
#elif USE_EDDSA_OPENSSL
  if (cipher.capacity() == 0) {
    return {};
  }
  const int cipherLength = cipher.capacity();
  int c_len{0}, f_len{0};

  auto deleter = [](unsigned char* p) {
    if (nullptr != p) {
      delete[] p;
    }
  };
  unique_ptr<unsigned char, decltype(deleter)> plaintext(new unsigned char[cipherLength], deleter);

  unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
  ConcordAssert(nullptr != ctx);

  ConcordAssert(1 == EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()));
  EVP_CIPHER_CTX_set_key_length(ctx.get(), EVP_MAX_KEY_LENGTH);
  ConcordAssert(
      1 == EVP_DecryptUpdate(ctx.get(), plaintext.get(), &c_len, (const unsigned char*)cipher.data(), cipherLength));
  ConcordAssert(1 == EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + c_len, &f_len));

  plaintext.get()[c_len + f_len] = 0;

  vector<uint8_t> temp(c_len + f_len);
  for (int i{0}; i < c_len + f_len; ++i) {
    temp[i] = plaintext.get()[i];
  }
  return string(temp.begin(), temp.end());
#endif
}
}  // namespace concord::secretsmanager