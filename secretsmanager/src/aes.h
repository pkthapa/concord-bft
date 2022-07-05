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

#pragma once

#include <vector>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#include "key_params.h"

namespace concord::secretsmanager {

using std::string;
using std::vector;
using std::unique_ptr;

class AES_CBC {
#ifdef USE_CRYPTOPP_RSA
  CryptoPP::AES::Encryption aesEncryption;
  CryptoPP::AES::Decryption aesDecryption;
  CryptoPP::CBC_Mode_ExternalCipher::Encryption enc;
  CryptoPP::CBC_Mode_ExternalCipher::Decryption dec;
#elif USE_EDDSA_SINGLE_SIGN
  vector<uint8_t> key;
  vector<uint8_t> iv;
#endif

 public:
  static size_t getBlockSize() { return CryptoPP::AES::BLOCKSIZE; }
  AES_CBC(const KeyParams& params);
  vector<uint8_t> encrypt(const string& input) const;
  string decrypt(const vector<uint8_t>& cipher) const;
};

}  // namespace concord::secretsmanager