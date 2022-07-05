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

#ifdef USE_CRYPTOPP_RSA
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#elif USE_EDDSA_SINGLE_SIGN
#include <openssl/aes.h>
#endif

#include "key_params.h"

namespace concord::secretsmanager {

class AES_CBC {
#ifdef USE_CRYPTOPP_RSA
  CryptoPP::AES::Encryption aesEncryption;
  CryptoPP::AES::Decryption aesDecryption;
  CryptoPP::CBC_Mode_ExternalCipher::Encryption enc;
  CryptoPP::CBC_Mode_ExternalCipher::Decryption dec;
#elif USE_EDDSA_SINGLE_SIGN
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
#endif

 public:
  AES_CBC(const KeyParams& params);
  std::vector<uint8_t> encrypt(const std::string& input) const;
  std::string decrypt(const std::vector<uint8_t>& cipher) const;
};

}  // namespace concord::secretsmanager
