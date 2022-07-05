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

#include "base64.h"

#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>

namespace concord::secretsmanager {

using std::string;
using std::vector;
using std::unique_ptr;

string base64Enc(const vector<uint8_t>& cipher_text) {
#ifdef USE_CRYPTOPP_RSA
  CryptoPP::Base64Encoder encoder;
  encoder.Put(cipher_text.data(), cipher_text.size());
  encoder.MessageEnd();
  uint64_t output_size = encoder.MaxRetrievable();
  string output(output_size, '0');
  encoder.Get((unsigned char*)output.data(), output.size());

  return output;
#elif USE_EDDSA_SINGLE_SIGN
  if (cipher_text.capacity() == 0) {
    return {};
  }
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_write(bio, cipher_text.data(), cipher_text.capacity());

  BUF_MEM* bufferPtr{nullptr};
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_flush(bio);
  BIO_free_all(bio);

  string encodedMsg;
  encodedMsg.reserve((*bufferPtr).length);

  for (size_t i{0UL}; i < (*bufferPtr).length; ++i) {
    encodedMsg += (unsigned char)(*bufferPtr).data[i];
  }
  BUF_MEM_free(bufferPtr);
  return encodedMsg;
#endif
}

vector<uint8_t> base64Dec(const string& input) {
#ifdef USE_CRYPTOPP_RSA
  vector<uint8_t> dec;
  CryptoPP::StringSource ss(input, true, new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(dec)));
  return dec;
#elif USE_EDDSA_SINGLE_SIGN
  if (input.empty()) {
    return {};
  }
  string decodedOutput;
  decodedOutput.reserve(calcDecodeLength(input.data()));

  BIO* bio = BIO_new_mem_buf(input.data(), -1);
  BIO* b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  const int outputLen = BIO_read(bio, decodedOutput.data(), input.size());
  vector<uint8_t> dec(outputLen);

  for (int i = 0; i < outputLen; ++i) {
    dec[i] = (char)decodedOutput[i];  // Copy one character at a time.
  }

  BIO_free_all(bio);
  return dec;
#endif
}

size_t calcDecodeLength(const char* b64input) {
  const size_t len{strlen(b64input)};
  size_t padding{0};

  if ((b64input[len - 1] == '=') && (b64input[len - 2] == '=')) {  // Check if the last 2 characters are '=='
    padding = 2;
  } else if (b64input[len - 1] == '=') {  // Check if the last characters is '='
    padding = 1;
  }
  return (((len * 3) / 4) - padding);
}
}  // namespace concord::secretsmanager
