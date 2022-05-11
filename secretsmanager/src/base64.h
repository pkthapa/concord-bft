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

#include <string>
#include <vector>
#include <memory>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace concord::secretsmanager {
using std::string;
using std::vector;
using std::unique_ptr;

/*
 * Encode message to Base64 string.
 * @param cipher_text (input) Message to be encoded.
 * @return Base64 encoded message.
 */
string base64Enc(const vector<uint8_t>& cipher_text);

/*
 * Decode Base64 string.
 * @param b64message (input) Base64 encoded message.
 * @return Decoded, but encrypted message.
 */
vector<uint8_t> base64Dec(const string& input);

size_t calcDecodeLength(const char* b64input);

}  // namespace concord::secretsmanager