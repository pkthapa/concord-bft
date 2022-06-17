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

#include "openssl_utils.hpp"

namespace concord::signerverifier {
#ifdef USE_CRYPTOPP_RSA
using TransactionSigner = concord::crypto::cryptopp::RSASigner;
using TransactionVerifier = concord::crypto::cryptopp::RSAVerifier;
#elif USE_EDDSA_SINGLE_SIGN
using TransactionSigner = concord::crypto::openssl::EdDSASigner;
using TransactionVerifier = concord::crypto::openssl::EdDSAVerifier;
#endif
}  // namespace concord::signerverifier