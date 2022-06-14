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

namespace concord::util::signerverifier {
#ifdef USE_CRYPTOPP
using TransactionSigner = concord::util::cryptopp_utils::RSASigner;
using TransactionVerifier = concord::util::cryptopp_utils::RSAVerifier;
#elif USE_EDDSA_OPENSSL
using TransactionSigner = concord::util::openssl_utils::EdDSASigner;
using TransactionVerifier = concord::util::openssl_utils::EdDSAVerifier;
#endif
}  // namespace concord::util::signerverifier