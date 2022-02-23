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

#include "openssl_utils.hpp"
namespace concord::util::openssl_utils {
class EdDSA_Signer::Impl {};

EdDSA_Signer::EdDSA_Signer(const std::string& str_priv_key, KeyFormat fmt) {}
std::string EdDSA_Signer::sign(const std::string& data) {}
uint32_t EdDSA_Signer::signatureLength() const {}

EdDSA_Verifier::EdDSA_Verifier(const std::string& str_pub_key, KeyFormat fmt) {}
bool EdDSA_Verifier::verify(const std::string& data, const std::string& sig) const {}
uint32_t EdDSA_Verifier::signatureLength() const {}
}  // namespace concord::util::openssl_utils