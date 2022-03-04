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

// Deleter classes.
class EVP_PKEY_CTX_Deleter {
 public:
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};

class EVP_MD_CTX_Deleter {
 public:
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};

class EdDSA_Signer::Impl {};

EdDSA_Signer::EdDSA_Signer(const string& str_priv_key, KeyFormat fmt) {}

string EdDSA_Signer::sign(const string& data) {
  EVP_PKEY* ed_pkey = nullptr;
  // EVP_MD_CTX* ed_mdctx = nullptr;

  unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ed_mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_Deleter());
  if (nullptr == ed_mdctx) {
  }

  unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ed_pctx(EVP_PKEY_CTX_new_id(NID_ED25519, nullptr),
                                                         EVP_PKEY_CTX_Deleter());
  if ((nullptr == ed_pctx) || (EVP_PKEY_keygen_init(ed_pctx.get()) <= 0) ||
      (EVP_PKEY_keygen(ed_pctx.get(), &ed_pkey) <= 0)) {
    // EVP_PKEY_CTX_free(ed_pctx.get());
  }

  if (!EVP_DigestSignInit(ed_mdctx.get(), nullptr, nullptr, nullptr, ed_pkey)) {
    EVP_PKEY_free(ed_pkey);
  }

  size_t siglen{0}, tbslen{64};
  string signature(64, 0);
  if (0 == EVP_DigestSign(ed_mdctx.get(),
                          reinterpret_cast<unsigned char*>(signature.data()),
                          &siglen,
                          reinterpret_cast<const unsigned char*>(data.data()),
                          tbslen)) {
  }
  return signature;
}

uint32_t EdDSA_Signer::signatureLength() const { return 0; }

class EdDSA_Verifier::Impl {};

EdDSA_Verifier::EdDSA_Verifier(const string& str_pub_key, KeyFormat fmt) {}

bool EdDSA_Verifier::verify(const string& data, const string& sig) const { return true; }

uint32_t EdDSA_Verifier::signatureLength() const { return 0; }
}  // namespace concord::util::openssl_utils