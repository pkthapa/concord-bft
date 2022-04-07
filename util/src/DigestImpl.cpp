// Concord
//
// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").  You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include <string.h>
#include <iomanip>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <cryptopp/dll.h>
#include <cryptopp/pem.h>
#pragma GCC diagnostic pop

#include "assertUtils.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/ida.h>
#include <cryptopp/eccrypto.h>

#include "Digest.hpp"
#include "DigestImpl.ipp"

#if defined MD5_DIGEST
#include <cryptopp/md5.h>
#define DigestType Weak1::MD5
#elif defined SHA256_DIGEST
#define DigestType SHA256
#elif defined SHA512_DIGEST
#define DigestType SHA512
#endif

using namespace CryptoPP;

namespace concord::util::digest {

////////////////////////////////////////////
// CryptoppDigestCreator implementations.
////////////////////////////////////////////
CryptoppDigestCreator::CryptoppDigestCreator() {
  DigestType* p = new DigestType();
  internalState = p;
}

size_t CryptoppDigestCreator::digestLength() { return DigestType::DIGESTSIZE; }

bool CryptoppDigestCreator::compute(const char* input,
                                    size_t inputLength,
                                    char* outBufferForDigest,
                                    size_t lengthOfBufferForDigest) {
  DigestType dig;

  const size_t size = dig.DigestSize();

  if (lengthOfBufferForDigest < size) {
    return false;
  }

  SecByteBlock digest(size);

  dig.Update((CryptoPP::byte*)input, inputLength);
  dig.Final(digest);

  const CryptoPP::byte* h = digest;
  memcpy(outBufferForDigest, h, size);

  return true;
}

void CryptoppDigestCreator::update(const char* data, size_t len) {
  // void CryptoppDigestCreator::Context::update(const char* data, size_t len) {
  ConcordAssert(nullptr != internalState);

  DigestType* p = (DigestType*)internalState;
  p->Update((CryptoPP::byte*)data, len);
}

void CryptoppDigestCreator::writeDigest(char* outDigest) {
  // void CryptoppDigestCreator::Context::writeDigest(char* outDigest) {
  ConcordAssert(nullptr != internalState);

  DigestType* p = (DigestType*)internalState;
  SecByteBlock digest(digestLength());
  p->Final(digest);
  const CryptoPP::byte* h = digest;
  memcpy(outDigest, h, digestLength());

  delete p;
  internalState = nullptr;
}

CryptoppDigestCreator::~CryptoppDigestCreator() {
  if (nullptr != internalState) {
    DigestType* p = (DigestType*)internalState;
    delete p;
    internalState = nullptr;
  }
}
}  // namespace concord::util::digest
