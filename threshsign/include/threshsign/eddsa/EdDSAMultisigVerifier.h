// Concord
//
// Copyright (c) 2018-2022 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
#pragma once
#include "threshsign/IThresholdVerifier.h"
#include "SingleEdDSASignature.h"
#include "crypto/eddsa/EdDSAVerifier.hpp"
#include "EdDSAThreshsignKeys.h"

class EdDSAMultisigVerifier;

class EdDSASignatureAccumulator : public IThresholdAccumulator {
 public:
  EdDSASignatureAccumulator();
  int add(const char *sigShareWithId, int len) override;
  void setExpectedDigest(const unsigned char *msg, int len) override;
  size_t getFullSignedData(char *outThreshSig, int threshSigLen) override;
  bool hasShareVerificationEnabled() const override;
  int getNumValidShares() const override;
  std::set<ShareID> getInvalidShareIds() const override;

 private:
  /// Accumulated signatures
  std::unordered_map<uint32_t, SingleEdDSASignature> signatures_;
  std::string expectedMsgDigest_;
};

class EdDSAMultisigVerifier : public IThresholdVerifier {
 public:
  using SingleVerifier = EdDSAVerifier<EdDSAThreshsignPublicKey>;
  EdDSAMultisigVerifier(const std::vector<SingleVerifier> &verifiers,
                        const size_t signersCount,
                        const size_t threshold);
  IThresholdAccumulator *newAccumulator(bool withShareVerification) const override;

  bool verify(const char *msg, int msgLen, const char *sig, int sigLen) const override;

  int requiredLengthForSignedData() const override;
  const IPublicKey &getPublicKey() const override;
  const IShareVerificationKey &getShareVerificationKey(ShareID signer) const override;
  bool verifySingleSignature(const uint8_t *msg,
                             size_t msgLen,
                             const SingleEdDSASignature &signature,
                             const SingleVerifier &verifier) const;
  ~EdDSAMultisigVerifier() override = default;

 private:
  std::vector<SingleVerifier> verifiers_;
  const size_t signersCount_;
  const size_t threshold_;
};