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

#include <string>

namespace concord::crypto {

// Interface for verifier.
class IVerifier {
 public:
  virtual bool verify(const std::string& data, const std::string& sig) const = 0;
  virtual uint32_t signatureLength() const = 0;
  virtual ~IVerifier() = default;
  virtual std::string getPubKey() const = 0;
};

// Interface for signer.
class ISigner {
 public:
  virtual std::string sign(const std::string& data) = 0;
  virtual uint32_t signatureLength() const = 0;
  virtual ~ISigner() = default;
  virtual std::string getPrivKey() const = 0;
};
}  // namespace concord::crypto
