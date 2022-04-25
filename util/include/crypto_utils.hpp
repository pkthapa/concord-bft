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

namespace concord::util::crypto {
enum class KeyFormat : std::uint16_t { HexaDecimalStrippedFormat, PemFormat };
enum class CurveType : std::uint16_t { secp256k1, secp384r1 };
}  // namespace concord::util::crypto