// Concord
//
// Copyright (c) 2018 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.

#pragma once

#ifdef USE_RELIC
#include "bls/relic/BlsThresholdScheme.h"

// RELIC has a #define PRIME which conflicts with CryptoPP's Integer::PRIME, so we #undef PRIME here
// before including the Shoup code.
#undef PRIME
// ...also RELIC has a #define HASH that conflicts as well
#undef HASH
#endif

#ifdef USE_EDDSA_OPENSSL
#include "eddsa/EdDSAMultisigFactory.h"
#endif
