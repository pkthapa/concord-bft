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

//#include <openssl/bio.h>
//#include <openssl/ec.h>
//#include <openssl/pem.h>
#include <openssl/x509.h>
//#include <openssl/evp.h>
#include <string>

namespace concord::util::openssl {
class CertificateUtils {
 public:
  static std::string generateSelfSignedCert(const std::string& origin_cert_path,
                                            const std::string& pub_key,
                                            const std::string& signing_key);
  static bool verifyCertificate(X509* cert, const std::string& pub_key);
  static bool verifyCertificate(X509* cert_to_verify,
                                const std::string& cert_root_directory,
                                uint32_t& remote_peer_id,
                                std::string& conn_type);
};
}  // namespace concord::util::openssl
