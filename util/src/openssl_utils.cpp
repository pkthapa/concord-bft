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
#include "Logger.hpp"
#include "assertUtils.hpp"
#include "hex_tools.h"
#include "openssl_crypto.hpp"
#include "crypto/eddsa/EdDSA.hpp"
#include "io.hpp"

#include <regex>
#include <utility>

namespace concord::crypto::openssl {
using std::pair;
using std::rewind;
using std::string;
using std::unique_ptr;
using concord::util::crypto::KeyFormat;
using concord::util::openssl_utils::UniquePKEY;
using concord::util::openssl_utils::UniqueOpenSSLPKEYContext;
using concord::util::openssl_utils::UniqueOpenSSLX509;
using concord::util::openssl_utils::UniqueOpenSSLBIO;
using concord::util::openssl_utils::OPENSSL_SUCCESS;
using concord::util::openssl_utils::OPENSSL_FAILURE;
using concord::util::openssl_utils::OPENSSL_ERROR;

string CertificateUtils::generateSelfSignedCert(const string& origin_cert_path,
                                                const string& public_key,
                                                const string& signing_key) {
  auto deleter = [](FILE* fp) {
    if (nullptr != fp) {
      fclose(fp);
    }
  };
  unique_ptr<FILE, decltype(deleter)> fp(fopen(origin_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(OPENSSL_LOG, "Certificate file not found, path: " << origin_cert_path);
    return string();
  }

  UniqueOpenSSLX509 cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    LOG_ERROR(OPENSSL_LOG, "Cannot parse certificate, path: " << origin_cert_path);
    return string();
  }

  UniquePKEY priv_key(EVP_PKEY_new());
  UniqueOpenSSLBIO priv_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(priv_bio.get(), static_cast<const char*>(signing_key.c_str()), signing_key.size()) <= 0) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create private key object");
    return string();
  }

  if (!PEM_read_bio_PrivateKey(priv_bio.get(), reinterpret_cast<EVP_PKEY**>(&priv_key), nullptr, nullptr)) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create private key object");
    return string();
  }
  UniquePKEY pub_key(EVP_PKEY_new());
  UniqueOpenSSLBIO pub_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(pub_bio.get(), static_cast<const char*>(public_key.c_str()), public_key.size()) <= 0) {
    LOG_ERROR(OPENSSL_LOG, "Unable to write public key object");
    return string();
  }
  if (!PEM_read_bio_PUBKEY(pub_bio.get(), reinterpret_cast<EVP_PKEY**>(&pub_key), nullptr, nullptr)) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create public key object");
    return string();
  }

  if (OPENSSL_FAILURE == X509_set_pubkey(cert.get(), pub_key.get())) {
    LOG_ERROR(OPENSSL_LOG, "Failed to set public key for certificate.");
    return {};
  }

  if (OPENSSL_FAILURE == X509_sign(cert.get(), priv_key.get(), EVP_sha256())) {
    LOG_ERROR(OPENSSL_LOG, "Failed to sign certificate using private key.");
    return {};
  }

  UniqueOpenSSLBIO outbio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(outbio.get(), cert.get())) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create certificate object");
    return string();
  }
  string certStr;
  int certLen = BIO_pending(outbio.get());
  certStr.resize(certLen);
  const auto res = BIO_read(outbio.get(), (void*)&(certStr.front()), certLen);
  if (OPENSSL_FAILURE == res or OPENSSL_ERROR == res) {
    LOG_ERROR(OPENSSL_LOG, "Failed to read data from the BIO certifiate object.");
    return {};
  }
  return certStr;
}

bool CertificateUtils::verifyCertificate(X509& cert, const string& public_key) {
  UniquePKEY pub_key(EVP_PKEY_new());
  UniqueOpenSSLBIO pub_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(pub_bio.get(), static_cast<const char*>(public_key.c_str()), public_key.size()) <= 0) {
    return false;
  }
  if (!PEM_read_bio_PUBKEY(pub_bio.get(), reinterpret_cast<EVP_PKEY**>(&pub_key), nullptr, nullptr)) {
    return false;
  }
  return (bool)X509_verify(&cert, pub_key.get());
}

bool CertificateUtils::verifyCertificate(const X509& cert_to_verify,
                                         const string& cert_root_directory,
                                         uint32_t& remote_peer_id,
                                         string& conn_type,
                                         bool use_unified_certs) {
  // First get the source ID
  static constexpr size_t SIZE = 512;
  string subject(SIZE, 0);
  X509_NAME_oneline(X509_get_subject_name(&cert_to_verify), subject.data(), SIZE);

  int peerIdPrefixLength = 3;
  std::regex r("OU=\\d*", std::regex_constants::icase);
  std::smatch sm;
  regex_search(subject, sm, r);
  if (sm.length() <= peerIdPrefixLength) {
    LOG_ERROR(OPENSSL_LOG, "OU not found or empty: " << subject);
    return false;
  }

  auto remPeer = sm.str().substr(peerIdPrefixLength, sm.str().length() - peerIdPrefixLength);
  if (0 == remPeer.length()) {
    LOG_ERROR(OPENSSL_LOG, "OU empty " << subject);
    return false;
  }

  uint32_t remotePeerId;
  try {
    remotePeerId = stoul(remPeer, nullptr);
  } catch (const std::invalid_argument& ia) {
    LOG_ERROR(OPENSSL_LOG, "cannot convert OU, " << subject << ", " << ia.what());
    return false;
  } catch (const std::out_of_range& e) {
    LOG_ERROR(OPENSSL_LOG, "cannot convert OU, " << subject << ", " << e.what());
    return false;
  }
  remote_peer_id = remotePeerId;
  string CN;
  CN.resize(SIZE);
  X509_NAME_get_text_by_NID(X509_get_subject_name(&cert_to_verify), NID_commonName, CN.data(), SIZE);
  string cert_type = "server";
  if (CN.find("cli") != string::npos) {
    cert_type = "client";
  }
  conn_type = cert_type;

  // Get the local stored certificate for this peer
  string local_cert_path =
      (use_unified_certs)
          ? cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + "node.cert"
          : cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + cert_type + "/" + cert_type + ".cert";
  auto deleter = [](FILE* fp) {
    if (nullptr != fp) {
      fclose(fp);
    }
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(fopen(local_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(OPENSSL_LOG, "Certificate file not found, path: " << local_cert_path);
    return false;
  }

  UniqueOpenSSLX509 localCert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
  if (!localCert) {
    LOG_ERROR(OPENSSL_LOG, "Cannot parse certificate, path: " << local_cert_path);
    return false;
  }

  // this is actual comparison, compares hash of 2 certs
  bool res = (X509_cmp(&cert_to_verify, localCert.get()) == 0);
  return res;
}

pair<string, string> OpenSSLCryptoImpl::generateEdDSAKeyPair(const KeyFormat fmt) const {
  UniquePKEY edPkey;
  UniqueOpenSSLPKEYContext edPkeyCtx(EVP_PKEY_CTX_new_id(NID_ED25519, nullptr));

  ConcordAssertNE(edPkeyCtx, nullptr);

  ConcordAssertEQ(OPENSSL_SUCCESS, EVP_PKEY_keygen_init(edPkeyCtx.get()));
  ConcordAssertEQ(
      OPENSSL_SUCCESS,
      EVP_PKEY_keygen(edPkeyCtx.get(), reinterpret_cast<EVP_PKEY**>(&edPkey)));  // Generate EdDSA key 'edPkey'.

  unsigned char privKey[EdDSASignatureByteSize]{};
  unsigned char pubKey[EdDSASignatureByteSize]{};
  size_t privlen{EdDSASignatureByteSize};
  size_t publen{EdDSASignatureByteSize};

  ConcordAssertEQ(OPENSSL_SUCCESS, EVP_PKEY_get_raw_private_key(edPkey.get(), privKey, &privlen));
  ConcordAssertEQ(OPENSSL_SUCCESS, EVP_PKEY_get_raw_public_key(edPkey.get(), pubKey, &publen));

  pair<string, string> keyPair(boost::algorithm::hex(string(reinterpret_cast<const char*>(privKey), privlen)),
                               boost::algorithm::hex(string(reinterpret_cast<const char*>(pubKey), publen)));

  if (KeyFormat::PemFormat == fmt) {
    keyPair = EdDSAHexToPem(keyPair);
  }
  return keyPair;
}

pair<string, string> OpenSSLCryptoImpl::EdDSAHexToPem(const std::pair<std::string, std::string>& hex_key_pair) const {
  string privPemString;
  string pubPemString;
  constexpr uint64_t maxBytesToRead = 1024U;

  if (!hex_key_pair.first.empty()) {  // Proceed with private key pem file generation.
    const auto privKey = boost::algorithm::unhex(hex_key_pair.first);

    UniquePKEY ed_privKey(EVP_PKEY_new_raw_private_key(
        NID_ED25519, nullptr, reinterpret_cast<const unsigned char*>(privKey.data()), privKey.size()));

    ConcordAssertNE(nullptr, ed_privKey);

    auto fp = tmpfile();
    ConcordAssertNE(nullptr, fp);
    PEM_write_PrivateKey(fp, ed_privKey.get(), nullptr, nullptr, 0, nullptr, nullptr);
    rewind(fp);

    privPemString = concord::io::readFile(fp, maxBytesToRead);
    fclose(fp);
  }

  if (!hex_key_pair.second.empty()) {  // Proceed with public key pem file generation.
    const auto pubKey = boost::algorithm::unhex(hex_key_pair.second);

    UniquePKEY ed_pubKey(EVP_PKEY_new_raw_public_key(
        NID_ED25519, nullptr, reinterpret_cast<const unsigned char*>(pubKey.data()), pubKey.size()));

    ConcordAssertNE(nullptr, ed_pubKey);

    auto fp = tmpfile();
    ConcordAssertNE(nullptr, fp);
    PEM_write_PUBKEY(fp, ed_pubKey.get());
    rewind(fp);

    pubPemString = concord::io::readFile(fp, maxBytesToRead);
    fclose(fp);
  }
  return make_pair(privPemString, pubPemString);
}

KeyFormat OpenSSLCryptoImpl::getFormat(const string& key) const {
  return (key.find("BEGIN") != string::npos) ? KeyFormat::PemFormat : KeyFormat::HexaDecimalStrippedFormat;
}
}  // namespace concord::crypto::openssl
