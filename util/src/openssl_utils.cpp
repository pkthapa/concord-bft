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

#include <regex>

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

std::string CertificateUtils::generateSelfSignedCert(const std::string& origin_cert_path,
                                                     const std::string& public_key,
                                                     const std::string& signing_key) {
  auto deleter = [](FILE* fp) {
    if (fp) fclose(fp);
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(fopen(origin_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(GL, "Certificate file not found, path: " << origin_cert_path);
    return std::string();
  }

  X509* cert = PEM_read_X509(fp.get(), NULL, NULL, NULL);
  if (!cert) {
    LOG_ERROR(GL, "Cannot parse certificate, path: " << origin_cert_path);
    return std::string();
  }

  EVP_PKEY* priv_key = EVP_PKEY_new();
  BIO* priv_bio = BIO_new(BIO_s_mem());
  int priv_bio_write_ret = BIO_write(priv_bio, static_cast<const char*>(signing_key.c_str()), signing_key.size());
  if (priv_bio_write_ret <= 0) {
    EVP_PKEY_free(priv_key);
    BIO_free(priv_bio);
    X509_free(cert);
    LOG_ERROR(GL, "Unable to create private key object");
    return std::string();
  }
  if (!PEM_read_bio_PrivateKey(priv_bio, &priv_key, NULL, NULL)) {
    EVP_PKEY_free(priv_key);
    BIO_free(priv_bio);
    X509_free(cert);
    LOG_ERROR(GL, "Unable to create private key object");
    return std::string();
  }
  EVP_PKEY* pub_key = EVP_PKEY_new();
  BIO* pub_bio = BIO_new(BIO_s_mem());
  int pub_bio_write_ret = BIO_write(pub_bio, static_cast<const char*>(public_key.c_str()), public_key.size());
  if (pub_bio_write_ret <= 0) {
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    BIO_free(priv_bio);
    BIO_free(pub_bio);
    X509_free(cert);
    LOG_ERROR(GL, "Unable to create public key object");
    return std::string();
  }
  if (!PEM_read_bio_PUBKEY(pub_bio, &pub_key, NULL, NULL)) {
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    BIO_free(priv_bio);
    BIO_free(pub_bio);
    X509_free(cert);
    LOG_ERROR(GL, "Unable to create public key object");
    return std::string();
  }

  X509_set_pubkey(cert, pub_key);
  X509_sign(cert, priv_key, EVP_sha256());

  BIO* outbio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_X509(outbio, cert)) {
    BIO_free(outbio);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    BIO_free(priv_bio);
    BIO_free(pub_bio);
    X509_free(cert);
    LOG_ERROR(GL, "Unable to create certificate object");
    return std::string();
  }
  std::string certStr;
  int certLen = BIO_pending(outbio);
  certStr.resize(certLen);
  BIO_read(outbio, (void*)&(certStr.front()), certLen);
  // free all pointers
  BIO_free(outbio);
  EVP_PKEY_free(priv_key);
  BIO_free(priv_bio);
  EVP_PKEY_free(pub_key);
  BIO_free(pub_bio);
  X509_free(cert);
  return certStr;
}

bool CertificateUtils::verifyCertificate(X509* cert, const std::string& public_key) {
  EVP_PKEY* pub_key = EVP_PKEY_new();
  BIO* pub_bio = BIO_new(BIO_s_mem());
  int pub_bio_write_ret = BIO_write(pub_bio, static_cast<const char*>(public_key.c_str()), public_key.size());
  if (pub_bio_write_ret <= 0) {
    EVP_PKEY_free(pub_key);
    BIO_free(pub_bio);
    return false;
  }
  if (!PEM_read_bio_PUBKEY(pub_bio, &pub_key, NULL, NULL)) {
    EVP_PKEY_free(pub_key);
    BIO_free(pub_bio);
    return false;
  }
  int r = X509_verify(cert, pub_key);
  EVP_PKEY_free(pub_key);
  BIO_free(pub_bio);
  return (bool)r;
}

bool CertificateUtils::verifyCertificate(X509* cert_to_verify,
                                         const std::string& cert_root_directory,
                                         uint32_t& remote_peer_id,
                                         std::string& conn_type,
                                         bool use_unified_certs) {
  // First get the source ID
  static constexpr size_t SIZE = 512;
  std::string subject(SIZE, 0);
  X509_NAME_oneline(X509_get_subject_name(cert_to_verify), subject.data(), SIZE);

  int peerIdPrefixLength = 3;
  std::regex r("OU=\\d*", std::regex_constants::icase);
  std::smatch sm;
  regex_search(subject, sm, r);
  if (sm.length() <= peerIdPrefixLength) {
    LOG_ERROR(GL, "OU not found or empty: " << subject);
    return false;
  }

  auto remPeer = sm.str().substr(peerIdPrefixLength, sm.str().length() - peerIdPrefixLength);
  if (0 == remPeer.length()) {
    LOG_ERROR(GL, "OU empty " << subject);
    return false;
  }

  uint32_t remotePeerId;
  try {
    remotePeerId = stoul(remPeer, nullptr);
  } catch (const std::invalid_argument& ia) {
    LOG_ERROR(GL, "cannot convert OU, " << subject << ", " << ia.what());
    return false;
  } catch (const std::out_of_range& e) {
    LOG_ERROR(GL, "cannot convert OU, " << subject << ", " << e.what());
    return false;
  }
  remote_peer_id = remotePeerId;
  std::string CN;
  CN.resize(SIZE);
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert_to_verify), NID_commonName, CN.data(), SIZE);
  std::string cert_type = "server";
  if (CN.find("cli") != std::string::npos) cert_type = "client";
  conn_type = cert_type;

  // Get the local stored certificate for this peer
  std::string local_cert_path =
      (use_unified_certs)
          ? cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + "node.cert"
          : cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + cert_type + "/" + cert_type + ".cert";
  auto deleter = [](FILE* fp) {
    if (fp) fclose(fp);
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(fopen(local_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(GL, "Certificate file not found, path: " << local_cert_path);
    return false;
  }

  X509* localCert = PEM_read_X509(fp.get(), NULL, NULL, NULL);
  if (!localCert) {
    LOG_ERROR(GL, "Cannot parse certificate, path: " << local_cert_path);
    return false;
  }

  // this is actual comparison, compares hash of 2 certs
  bool res = (X509_cmp(cert_to_verify, localCert) == 0);
  X509_free(localCert);
  return res;
}

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
