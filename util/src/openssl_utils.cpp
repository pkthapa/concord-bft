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

#include <regex>
#include <utility>

namespace concord::crypto::openssl {

class BIO_Deleter {
 public:
  void operator()(BIO* p) const { BIO_free(p); }
};

class X509_Deleter {
 public:
  void operator()(X509* p) const { X509_free(p); }
};
constexpr size_t EDDSA_KEY_SIZE = 32;

string CertificateUtils::generateSelfSignedCert(const string& origin_cert_path,
                                                const string& public_key,
                                                const string& signing_key) {
  auto deleter = [](FILE* fp) {
    if (fp) fclose(fp);
  };
  unique_ptr<FILE, decltype(deleter)> fp(fopen(origin_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(OPENSSL_LOG, "Certificate file not found, path: " << origin_cert_path);
    return string();
  }

  unique_ptr<X509, X509_Deleter> cert(PEM_read_X509(fp.get(), NULL, NULL, NULL));
  if (!cert) {
    LOG_ERROR(OPENSSL_LOG, "Cannot parse certificate, path: " << origin_cert_path);
    return string();
  }

  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> priv_key(EVP_PKEY_new());
  unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(priv_bio.get(), static_cast<const char*>(signing_key.c_str()), signing_key.size()) <= 0) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create private key object");
    return string();
  }

  if (!PEM_read_bio_PrivateKey(priv_bio.get(), reinterpret_cast<EVP_PKEY**>(&priv_key), NULL, NULL)) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create private key object");
    return string();
  }
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pub_key(EVP_PKEY_new());
  unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(pub_bio.get(), static_cast<const char*>(public_key.c_str()), public_key.size()) <= 0) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create public key object");
    return string();
  }
  if (!PEM_read_bio_PUBKEY(pub_bio.get(), reinterpret_cast<EVP_PKEY**>(&pub_key), NULL, NULL)) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create public key object");
    return string();
  }

  X509_set_pubkey(cert.get(), pub_key.get());
  X509_sign(cert.get(), priv_key.get(), EVP_sha256());

  unique_ptr<BIO, BIO_Deleter> outbio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(outbio.get(), cert.get())) {
    LOG_ERROR(OPENSSL_LOG, "Unable to create certificate object");
    return string();
  }
  string certStr;
  int certLen = BIO_pending(outbio.get());
  certStr.resize(certLen);
  BIO_read(outbio.get(), (void*)&(certStr.front()), certLen);
  return certStr;
}

bool CertificateUtils::verifyCertificate(X509* cert, const string& public_key) {
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pub_key(EVP_PKEY_new());
  unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));

  if (BIO_write(pub_bio.get(), static_cast<const char*>(public_key.c_str()), public_key.size()) <= 0) {
    return false;
  }
  if (!PEM_read_bio_PUBKEY(pub_bio.get(), reinterpret_cast<EVP_PKEY**>(&pub_key), nullptr, nullptr)) {
    return false;
  }
  return (bool)X509_verify(cert, pub_key.get());
}

bool CertificateUtils::verifyCertificate(X509* cert_to_verify,
                                         const string& cert_root_directory,
                                         uint32_t& remote_peer_id,
                                         string& conn_type,
                                         bool use_unified_certs) {
  // First get the source ID
  static constexpr size_t SIZE = 512;
  string subject(SIZE, 0);
  X509_NAME_oneline(X509_get_subject_name(cert_to_verify), subject.data(), SIZE);

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
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert_to_verify), NID_commonName, CN.data(), SIZE);
  string cert_type = "server";
  if (CN.find("cli") != string::npos) cert_type = "client";
  conn_type = cert_type;

  // Get the local stored certificate for this peer
  string local_cert_path =
      (use_unified_certs)
          ? cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + "node.cert"
          : cert_root_directory + "/" + std::to_string(remotePeerId) + "/" + cert_type + "/" + cert_type + ".cert";
  auto deleter = [](FILE* fp) {
    if (fp) fclose(fp);
  };
  std::unique_ptr<FILE, decltype(deleter)> fp(fopen(local_cert_path.c_str(), "r"), deleter);
  if (!fp) {
    LOG_ERROR(OPENSSL_LOG, "Certificate file not found, path: " << local_cert_path);
    return false;
  }

  unique_ptr<X509, X509_Deleter> localCert(PEM_read_X509(fp.get(), NULL, NULL, NULL));
  if (!localCert) {
    LOG_ERROR(OPENSSL_LOG, "Cannot parse certificate, path: " << local_cert_path);
    return false;
  }

  // this is actual comparison, compares hash of 2 certs
  bool res = (X509_cmp(cert_to_verify, localCert.get()) == 0);
  return res;
}

EdDSASigner::EdDSASigner(const string& strPrivKey, KeyFormat fmt) : keyStr_{strPrivKey} {
  ConcordAssertGT(strPrivKey.size(), 0);

  if (KeyFormat::PemFormat == fmt) {
    // Write the key data into a temp file under /tmp/ directory and delete the temp file after usage.
    const string temp{"/tmp/concordTempPrivKey.pem"};
    ofstream out(temp.data());
    out << strPrivKey;
    out.close();

    auto deleter = [](FILE* fp) {
      if (nullptr != fp) {
        fclose(fp);
      }
    };
    unique_ptr<FILE, decltype(deleter)> fp(fopen(temp.data(), "r"), deleter);

    if (nullptr == fp) {
      LOG_ERROR(OPENSSL_LOG, "Unable to open private key file to initialize signer." << KVLOG(fp.get(), strPrivKey));
      std::terminate();
    }

    size_t keyLen{EDDSA_KEY_SIZE};

    edPkey_.reset(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(1,
                    EVP_PKEY_get_raw_private_key(edPkey_.get(),
                                                 reinterpret_cast<unsigned char*>(keyStr_.data()),
                                                 &keyLen));  // Extract private key in 'keyStr_'.
    remove(temp.data());
  } else {
    string privCh = concordUtils::hexToASCII(strPrivKey);
    edPkey_.reset(
        EVP_PKEY_new_raw_private_key(NID_ED25519, nullptr, (const unsigned char*)privCh.data(), privCh.size()));
  }
  ConcordAssertNE(edPkey_, nullptr);
}

string EdDSASigner::sign(const string& dataToSign) {
  unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> edCtx(EVP_MD_CTX_new());

  ConcordAssertNE(edCtx, nullptr);
  ConcordAssertEQ(1, EVP_DigestSignInit(edCtx.get(), nullptr, nullptr, nullptr, edPkey_.get()));

  string signature(EdDSA_SIG_LENGTH, 0);
  ConcordAssertEQ(1,
                  EVP_DigestSign(edCtx.get(),
                                 reinterpret_cast<unsigned char*>(signature.data()),
                                 &sigLen_,
                                 reinterpret_cast<const unsigned char*>(dataToSign.data()),
                                 dataToSign.size()));
  return signature;
}

uint32_t EdDSASigner::signatureLength() const { return sigLen_; }

string EdDSASigner::getPrivKey() const { return keyStr_; }

EdDSAVerifier::EdDSAVerifier(const string& strPubKey, KeyFormat fmt) : keyStr_{strPubKey} {
  ConcordAssertGT(strPubKey.size(), 0);

  if (KeyFormat::PemFormat == fmt) {
    // Write the key data into a temp file under /tmp/ directory and delete the temp file after usage.
    const string temp{"/tmp/concordTempPubKey.pem"};
    ofstream out(temp.data());
    out << strPubKey;
    out.close();

    auto deleter = [](FILE* fp) {
      if (nullptr != fp) {
        fclose(fp);
      }
    };
    unique_ptr<FILE, decltype(deleter)> fp(fopen(temp.data(), "r"), deleter);
    if (nullptr == fp) {
      LOG_ERROR(OPENSSL_LOG, "Unable to open public key file to initialize verifier." << KVLOG(fp.get(), strPubKey));
      std::terminate();
    }

    size_t keyLen{EDDSA_KEY_SIZE};

    edPkey_.reset(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));
    ConcordAssertEQ(1,
                    EVP_PKEY_get_raw_public_key(edPkey_.get(),
                                                reinterpret_cast<unsigned char*>(keyStr_.data()),
                                                &keyLen));  // Extract public key in 'keyStr_'.
    remove(temp.data());
  } else {
    string pubCh = concordUtils::hexToASCII(strPubKey);
    edPkey_.reset(EVP_PKEY_new_raw_public_key(NID_ED25519, nullptr, (const unsigned char*)pubCh.data(), pubCh.size()));
  }
  ConcordAssertNE(edPkey_, nullptr);
}

bool EdDSAVerifier::verify(const string& dataToVerify, const string& sigToVerify) const {
  sigLen_ = sigToVerify.size();
  ConcordAssertEQ(sigLen_, EdDSA_SIG_LENGTH);

  unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> edCtx(EVP_MD_CTX_new());

  ConcordAssert(nullptr != edCtx);
  ConcordAssertEQ(1, EVP_DigestVerifyInit(edCtx.get(), nullptr, nullptr, nullptr, edPkey_.get()));

  if (1 != EVP_DigestVerify(edCtx.get(),
                            reinterpret_cast<const unsigned char*>(sigToVerify.data()),
                            sigLen_,
                            reinterpret_cast<const unsigned char*>(dataToVerify.data()),
                            dataToVerify.size())) {
    LOG_ERROR(OPENSSL_LOG, "EdDSA verification failed." << KVLOG(dataToVerify, sigToVerify));
    return false;
  }
  return true;
}

uint32_t EdDSAVerifier::signatureLength() const { return sigLen_; }

string EdDSAVerifier::getPubKey() const { return keyStr_; }

pair<string, string> Crypto::generateEdDSAKeyPair(const KeyFormat fmt) const {
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> edPkey;
  unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> edPkeyCtx(EVP_PKEY_CTX_new_id(NID_ED25519, nullptr));

  ConcordAssertNE(edPkeyCtx, nullptr);

  ConcordAssertEQ(1, EVP_PKEY_keygen_init(edPkeyCtx.get()));
  ConcordAssertEQ(
      1, EVP_PKEY_keygen(edPkeyCtx.get(), reinterpret_cast<EVP_PKEY**>(&edPkey)));  // Generate EdDSA key 'edPkey'.

  unsigned char privKey[EdDSA_SIG_LENGTH]{};
  unsigned char pubKey[EdDSA_SIG_LENGTH]{};
  size_t privlen{EdDSA_SIG_LENGTH};
  size_t publen{EdDSA_SIG_LENGTH};

  ConcordAssertEQ(1, EVP_PKEY_get_raw_private_key(edPkey.get(), privKey, &privlen));
  ConcordAssertEQ(1, EVP_PKEY_get_raw_public_key(edPkey.get(), pubKey, &publen));

  pair<string, string> keyPair;
  keyPair.first = concordUtils::bufferToHex(reinterpret_cast<const char*>(privKey), (const size_t)privlen, false);
  keyPair.second = concordUtils::bufferToHex(reinterpret_cast<const char*>(pubKey), (const size_t)publen, false);

  if (KeyFormat::PemFormat == fmt) {
    keyPair = EdDSAHexToPem(keyPair);
  }
  return keyPair;
}

pair<string, string> Crypto::EdDSAHexToPem(const std::pair<std::string, std::string>& hex_key_pair) const {
  auto privKey = concordUtils::hexToASCII(hex_key_pair.first);
  auto pubKey = concordUtils::hexToASCII(hex_key_pair.second);

  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ed_privKey(
      EVP_PKEY_new_raw_private_key(NID_ED25519, nullptr, (const unsigned char*)privKey.data(), privKey.size()));
  unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ed_pubKey(
      EVP_PKEY_new_raw_public_key(NID_ED25519, nullptr, (const unsigned char*)pubKey.data(), pubKey.size()));

  ConcordAssertNE(nullptr, ed_privKey);
  ConcordAssertNE(nullptr, ed_pubKey);

  const char* const tempPrivPem = "/tmp/concordTempPrivKey.pem";
  const char* const tempPubPem = "/tmp/concordTempPubKey.pem";

  FILE* fp = fopen(tempPrivPem, "w");
  PEM_write_PrivateKey(fp, ed_privKey.get(), nullptr, nullptr, 0, nullptr, nullptr);
  fclose(fp);

  fp = fopen(tempPubPem, "w");
  PEM_write_PUBKEY(fp, ed_pubKey.get());
  fclose(fp);

  string privPemString, pubPemString;

  // Read private key from pem file.
  std::ifstream privPem(tempPrivPem);
  string temp;
  if (privPem.is_open()) {
    while (privPem.good()) {
      getline(privPem, temp);
      privPemString += temp + '\n';
    }
  }

  // Read public key from pem file.
  std::ifstream pubPem(tempPubPem);
  if (pubPem.is_open()) {
    while (pubPem.good()) {
      getline(pubPem, temp);
      pubPemString += temp + '\n';
    }
  }

  remove(tempPrivPem);
  remove(tempPubPem);

  return make_pair(privPemString, pubPemString);
}
}  // namespace concord::crypto::openssl
