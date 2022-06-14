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
//

// #define PICOBENCH_DEBUG
//#define PICOBENCH_IMPLEMENT_WITH_MAIN
#define PICOBENCH_IMPLEMENT
#define PICOBENCH_STD_FUNCTION_BENCHMARKS

#include <vector>
#include <cstdlib>
#include <iostream>
#include <random>
#include <boost/program_options.hpp>
#include "thread_pool.hpp"
#include "picobench.hpp"
#include "openssl_utils.hpp"
#include "cryptopp_utils.hpp"

using concord::util::cryptopp_utils::RSASigner;
using concord::util::cryptopp_utils::RSAVerifier;
using concord::util::openssl_utils::EdDSASigner;
using concord::util::openssl_utils::EdDSAVerifier;

std::default_random_engine generator;

constexpr char KEYS_BASE_PARENT_PATH[] = "/tmp/";
constexpr char EDDSA_KEYS_BASE_PATH[] = "transaction_eddsa_signing_keys";
constexpr char RSA_KEYS_BASE_PATH[] = "transaction_rsa_signing_keys";
constexpr char PRIV_KEY_NAME[] = "privkey.pem";
constexpr char PUB_KEY_NAME[] = "pubkey.pem";
constexpr char EDDSA_ALGO[] = "eddsa";
constexpr char RSA_ALGO[] = "rsa";
constexpr char KEYS_GEN_SCRIPT_PATH[] =
    "/concord-bft//scripts/linux/create_concord_clients_transaction_signing_keys.sh";
constexpr size_t RANDOM_DATA_SIZE = 1000U;

constexpr uint8_t RANDOM_DATA_ARRAY_SIZE = 100U;
static string randomData[RANDOM_DATA_ARRAY_SIZE];

/**
 * @brief Generates a EdDSA private-public key pair.
 * @param count Number of key pair.
 */
void generateKeyPairs(size_t count, const char algo[]) {
  std::ostringstream cmd;

  cmd << "rm -rf " << RSA_KEYS_BASE_PATH;
  ConcordAssertEQ(0, system(cmd.str().c_str()));
  cmd << "rm -rf " << EDDSA_KEYS_BASE_PATH;
  ConcordAssertEQ(0, system(cmd.str().c_str()));

  cmd.str("");
  cmd.clear();

  if (0 == strcmp(algo, "rsa")) {
    cmd << KEYS_GEN_SCRIPT_PATH << " -n " << count << " -r " << PRIV_KEY_NAME << " -u " << PUB_KEY_NAME << " -o "
        << KEYS_BASE_PARENT_PATH << " -a " << algo << " -d " << RSA_KEYS_BASE_PATH;
  } else if (0 == strcmp(algo, "eddsa")) {
    cmd << KEYS_GEN_SCRIPT_PATH << " -n " << count << " -r " << PRIV_KEY_NAME << " -u " << PUB_KEY_NAME << " -o "
        << KEYS_BASE_PARENT_PATH << " -a " << algo << " -d " << EDDSA_KEYS_BASE_PATH;
  }

  ConcordAssertEQ(0, system(cmd.str().c_str()));
}

/**
 * Initializes 'randomData' with random bytes of size 'len'.
 * @param len Length of the random data to be generated.
 */
void generateRandomData(size_t len) {
  for (uint8_t i{0}; i < RANDOM_DATA_ARRAY_SIZE; ++i) {
    randomData[i].reserve(RANDOM_DATA_SIZE);
  }

  std::uniform_int_distribution<int> distribution(0, 0xFF);

  for (uint8_t i{0}; i < RANDOM_DATA_ARRAY_SIZE; ++i) {
    for (size_t j{0}; j < len; ++j) {
      randomData[i][j] = static_cast<char>(distribution(generator));
    }
  }
}

/**
 * @brief Reads a file and outputs the content to 'keyOut' param.
 * @param path File path.
 * @param keyOut File content.
 */
void readFile(std::string_view path, std::string& keyOut) {
  std::stringstream stream;
  std::ifstream file(path.data());
  ConcordAssert(file.good());
  stream << file.rdbuf();
  keyOut = stream.str();
}

/**
 * A benchmark which measures the time it takes for EdDSA signer to sign a message.
 * @param s
 */
void edDSASignerBenchmark(picobench::state& s) {
  string publicKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(EDDSA_KEYS_BASE_PATH) + string("/1/") + PUB_KEY_NAME});
  string privateKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(EDDSA_KEYS_BASE_PATH) + string("/1/") + PRIV_KEY_NAME});

  string privKey, pubkey, sig;

  readFile(privateKeyFullPath, privKey);
  readFile(publicKeyFullPath, pubkey);

  auto signer_ = unique_ptr<EdDSASigner>(new EdDSASigner(privKey, KeyFormat::PemFormat));

  // Sign with EdDSASigner.
  size_t expectedSignerSigLen = signer_->signatureLength();
  sig.reserve(expectedSignerSigLen);
  size_t lenRetData;

  uint64_t signaturesPerformed = 0;
  {
    picobench::scope scope(s);

    for (int msgIdx = 0; msgIdx < s.iterations(); msgIdx++) {
      sig = signer_->sign(randomData[msgIdx % RANDOM_DATA_ARRAY_SIZE]);
      lenRetData = sig.size();
      ++signaturesPerformed;
      ConcordAssertEQ(lenRetData, expectedSignerSigLen);
    }
  }
  s.set_result(signaturesPerformed);
}

/**
 * @brief A benchmark which measures the time it takes for EdDSA verifier to verify a signature.
 *
 * @param s
 */
void edDSAVerifierBenchmark(picobench::state& s) {
  string publicKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(EDDSA_KEYS_BASE_PATH) + string("/1/") + PUB_KEY_NAME});
  string privateKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(EDDSA_KEYS_BASE_PATH) + string("/1/") + PRIV_KEY_NAME});

  string privKey, pubkey, sig;

  readFile(privateKeyFullPath, privKey);
  readFile(publicKeyFullPath, pubkey);
  auto verifier_ = unique_ptr<EdDSAVerifier>(new EdDSAVerifier(pubkey, KeyFormat::PemFormat));
  auto signer_ = unique_ptr<EdDSASigner>(new EdDSASigner(privKey, KeyFormat::PemFormat));

  // Sign with EdDSASigner.
  size_t expectedSignerSigLen = signer_->signatureLength();
  sig.reserve(expectedSignerSigLen);
  size_t lenRetData;

  const auto offset = (uint8_t)rand() % RANDOM_DATA_ARRAY_SIZE;
  sig = signer_->sign(randomData[offset]);
  lenRetData = sig.size();
  ConcordAssertEQ(lenRetData, expectedSignerSigLen);

  uint64_t signaturesVerified = 0;
  {
    picobench::scope scope(s);

    for (int msgIdx = 0; msgIdx < s.iterations(); msgIdx++) {
      ++signaturesVerified;

      // validate with EdDSAVerifier.
      ConcordAssert(verifier_->verify(randomData[offset], sig));
    }
  }
  s.set_result(signaturesVerified);
}

/**
 * @brief A benchmark which measures the time it takes for RSA signer to sign a message.
 *
 * @param s
 */
void rsaSignerBenchmark(picobench::state& s) {
  string publicKeyFullPath({string(KEYS_BASE_PARENT_PATH) + string(RSA_KEYS_BASE_PATH) + string("/1/") + PUB_KEY_NAME});
  string privateKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(RSA_KEYS_BASE_PATH) + string("/1/") + PRIV_KEY_NAME});

  string privKey, pubkey, sig;

  readFile(privateKeyFullPath, privKey);
  readFile(publicKeyFullPath, pubkey);

  auto signer_ = unique_ptr<RSASigner>(new RSASigner(privKey, KeyFormat::PemFormat));

  // Sign with RSA_Signer.
  size_t expectedSignerSigLen = signer_->signatureLength();
  sig.reserve(expectedSignerSigLen);
  size_t lenRetData;

  uint64_t signaturesPerformed = 0;
  {
    picobench::scope scope(s);

    for (int msgIdx = 0; msgIdx < s.iterations(); msgIdx++) {
      sig = signer_->sign(randomData[msgIdx % RANDOM_DATA_ARRAY_SIZE]);
      lenRetData = sig.size();
      ++signaturesPerformed;
      ConcordAssertEQ(lenRetData, expectedSignerSigLen);
    }
  }
  s.set_result(signaturesPerformed);
}

/**
 * @brief A benchmark which measures the time it takes for RSA verifier to verify a signature.
 *
 * @param s
 */
void rsaVerifierBenchmark(picobench::state& s) {
  string publicKeyFullPath({string(KEYS_BASE_PARENT_PATH) + string(RSA_KEYS_BASE_PATH) + string("/1/") + PUB_KEY_NAME});
  string privateKeyFullPath(
      {string(KEYS_BASE_PARENT_PATH) + string(RSA_KEYS_BASE_PATH) + string("/1/") + PRIV_KEY_NAME});

  string privKey, pubkey, sig;

  readFile(privateKeyFullPath, privKey);
  readFile(publicKeyFullPath, pubkey);
  auto verifier_ = unique_ptr<RSAVerifier>(new RSAVerifier(pubkey, KeyFormat::PemFormat));
  auto signer_ = unique_ptr<RSASigner>(new RSASigner(privKey, KeyFormat::PemFormat));

  // Sign with RSASigner.
  size_t expectedSignerSigLen = signer_->signatureLength();
  sig.reserve(expectedSignerSigLen);
  size_t lenRetData;

  const auto offset = (uint8_t)rand() % RANDOM_DATA_ARRAY_SIZE;
  sig = signer_->sign(randomData[offset]);
  lenRetData = sig.size();
  ConcordAssertEQ(lenRetData, expectedSignerSigLen);

  uint64_t signaturesVerified = 0;
  {
    picobench::scope scope(s);

    for (int msgIdx = 0; msgIdx < s.iterations(); msgIdx++) {
      ++signaturesVerified;

      // validate with RSAVerifier.
      ConcordAssert(verifier_->verify(randomData[offset], sig));
    }
  }
  s.set_result(signaturesVerified);
}

/**
 * @brief Construct a new PICOBENCH object.
 */
PICOBENCH(edDSASignerBenchmark).label("EdDSA-Signer").samples(10).iterations({50000, 1000000});
PICOBENCH(rsaSignerBenchmark).label("RSA-Signer").samples(10).iterations({50000, 1000000});
PICOBENCH(edDSAVerifierBenchmark).label("EdDSA-Verifier").samples(10).iterations({50000, 1000000});
PICOBENCH(rsaVerifierBenchmark).label("RSA-Verifier").samples(10).iterations({50000, 1000000});

/**
 * @brief Entry function.
 *
 * @param argc
 * @param argv
 * @return int
 */
int main(int argc, char* argv[]) {
  generateKeyPairs(1, EDDSA_ALGO);
  generateKeyPairs(1, RSA_ALGO);

  generateRandomData(RANDOM_DATA_SIZE);

  constexpr const uint64_t picobenchSeed = 20222022;
  picobench::runner runner;
  runner.set_default_samples(1);

  return runner.run(picobenchSeed);
}