#include "key_params.h"
#include <cstring>

#define RSA_Algo false
#if RSA_Algo
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#else
#include "hex_tools.h"
#endif

namespace concord::secretsmanager {

KeyParams::KeyParams(const std::string& pkey, const std::string& piv) {
#if RSA_Algo
  CryptoPP::StringSource sskey(pkey, true, new CryptoPP::HexDecoder(new CryptoPP::VectorSink(key)));
  CryptoPP::StringSource ssiv(piv, true, new CryptoPP::HexDecoder(new CryptoPP::VectorSink(iv)));
#else
  const auto keyInAsciiStr = concordUtils::hexToASCII(pkey);
  const auto ivInAsciiStr = concordUtils::hexToASCII(piv);

  std::copy(keyInAsciiStr.begin(), keyInAsciiStr.end(), std::back_inserter(key));
  std::copy(ivInAsciiStr.begin(), ivInAsciiStr.end(), std::back_inserter(iv));
#endif
}
}  // namespace concord::secretsmanager