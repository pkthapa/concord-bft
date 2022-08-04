// Concord
//
// Copyright (c) 2018-2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License"). You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "helper.hpp"
#include "ReplicaConfig.hpp"

typedef std::pair<uint16_t, std::string> IdToKeyPair;

using concord::crypto::SIGN_VERIFY_ALGO;
using bftEngine::ReplicaConfig;

const std::string replicaRSAPrivateKey = {
    "308204BC020100300D06092A864886F70D0101010500048204A6308204A20201000282010100BCC5BEA607F4F52A493AA2F40C2D5482D7CE37"
    "DFC526E98131FDC92CE2ECA6035DB307B182EF52CA8471B78A65E445399816AFACB224F4CEA9597D4B6FE5E84030B7AF78A88BA0233263A9F0"
    "E2658A6E5BE57923D9093B7D6B70FDBAEC3CDA05C5EDE237674A598F5D607A50C1C528EEAE4B690C90820901A01BF4747C39FE6BD6DA535A9B"
    "8CAE04B39D5D5158C8FFD2CD6652195AC48646B8AEF202615306575FD9508632E6027ABD50E786BD1A984C7DD11E36293A45EDBBFB61E438C1"
    "89C2B73A69F6605C909F98B6C3F795354BBB988C9695F8A1E27FFC3CE4FFA64B549DD9072763404FBD352C5C1A05FA3D17377E113600B1EDCA"
    "EE17687BC4C1AA6F3D020111028201000A2DCCCA35228AB5BB2A1050EC94034D546BBF3F845B323CED5CBE4C75A5DBC674BD1AC48D55B062C3"
    "607C17C6BFC27A523D7564EB7CF91F38D15FDAA7EA83BD2FCDAB581320A07A5E532D8E3E675B8AF867FB3CE9D21102FF84D6774171B66C3B9D"
    "240A84508EDE51958415EC54AB9E704CD9BE2AEDE9E5BC1595F738E5026C9FB204D15017B72A7C22A9026BEC239EF9B329BBA56384D625217C"
    "5C9513EFD10A4DC84B37505C99EBD2695F3CE59ABECD280FA7014865F0FD6E48F34AB0ADC2F66DF738A3C058818BB321DDF0D7AB17EACEE6B5"
    "5AADD2C0D9522FB6E001D945C014DA857FE347FF41F29DFCA5E9BA9779B26224F65503AD7FE6AF92A63C1EB902818100F16B929438481F3EC0"
    "64FC91AD9F41CB95368C06221FE323E02547FBECA9A65CE7EC3C70C2F35D48BEB0A70F9CDF5D367962AD6F80438A758F1E84425D168E3BF16B"
    "6FD9F73B3A77ECA80CA1845C0C89BA46DD6D9234621A713803D0DC872FBE4C6E372D04FB28454978C319D187FAEFBE78AE3E2D4D36DEC11869"
    "2C9C56162902818100C82C38E2675E329AC6870B1E655440B17E7AEEA9C911EC599C4B335179662F0444791D2E284ED89717BF29EDFCB0625A"
    "CA9EC2DC05898777453CAC01E6DE650A02EEE2BC2F323296A488FD709E50DA307E8E76EDD4BE98F8B56DC963A6B921A373D0617326235DB7D6"
    "0A13876997F4F17A4F3D150960ACF2125414B2A610AAF502818100AA6A0D1D54E79D95B4FBFD94021610537862BD31817FEBA0DA74AB486AD2"
    "1B14677994135C6F8D244A5E940B05525FEA3790F2E54B7AF852FB9D1210BA2E0A0C31F17C216338DDFA4CB2DBBD4E5F17E8BFB98D3E4915EA"
    "E57D187B2A051421B3813EBD8930B1499A51FAE412398D299A2C18F3772F0953E8884D776AC8B53CD10281803ADFD47ED31BB487E00999DBC3"
    "73221616242813D1B9FA3879434B5432C3B379B9C944D157263FB3F7ECEE36EFF7A4750E6AEE047A196414054E147907AAD26C5B3733A0C296"
    "4B1D3F7395D5D435E5D2071AD7AF5CB08758355C8686B890CDA88B798612CEFB57CCA85D5109B5A529ECAB80B79CC685D8836ECD6F7FD67D5F"
    "7502818100B33DC57C801E0824CF2C77D6D35EC51E321168DA1DED72238ECF69DF6BD485B19A2A67CFBE87F6819F5872463687295F4091C6D9"
    "9AE98AD08EB45931E761D42D9CE941CEF7DF8A493FEAD8EB571BBBA21EF6403151CB25C71A9BB457D3FB058AA34AB4C1AB474C86293A26D428"
    "E77960457E2631215FF7B68013877ABCCE4322"};
const std::string replicaRSAPubKey = {
    "30820120300D06092A864886F70D01010105000382010D00308201080282010100B"
    "CC5BEA607F4F52A493AA2F40C2D5482D7CE37DFC526E981"
    "31FDC92CE2ECA6035DB307B182EF52CA8471B78A65E445399816AFACB224F4CEA95"
    "97D4B6FE5E84030B7AF78A88BA0233263A9F0E2658A6E5B"
    "E57923D9093B7D6B70FDBAEC3CDA05C5EDE237674A598F5D607A50C1C528EEAE4B6"
    "90C90820901A01BF4747C39FE6BD6DA535A9B8CAE04B39D"
    "5D5158C8FFD2CD6652195AC48646B8AEF202615306575FD9508632E6027ABD50E78"
    "6BD1A984C7DD11E36293A45EDBBFB61E438C189C2B73A69"
    "F6605C909F98B6C3F795354BBB988C9695F8A1E27FFC3CE4FFA64B549DD90727634"
    "04FBD352C5C1A05FA3D17377E113600B1EDCAEE17687BC4"
    "C1AA6F3D020111"};
const std::string replicaEdDSAPrivateKey = {"09a30490ebf6f6685556046f2497fd9c7df4a552998c9a9b6ebec742e8183174"};
const std::string replicaEdDSAPubKey = {"7363bc5ab96d7f85e71a5ffe0b284405ae38e2e0f032fb3ffe805d9f0e2d117b"};

void loadPrivateAndPublicKeys(std::string& myPrivateKey,
                              std::set<std::pair<uint16_t, const std::string>>& publicKeysOfReplicas,
                              ReplicaId myId,
                              size_t numReplicas) {
  ConcordAssert(numReplicas <= 7);

  std::string pubKey;
  if (ReplicaConfig::instance().replicaMsgSigningAlgo == SIGN_VERIFY_ALGO::RSA) {
    myPrivateKey = replicaRSAPrivateKey;
    pubKey = replicaRSAPubKey;
  } else if (ReplicaConfig::instance().replicaMsgSigningAlgo == SIGN_VERIFY_ALGO::EDDSA) {
    myPrivateKey = replicaEdDSAPrivateKey;
    pubKey = replicaEdDSAPubKey;
  }
  const std::vector<std::string> replicasPubKeys{pubKey, pubKey, pubKey, pubKey, pubKey, pubKey, pubKey};

  for (size_t i{0}; i < numReplicas; ++i) {
    if (i == myId) continue;
    publicKeysOfReplicas.insert(IdToKeyPair(i, replicasPubKeys[i].c_str()));
  }
}

bftEngine::ReplicaConfig& createReplicaConfig(uint16_t fVal, uint16_t cVal) {
  bftEngine::ReplicaConfig& config = bftEngine::ReplicaConfig::instance();
  config.numReplicas = 3 * fVal + 2 * cVal + 1;
  config.fVal = fVal;
  config.cVal = cVal;
  config.replicaId = 0;
  config.numOfClientProxies = 0;
  config.statusReportTimerMillisec = 15;
  config.concurrencyLevel = 5;
  config.viewChangeProtocolEnabled = true;
  config.viewChangeTimerMillisec = 12;
  config.autoPrimaryRotationEnabled = false;
  config.autoPrimaryRotationTimerMillisec = 42;
  config.maxExternalMessageSize = 2000000;
  config.maxNumOfReservedPages = 256;
  config.maxReplyMessageSize = 1024;
  config.sizeOfReservedPage = 2048;
  config.debugStatisticsEnabled = true;
  config.threadbagConcurrencyLevel1 = 16;
  config.threadbagConcurrencyLevel2 = 8;

  loadPrivateAndPublicKeys(config.replicaPrivateKey, config.publicKeysOfReplicas, config.replicaId, config.numReplicas);

  bftEngine::CryptoManager::instance(std::make_unique<TestCryptoSystem>());

  return config;
}

bftEngine::impl::SigManager* createSigManager(size_t myId,
                                              std::string& myPrivateKey,
                                              concord::crypto::KeyFormat replicasKeysFormat,
                                              std::set<std::pair<uint16_t, const std::string>>& publicKeysOfReplicas,
                                              ReplicasInfo& replicasInfo) {
  return SigManager::init(myId,
                          myPrivateKey,
                          publicKeysOfReplicas,
                          replicasKeysFormat,
                          nullptr,
                          concord::crypto::KeyFormat::PemFormat,
                          replicasInfo);
}
