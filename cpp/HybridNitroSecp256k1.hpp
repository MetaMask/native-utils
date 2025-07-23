#pragma once

#include "HybridNitroSecp256k1Spec.hpp"

namespace margelo::nitro::nitrosecp256k1 {

class HybridNitroSecp256k1 : public HybridNitroSecp256k1Spec {
public:
  HybridNitroSecp256k1() : HybridObject(TAG) {}

public:
  double multiply(double a, double b) override;
  std::shared_ptr<ArrayBuffer> toPublicKey(const std::string& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> hmacSha512(const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> pubToAddress(const std::shared_ptr<ArrayBuffer>& pubKey, bool sanitize = false) override;
  std::shared_ptr<ArrayBuffer> keccak256(const std::string& data) override;
  std::shared_ptr<ArrayBuffer> keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) override;
};

} // namespace margelo::nitro::nitrosecp256k1
