#pragma once

#include "HybridNativeUtilsSpec.hpp"

namespace margelo::nitro::metamask_nativeutils {

class HybridNativeUtils : public HybridNativeUtilsSpec {
public:
  HybridNativeUtils() : HybridObject(TAG) {}

public:
  double multiply(double a, double b) override;
  std::shared_ptr<ArrayBuffer> toPublicKey(const std::string& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> keccak256(const std::string& data) override;
  std::shared_ptr<ArrayBuffer> keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) override;
};

} // namespace margelo::nitro::metamask_nativeutils
