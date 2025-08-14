#pragma once

#include "HybridNativeUtilsSpec.hpp"

namespace margelo::nitro::metamask_nativeutils {

class HybridNativeUtils : public HybridNativeUtilsSpec {
public:
  HybridNativeUtils() : HybridObject(TAG) {}

public:
  double multiply(double a, double b) override;
};

} // namespace margelo::nitro::metamask_nativeutils
