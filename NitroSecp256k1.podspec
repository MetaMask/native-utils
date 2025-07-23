require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "NitroSecp256k1"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/MetaMask/native-utils.git", :tag => "#{s.version}" }

  s.source_files = [
    "ios/**/*.{swift}",
    "ios/**/*.{m,mm}",
    "cpp/**/*.{hpp,cpp}",
    "cpp/**/*.{h,c}",
    "cpp/secp256k1/src/secp256k1.c",
    "cpp/secp256k1/src/precomputed_ecmult.c",
    "cpp/secp256k1/src/precomputed_ecmult_gen.c",
  ]

  s.public_header_files = [
    "cpp/secp256k1/include/secp256k1.h",
    "cpp/secp256k1/include/secp256k1_recovery.h",
    "cpp/secp256k1/include/secp256k1_ecdh.h",
    "cpp/secp256k1/include/secp256k1_schnorrsig.h",
    "cpp/secp256k1/include/secp256k1_extrakeys.h",
  ]

  s.header_dir = "secp256k1"
  s.header_mappings_dir = "cpp/secp256k1/include"

  s.pod_target_xcconfig = {
    # C++ compiler flags, mainly for folly.
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) FOLLY_NO_CONFIG FOLLY_CFG_NO_COROUTINES USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_10X26 USE_SCALAR_8X32 ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4 ENABLE_MODULE_RECOVERY ENABLE_MODULE_ECDH ENABLE_MODULE_SCHNORRSIG ENABLE_MODULE_EXTRAKEYS",
    "HEADER_SEARCH_PATHS" => "$(inherited) $(PODS_TARGET_SRCROOT)/cpp/secp256k1 $(PODS_TARGET_SRCROOT)/cpp/secp256k1/include $(PODS_TARGET_SRCROOT)/cpp/secp256k1/src",
    "OTHER_CFLAGS" => "$(inherited) -DUSE_ECMULT_STATIC_PRECOMPUTATION -DUSE_FIELD_10X26 -DUSE_SCALAR_8X32 -DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_PREC_BITS=4 -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_ECDH -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS",
    "CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES" => "YES"
  }

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'

  load 'nitrogen/generated/ios/NitroSecp256k1+autolinking.rb'
  add_nitrogen_files(s)

  install_modules_dependencies(s)
end
