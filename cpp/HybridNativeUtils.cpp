#include "HybridNativeUtils.hpp"
#include "secp256k1_wrapper.h"
#include "hex_utils.hpp"
#include "botan_conditional.h"
#include <stdexcept>

namespace margelo::nitro::metamask_nativeutils {

// Static global context for maximum performance
static secp256k1_context* g_ctx = nullptr;

// Initialize context once (thread-safe)
static void initializeContext() {
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}


// Common function to generate public key from raw private key bytes
static std::shared_ptr<ArrayBuffer> generatePublicKeyFromBytes(const uint8_t* privateKeyBytes, bool isCompressed) {
  initializeContext();
  
  // Use secp256k1's built-in validation (checks if key is not 0 and < curve order)
  if (!secp256k1_ec_seckey_verify(g_ctx, privateKeyBytes)) {
      throw std::runtime_error("private key invalid 3");
  }
  
  // Create public key from private key
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_create(g_ctx, &pubkey, privateKeyBytes)) {
      throw std::runtime_error("private key invalid 3");
  }
  
  // Serialize the public key
  size_t keySize = isCompressed ? 33 : 65;
  auto buffer = ArrayBuffer::allocate(keySize);
  auto data = static_cast<uint8_t*>(buffer->data());
  
  size_t outputLen = keySize;
  unsigned int flags = isCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  
  if (!secp256k1_ec_pubkey_serialize(g_ctx, data, &outputLen, &pubkey, flags)) {
      throw std::runtime_error("private key invalid 3");
  }
  
  return buffer;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKey(const std::string& privateKey, bool isCompressed) {
  std::string hex = privateKey;
  
  // Must be exactly 64 characters (32 bytes)
  if (hex.length() != 64) {
      throw std::runtime_error("Uint8Array expected");
  }
  
  // Convert hex to bytes with validation
  uint8_t seckey[32];
  hexToBytes(hex, seckey, 32);
  
  return generatePublicKeyFromBytes(seckey, isCompressed);
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) {
  // Validate input size (must be exactly 32 bytes for secp256k1)
  if (privateKey->size() != 32) {
      throw std::runtime_error("Uint8Array expected");
  }
  
  // Get the private key bytes directly
  const uint8_t* seckey = static_cast<const uint8_t*>(privateKey->data());
  
  return generatePublicKeyFromBytes(seckey, isCompressed);
}

static std::shared_ptr<ArrayBuffer> keccak256Hash(const uint8_t* dataBytes, size_t dataLen) {
  auto hasher = Botan::HashFunction::create("Keccak-1600(256)");
  if (!hasher) {
    throw std::runtime_error("Failed to create Keccak-256 hasher");
  }

  hasher->update(dataBytes, dataLen);

  // Convert hex string to bytes
  auto result = ArrayBuffer::allocate(32);
  hasher->final(static_cast<uint8_t*>(result->data()));

  return result;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::keccak256(const std::string& data) {
  validateHexString(data);
  
  size_t dataLen = data.length() / 2;
  
  auto dataBuffer = ArrayBuffer::allocate(dataLen);
  uint8_t* dataBytes = static_cast<uint8_t*>(dataBuffer->data());
  
  // Convert hex string to bytes
  for (size_t i = 0; i < dataLen; i++) {
      dataBytes[i] = (hexCharToByte(data[i * 2]) << 4) | hexCharToByte(data[i * 2 + 1]);
  }
  
  return keccak256FromBytes(dataBuffer);
}
std::shared_ptr<ArrayBuffer> HybridNativeUtils::keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) {
  // Get the data bytes
  const uint8_t* dataBytes = static_cast<const uint8_t*>(data->data());
  size_t dataLen = data->size();
  
  return keccak256Hash(dataBytes, dataLen);
}


double HybridNativeUtils::multiply(double a, double b) {
  return a * b;
}

} // namespace margelo::nitro::metamask_nativeutils