#include "HybridNitroSecp256k1.hpp"
#include "secp256k1_wrapper.h"
#include "hmac_sha512.h"
#include "keccak-tiny.h"
#include <stdexcept>

namespace margelo::nitro::nitrosecp256k1 {

// Static global context for maximum performance
static secp256k1_context* g_ctx = nullptr;

// secp256k1 group order N (same as noble/secp256k1)
static const uint8_t SECP256K1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// Initialize context once (thread-safe)
static void initializeContext() {
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

// Validate hex string contains only valid hex characters
static bool isValidHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

// Validate hex string format
static void validateHexString(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("hex invalid");
    }
    
    for (char c : hex) {
        if (!isValidHexChar(c)) {
            throw std::runtime_error("hex invalid");
        }
    }
}

// Compare two 32-byte arrays (returns true if a >= b)
static bool bytes32_gte(const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 32; i++) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true; // equal
}

// Check if 32-byte array is zero
static bool bytes32_is_zero(const uint8_t* bytes) {
    for (int i = 0; i < 32; i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

// Validate private key scalar is in range [1, N)
static void validatePrivateKeyScalar(const uint8_t* privateKeyBytes) {
    // Check if private key is zero
    if (bytes32_is_zero(privateKeyBytes)) {
        throw std::runtime_error("private key invalid 3");
    }
    
    // Check if private key >= N
    if (bytes32_gte(privateKeyBytes, SECP256K1_N)) {
        throw std::runtime_error("private key invalid 3");
    }
}

// Convert single hex character to byte value
static uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    throw std::runtime_error("hex invalid");
}

// Convert hex string to bytes with validation
static void hexToBytes(const std::string& hex, uint8_t* bytes, size_t expectedLen) {
    validateHexString(hex);
    
    if (hex.length() != expectedLen * 2) {
        throw std::runtime_error("Uint8Array expected");
    }
    
    for (size_t i = 0; i < expectedLen; i++) {
        bytes[i] = (hexCharToByte(hex[i * 2]) << 4) | hexCharToByte(hex[i * 2 + 1]);
    }
}

// Common function to generate public key from raw private key bytes
static std::shared_ptr<ArrayBuffer> generatePublicKeyFromBytes(const uint8_t* privateKeyBytes, bool isCompressed) {
    initializeContext();
    
    // Validate private key scalar
    validatePrivateKeyScalar(privateKeyBytes);
    
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

double HybridNitroSecp256k1::multiply(double a, double b) {
  return a * b;
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::toPublicKey(const std::string& privateKey, bool isCompressed) {
    std::string hex = privateKey;
    
    // Must be exactly 64 characters (32 bytes)
    if (hex.length() != 64) {
        throw std::runtime_error("Uint8Array expected");
    }
    
    // Convert hex to bytes with validation
    uint8_t seckey[32];
    hexToBytes(hex, seckey, 32);
    
    // Use common function to generate public key
    return generatePublicKeyFromBytes(seckey, isCompressed);
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) {
    // Validate input size (must be exactly 32 bytes for secp256k1)
    if (privateKey->size() != 32) {
        throw std::runtime_error("Uint8Array expected");
    }
    
    // Get the private key bytes directly
    const uint8_t* seckey = static_cast<const uint8_t*>(privateKey->data());
    
    // Use common function to generate public key
    return generatePublicKeyFromBytes(seckey, isCompressed);
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::hmacSha512(const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) {
    // Get key and data pointers
    const uint8_t* keyBytes = static_cast<const uint8_t*>(key->data());
    const uint8_t* dataBytes = static_cast<const uint8_t*>(data->data());
    
    // Create output buffer (SHA512 produces 64 bytes)
    auto buffer = ArrayBuffer::allocate(SHA512_DIGEST_SIZE);
    uint8_t* output = static_cast<uint8_t*>(buffer->data());
    
    // Use our standalone HMAC-SHA512 implementation
    hmac_sha512(keyBytes, key->size(), dataBytes, data->size(), output);
    
    return buffer;
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::pubToAddress(const std::shared_ptr<ArrayBuffer>& pubKey, bool sanitize) {
    initializeContext();
    
    const uint8_t* pubKeyBytes = static_cast<const uint8_t*>(pubKey->data());
    size_t pubKeySize = pubKey->size();
    
    // Buffer to hold the 64-byte uncompressed public key (without 0x04 prefix)
    uint8_t uncompressedPubKeyBytes[64];
    
    // Handle sanitization - convert various formats to 64-byte uncompressed
    if (sanitize && pubKeySize != 64) {
        secp256k1_pubkey parsedPubkey;
        
        // Parse the public key from various formats
        if (!secp256k1_ec_pubkey_parse(g_ctx, &parsedPubkey, pubKeyBytes, pubKeySize)) {
            throw std::runtime_error("Invalid public key format");
        }
        
        // Serialize to uncompressed format (65 bytes)
        uint8_t uncompressedKey[65];
        size_t outputLen = 65;
        if (!secp256k1_ec_pubkey_serialize(g_ctx, uncompressedKey, &outputLen, &parsedPubkey, SECP256K1_EC_UNCOMPRESSED)) {
            throw std::runtime_error("Failed to serialize public key");
        }
        
        // Skip the 0x04 prefix byte for keccak hashing
        memcpy(uncompressedPubKeyBytes, uncompressedKey + 1, 64);
        pubKeyBytes = uncompressedPubKeyBytes;
        pubKeySize = 64;
    } else {
        // Validate that pubKey is exactly 64 bytes (uncompressed without 0x04 prefix)
        if (pubKeySize != 64) {
            throw std::runtime_error("Expected pubKey to be of length 64");
        }
    }
    
    // Calculate keccak-256 hash using keccak-tiny
    // Note: sha3_256 in keccak-tiny actually implements Keccak-256 (0x01 padding)
    // which is what Ethereum uses, not the official SHA3-256 (0x06 padding)
    uint8_t hash[32];
    if (sha3_256(hash, 32, pubKeyBytes, pubKeySize) != 0) {
        throw std::runtime_error("Keccak-256 hash failed");
    }
    
    // Return the last 20 bytes (Ethereum address)
    auto result = ArrayBuffer::allocate(20);
    memcpy(result->data(), hash + 12, 20);
    
    return result;
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::keccak256(const std::string& data) {
    // Convert hex string to bytes
    validateHexString(data);
    
    size_t dataLen = data.length() / 2;
    std::vector<uint8_t> dataBytes(dataLen);
    
    for (size_t i = 0; i < dataLen; i++) {
        dataBytes[i] = (hexCharToByte(data[i * 2]) << 4) | hexCharToByte(data[i * 2 + 1]);
    }
    
    // Calculate keccak-256 hash
    uint8_t hash[32];
    if (sha3_256(hash, 32, dataBytes.data(), dataLen) != 0) {
        throw std::runtime_error("Keccak-256 hash failed");
    }
    
    // Return the 32-byte hash
    auto result = ArrayBuffer::allocate(32);
    memcpy(result->data(), hash, 32);
    
    return result;
}

std::shared_ptr<ArrayBuffer> HybridNitroSecp256k1::keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) {
    // Get the data bytes
    const uint8_t* dataBytes = static_cast<const uint8_t*>(data->data());
    size_t dataLen = data->size();
    
    // Calculate keccak-256 hash
    uint8_t hash[32];
    if (sha3_256(hash, 32, dataBytes, dataLen) != 0) {
        throw std::runtime_error("Keccak-256 hash failed");
    }
    
    // Return the 32-byte hash
    auto result = ArrayBuffer::allocate(32);
    memcpy(result->data(), hash, 32);
    
    return result;
}

} // namespace margelo::nitro::nitrosecp256k1
