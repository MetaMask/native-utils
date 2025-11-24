#include "hex_utils.hpp"
#include <stdexcept>

namespace margelo::nitro::metamask_nativeutils {

bool isValidHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

void validateHexString(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string: odd length");
    }
    
    for (char c : hex) {
        if (!isValidHexChar(c)) {
            throw std::runtime_error("Invalid hex string: contains non-hex characters");
        }
    }
}

uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    throw std::runtime_error("Invalid hex character");
}

void hexToBytes(const std::string& hex, uint8_t* bytes, size_t expectedLen) {
    validateHexString(hex);
    
    if (hex.length() != expectedLen * 2) {
        throw std::runtime_error("Invalid hex string length");
    }
    
    for (size_t i = 0; i < expectedLen; i++) {
        bytes[i] = (hexCharToByte(hex[i * 2]) << 4) | hexCharToByte(hex[i * 2 + 1]);
    }
}

} // namespace margelo::nitro::metamask_nativeutils
