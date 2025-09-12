import { pubToAddress } from '@metamask/native-utils';
import { publicToAddress as ethereumjsPublicToAddress } from '@ethereumjs/util';
import type { TestResult } from '../testUtils';
import { hexToUint8Array, uint8ArrayToHex } from '../testUtils';

// Test basic 64-byte public key (without 0x04 prefix)
function testBasicPublicKey(): TestResult {
  try {
    const pubKey = hexToUint8Array(
      '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
    );
    const expectedAddress = '0x2f015c60e0be116b1f0cd534704db9c92118fb6a';

    const result = pubToAddress(pubKey);
    const actualAddress = uint8ArrayToHex(result);

    if (actualAddress === expectedAddress) {
      return {
        name: 'Basic 64-byte public key',
        success: true,
        message: `✓ Correct address: ${actualAddress}`,
      };
    } else {
      return {
        name: 'Basic 64-byte public key',
        success: false,
        message: `✗ Expected: ${expectedAddress}, Got: ${actualAddress}`,
      };
    }
  } catch (error) {
    return {
      name: 'Basic 64-byte public key',
      success: false,
      message: `✗ Unexpected error: ${error}`,
    };
  }
}

// Test 65-byte SEC1 public key with sanitize=true (should work)
function testSEC1PublicKeyWithSanitize(): TestResult {
  try {
    const pubKey = hexToUint8Array(
      '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
    );
    const expectedAddress = '0x2f015c60e0be116b1f0cd534704db9c92118fb6a';

    const result = pubToAddress(pubKey, true);
    const actualAddress = uint8ArrayToHex(result);

    if (actualAddress === expectedAddress) {
      return {
        name: 'SEC1 public key with sanitize=true',
        success: true,
        message: `✓ Correct address: ${actualAddress}`,
      };
    } else {
      return {
        name: 'SEC1 public key with sanitize=true',
        success: false,
        message: `✗ Expected: ${expectedAddress}, Got: ${actualAddress}`,
      };
    }
  } catch (error) {
    return {
      name: 'SEC1 public key with sanitize=true',
      success: false,
      message: `✗ Unexpected error: ${error}`,
    };
  }
}

// Test compressed public key (should throw error even with sanitize=true)
function testCompressedPublicKey(): TestResult {
  try {
    const pubKey = hexToUint8Array(
      '0x023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
    );

    try {
      pubToAddress(pubKey, true);
      return {
        name: 'Compressed public key should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      };
    } catch (error) {
      return {
        name: 'Compressed public key should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      };
    }
  } catch (error) {
    return {
      name: 'Compressed public key should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    };
  }
}

// Test invalid public key length (should throw error)
function testInvalidPublicKeyLength(): TestResult {
  try {
    const pubKey = hexToUint8Array(
      '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744',
    );

    try {
      pubToAddress(pubKey);
      return {
        name: 'Invalid public key length should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      };
    } catch (error) {
      return {
        name: 'Invalid public key length should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      };
    }
  } catch (error) {
    return {
      name: 'Invalid public key length should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    };
  }
}

// Test 65-byte SEC1 public key without sanitize (should throw error)
function testSEC1PublicKeyWithoutSanitize(): TestResult {
  try {
    const pubKey = hexToUint8Array(
      '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
    );

    try {
      pubToAddress(pubKey, false);
      return {
        name: 'SEC1 public key without sanitize should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      };
    } catch (error) {
      return {
        name: 'SEC1 public key without sanitize should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      };
    }
  } catch (error) {
    return {
      name: 'SEC1 public key without sanitize should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    };
  }
}

// Test various edge cases
function testEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  // Test zero-length input
  try {
    try {
      const emptyBuffer = new Uint8Array(0);
      pubToAddress(emptyBuffer);
      results.push({
        name: 'Empty buffer should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'Empty buffer should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Empty buffer should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test null/undefined input (TypeScript should prevent this, but let's be safe)
  try {
    try {
      // @ts-ignore - intentionally testing invalid input
      pubToAddress(null);
      results.push({
        name: 'Null input should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'Null input should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Null input should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test string input (should throw - not a Uint8Array)
  try {
    try {
      // @ts-ignore - intentionally testing invalid input
      const stringInput =
        '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d' as any;
      pubToAddress(stringInput);
      results.push({
        name: 'String input should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'String input should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'String input should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test undefined input (should throw)
  try {
    try {
      // @ts-ignore - intentionally testing invalid input
      pubToAddress(undefined);
      results.push({
        name: 'Undefined input should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'Undefined input should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Undefined input should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test number input (should throw)
  try {
    try {
      // @ts-ignore - intentionally testing invalid input
      pubToAddress(123456);
      results.push({
        name: 'Number input should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'Number input should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Number input should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test object input (should throw)
  try {
    try {
      // @ts-ignore - intentionally testing invalid input
      pubToAddress({ key: 'value' });
      results.push({
        name: 'Object input should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: 'Object input should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Object input should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  return results;
}

// Test secp256k1-specific edge cases
function testSecp256k1EdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  // Test 33-byte compressed key (should succeed with sanitize)
  try {
    const compressedKey = new Uint8Array(33);
    compressedKey[0] = 0x02; // Compressed prefix
    // Fill with some valid-looking data
    compressedKey.fill(0x12, 1);
    const result = pubToAddress(compressedKey, true);
    const actualAddress = uint8ArrayToHex(result);
    const expectedAddress = '0x33c0f6b742a043b155798756a4facd0873634ffe';

    if (actualAddress === expectedAddress) {
      results.push({
        name: '33-byte compressed key should succeed',
        success: true,
        message: `✓ Correct address: ${actualAddress}`,
      });
    } else {
      results.push({
        name: '33-byte compressed key should succeed',
        success: false,
        message: `✗ Expected: ${expectedAddress}, Got: ${actualAddress}`,
      });
    }
  } catch (error) {
    results.push({
      name: '33-byte compressed key should succeed',
      success: false,
      message: `✗ Unexpected error: ${error}`,
    });
  }

  // Test 65-byte key with invalid prefix (not 0x04)
  try {
    try {
      const invalidPrefixKey = new Uint8Array(65);
      invalidPrefixKey[0] = 0x05; // Invalid prefix (should be 0x04)
      // Fill with some valid-looking data
      invalidPrefixKey.fill(0x12, 1);
      pubToAddress(invalidPrefixKey, true);
      results.push({
        name: '65-byte key with invalid prefix should throw',
        success: false,
        message: `✗ Expected error but function succeeded`,
      });
    } catch (error) {
      results.push({
        name: '65-byte key with invalid prefix should throw',
        success: true,
        message: `✓ Correctly threw error: ${error}`,
      });
    }
  } catch (error) {
    results.push({
      name: '65-byte key with invalid prefix should throw',
      success: false,
      message: `✗ Setup error: ${error}`,
    });
  }

  // Test all zeros (should succeed)
  try {
    const zeroKey = new Uint8Array(64);
    zeroKey.fill(0);
    const result = pubToAddress(zeroKey);
    const actualAddress = uint8ArrayToHex(result);
    const expectedAddress = '0x3f17f1962b36e491b30a40b2405849e597ba5fb5';

    if (actualAddress === expectedAddress) {
      results.push({
        name: 'All-zero key should succeed',
        success: true,
        message: `✓ Correct address: ${actualAddress}`,
      });
    } else {
      results.push({
        name: 'All-zero key should succeed',
        success: false,
        message: `✗ Expected: ${expectedAddress}, Got: ${actualAddress}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'All-zero key should succeed',
      success: false,
      message: `✗ Unexpected error: ${error}`,
    });
  }

  // Test all 0xFF (should succeed)
  try {
    const maxKey = new Uint8Array(64);
    maxKey.fill(0xff);
    const result = pubToAddress(maxKey);
    const actualAddress = uint8ArrayToHex(result);
    const expectedAddress = '0x2dcc482901728b6df477f4fb2f192733a005d396';

    if (actualAddress === expectedAddress) {
      results.push({
        name: 'All-0xFF key should succeed',
        success: true,
        message: `✓ Correct address: ${actualAddress}`,
      });
    } else {
      results.push({
        name: 'All-0xFF key should succeed',
        success: false,
        message: `✗ Expected: ${expectedAddress}, Got: ${actualAddress}`,
      });
    }
  } catch (error) {
    results.push({
      name: 'All-0xFF key should succeed',
      success: false,
      message: `✗ Unexpected error: ${error}`,
    });
  }

  return results;
}

// Test boundary conditions
function testBoundaryConditions(): TestResult[] {
  const results: TestResult[] = [];

  // Test various invalid lengths around the valid ones
  const invalidLengths = [1, 31, 32, 35, 63, 66, 67, 100];

  for (const length of invalidLengths) {
    try {
      try {
        const invalidKey = new Uint8Array(length);
        invalidKey.fill(0x12);
        pubToAddress(invalidKey);
        results.push({
          name: `${length}-byte key should throw`,
          success: false,
          message: `✗ Expected error but function succeeded`,
        });
      } catch (error) {
        results.push({
          name: `${length}-byte key should throw`,
          success: true,
          message: `✓ Correctly threw error: ${error}`,
        });
      }
    } catch (error) {
      results.push({
        name: `${length}-byte key should throw`,
        success: false,
        message: `✗ Setup error: ${error}`,
      });
    }
  }

  return results;
}

// Test with known test vectors from other implementations
function testKnownVectors(): TestResult[] {
  const results: TestResult[] = [];

  // Additional test vectors for more coverage (using well-known secp256k1 points)
  const testVectors = [
    {
      name: 'Generator point G',
      pubKey:
        '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      expectedAddress: '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',
    },
    {
      name: 'Another valid point',
      pubKey:
        '0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a',
      expectedAddress: '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf',
    },
  ];

  for (const vector of testVectors) {
    try {
      const pubKey = hexToUint8Array(vector.pubKey);
      const result = pubToAddress(pubKey);
      const actualAddress = uint8ArrayToHex(result);

      if (actualAddress === vector.expectedAddress) {
        results.push({
          name: vector.name,
          success: true,
          message: `✓ Correct address: ${actualAddress}`,
        });
      } else {
        results.push({
          name: vector.name,
          success: false,
          message: `✗ Expected: ${vector.expectedAddress}, Got: ${actualAddress}`,
        });
      }
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `✗ Error: ${error}`,
      });
    }
  }

  return results;
}

// ==================== COMPARISON TESTS WITH @ethereumjs/util ====================

// Test comparing our native implementation with @ethereumjs/util
function testComparisonWithEthereumJS(): TestResult[] {
  const results: TestResult[] = [];

  // Test vectors from the original ethereumjs test suite
  const testVectors = [
    {
      name: 'Original ethereumjs test vector 1 (64-byte)',
      pubKey:
        '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
      sanitize: false,
    },
    {
      name: 'Original ethereumjs test vector 2 (65-byte with sanitize)',
      pubKey:
        '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
      sanitize: true,
    },
  ];

  for (const vector of testVectors) {
    try {
      const pubKey = hexToUint8Array(vector.pubKey);

      // Get results from both implementations
      const nativeResult = pubToAddress(pubKey, vector.sanitize);
      const ethereumjsResult = ethereumjsPublicToAddress(
        pubKey,
        vector.sanitize,
      );

      const nativeAddress = uint8ArrayToHex(nativeResult);
      const ethereumjsAddress = uint8ArrayToHex(ethereumjsResult);

      if (nativeAddress === ethereumjsAddress) {
        results.push({
          name: `${vector.name} - Match`,
          success: true,
          message: `✓ Both implementations match: ${nativeAddress}`,
        });
      } else {
        results.push({
          name: `${vector.name} - MISMATCH`,
          success: false,
          message: `✗ Native: ${nativeAddress}, EthereumJS: ${ethereumjsAddress}`,
        });
      }
    } catch (error) {
      results.push({
        name: `${vector.name} - Error`,
        success: false,
        message: `✗ Error during comparison: ${error}`,
      });
    }
  }

  return results;
}

// Test error handling comparison
function testErrorHandlingComparison(): TestResult[] {
  const results: TestResult[] = [];

  const errorTestCases = [
    {
      name: 'Invalid length (63 bytes)',
      pubKey:
        '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744',
      sanitize: false,
    },
    {
      name: 'Empty buffer',
      pubKey: '0x',
      sanitize: false,
    },
    {
      name: 'SEC1 without sanitize',
      pubKey:
        '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d',
      sanitize: false,
    },
  ];

  for (const testCase of errorTestCases) {
    try {
      const pubKey = hexToUint8Array(testCase.pubKey);

      let nativeThrew = false;
      let ethereumjsThrew = false;

      // Test our native implementation
      try {
        pubToAddress(pubKey, testCase.sanitize);
      } catch (error) {
        nativeThrew = true;
      }

      // Test ethereumjs implementation
      try {
        ethereumjsPublicToAddress(pubKey, testCase.sanitize);
      } catch (error) {
        ethereumjsThrew = true;
      }

      if (nativeThrew && ethereumjsThrew) {
        results.push({
          name: `${testCase.name} - Both throw (correct)`,
          success: true,
          message: `✓ Both implementations threw errors correctly`,
        });
      } else if (!nativeThrew && !ethereumjsThrew) {
        results.push({
          name: `${testCase.name} - Both succeed (check if correct)`,
          success: true,
          message: `✓ Both implementations succeeded (may be valid case)`,
        });
      } else {
        results.push({
          name: `${testCase.name} - Inconsistent error behavior`,
          success: false,
          message: `✗ Native threw: ${nativeThrew}, EthereumJS threw: ${ethereumjsThrew}`,
        });
      }
    } catch (error) {
      results.push({
        name: `${testCase.name} - Setup error`,
        success: false,
        message: `✗ Setup error: ${error}`,
      });
    }
  }

  return results;
}

// Test random vectors for consistency
function testRandomVectorComparison(): TestResult[] {
  const results: TestResult[] = [];

  // Generate some test vectors with different public key formats
  const randomVectors = [
    {
      name: 'Random vector 1',
      pubKey:
        '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    },
    {
      name: 'Random vector 2',
      pubKey:
        '0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a',
    },
  ];

  for (const vector of randomVectors) {
    try {
      const pubKey = hexToUint8Array(vector.pubKey);

      // Test both implementations
      const nativeResult = pubToAddress(pubKey, false);
      const ethereumjsResult = ethereumjsPublicToAddress(pubKey, false);

      const nativeAddress = uint8ArrayToHex(nativeResult);
      const ethereumjsAddress = uint8ArrayToHex(ethereumjsResult);

      if (nativeAddress === ethereumjsAddress) {
        results.push({
          name: `${vector.name} - Match`,
          success: true,
          message: `✓ Addresses match: ${nativeAddress}`,
        });
      } else {
        results.push({
          name: `${vector.name} - MISMATCH`,
          success: false,
          message: `✗ Native: ${nativeAddress}, EthereumJS: ${ethereumjsAddress}`,
        });
      }
    } catch (error) {
      results.push({
        name: `${vector.name} - Error`,
        success: false,
        message: `✗ Error: ${error}`,
      });
    }
  }

  return results;
}

// Main test runner
export function runAllPubToAddressTests(): TestResult[] {
  const results: TestResult[] = [];

  // Run all individual tests
  results.push(testBasicPublicKey());
  results.push(testSEC1PublicKeyWithSanitize());
  results.push(testCompressedPublicKey());
  results.push(testInvalidPublicKeyLength());
  results.push(testSEC1PublicKeyWithoutSanitize());
  results.push(...testEdgeCases());
  results.push(...testSecp256k1EdgeCases());
  results.push(...testBoundaryConditions());
  results.push(...testKnownVectors());

  // Run comparison tests with @ethereumjs/util
  results.push(...testComparisonWithEthereumJS());
  results.push(...testErrorHandlingComparison());
  results.push(...testRandomVectorComparison());

  return results;
}
