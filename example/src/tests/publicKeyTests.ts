import { multiply, getPublicKey } from '@metamask/native-utils';
import * as secp256k1 from '@noble/secp256k1';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';

// Test cases with known results
const testCases = [
  {
    name: 'Private key 0x01',
    privateKey:
      '0000000000000000000000000000000000000000000000000000000000000001',
    expectedCompressed:
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    expectedUncompressed:
      '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  },
  {
    name: 'Private key 0x02',
    privateKey:
      '0000000000000000000000000000000000000000000000000000000000000002',
    expectedCompressed:
      '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    expectedUncompressed:
      '04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a',
  },
  {
    name: 'Random private key',
    privateKey:
      'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    expectedCompressed: null, // Will be calculated
    expectedUncompressed: null,
  },
];

// Basic functionality test
export const testBasicFunctionality = (): TestResult[] => {
  const results: TestResult[] = [];
  const multiplyResult = multiply(3, 7);

  results.push({
    name: 'Multiply function',
    success: multiplyResult === 21,
    message: `3 × 7 = ${multiplyResult} (expected 21)`,
  });

  return results;
};

// Test public key generation formats
export const testPublicKeyFormats = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKey =
    '0000000000000000000000000000000000000000000000000000000000000001';

  try {
    // Test compressed format
    const compressed = getPublicKey(privateKey, true);
    results.push({
      name: 'Compressed public key format',
      success: compressed.byteLength === 33,
      message: `Length: ${compressed.byteLength} bytes (expected 33)`,
    });

    // Test uncompressed format
    const uncompressed = getPublicKey(privateKey, false);
    results.push({
      name: 'Uncompressed public key format',
      success: uncompressed.byteLength === 65,
      message: `Length: ${uncompressed.byteLength} bytes (expected 65)`,
    });

    // Test default parameter (should be compressed)
    const defaultFormat = getPublicKey(privateKey);
    results.push({
      name: 'Default format (compressed)',
      success: defaultFormat.byteLength === 33,
      message: `Length: ${defaultFormat.byteLength} bytes (expected 33)`,
    });

    // Test prefix bytes
    const compressedBytes = new Uint8Array(compressed);
    const firstCompressedByte = compressedBytes[0];
    const isValidCompressedPrefix =
      firstCompressedByte === 0x02 || firstCompressedByte === 0x03;
    results.push({
      name: 'Compressed prefix validation',
      success: isValidCompressedPrefix,
      message: `First byte: 0x${firstCompressedByte?.toString(16).padStart(2, '0')} (expected 0x02 or 0x03)`,
    });

    const uncompressedBytes = new Uint8Array(uncompressed);
    const firstUncompressedByte = uncompressedBytes[0];
    const isValidUncompressedPrefix = firstUncompressedByte === 0x04;
    results.push({
      name: 'Uncompressed prefix validation',
      success: isValidUncompressedPrefix,
      message: `First byte: 0x${firstUncompressedByte?.toString(16).padStart(2, '0')} (expected 0x04)`,
    });
  } catch (error) {
    results.push({
      name: 'Public key generation error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test known test vectors
export const testKnownVectors = (): TestResult[] => {
  const results: TestResult[] = [];

  for (const testCase of testCases) {
    if (testCase.expectedCompressed !== null) {
      const expectedCompressed = testCase.expectedCompressed;
      try {
        const compressed = getPublicKey(testCase.privateKey, true);
        const hexResult = uint8ArrayToHex(compressed, false);
        const matches = hexResult === expectedCompressed;

        results.push({
          name: `${testCase.name} - Compressed`,
          success: matches,
          message: matches
            ? '✓ Matches expected result'
            : `Got: ${hexResult.slice(0, 20)}... Expected: ${expectedCompressed.slice(0, 20)}...`,
        });
      } catch (error) {
        results.push({
          name: `${testCase.name} - Compressed`,
          success: false,
          message: `Error: ${error}`,
        });
      }
    }

    if (testCase.expectedUncompressed !== null) {
      const expectedUncompressed = testCase.expectedUncompressed;
      try {
        const uncompressed = getPublicKey(testCase.privateKey, false);
        const hexResult = uint8ArrayToHex(uncompressed, false);
        const matches = hexResult === expectedUncompressed;

        results.push({
          name: `${testCase.name} - Uncompressed`,
          success: matches,
          message: matches
            ? '✓ Matches expected result'
            : `Got: ${hexResult.slice(0, 20)}... Expected: ${expectedUncompressed.slice(0, 20)}...`,
        });
      } catch (error) {
        results.push({
          name: `${testCase.name} - Uncompressed`,
          success: false,
          message: `Error: ${error}`,
        });
      }
    }
  }

  return results;
};

// Test new input variants (Uint8Array and BigInt)
export const testNewInputVariants = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKeyHex =
    '0000000000000000000000000000000000000000000000000000000000000001';
  const privateKeyBigInt =
    0x0000000000000000000000000000000000000000000000000000000000000001n;
  const privateKeyUint8Array = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ]);

  try {
    // Test BigInt input
    const resultBigInt = getPublicKey(privateKeyBigInt, true);
    results.push({
      name: 'BigInt input format',
      success: resultBigInt.length === 33,
      message: `BigInt input produces ${resultBigInt.length} bytes (expected 33)`,
    });

    // Test Uint8Array input
    const resultUint8Array = getPublicKey(privateKeyUint8Array, true);
    results.push({
      name: 'Uint8Array input format',
      success: resultUint8Array.length === 33,
      message: `Uint8Array input produces ${resultUint8Array.length} bytes (expected 33)`,
    });

    // Test cross-compatibility: all input types should produce same result
    const resultString = getPublicKey(privateKeyHex, true);
    const hexString = uint8ArrayToHex(resultString, false);
    const hexBigInt = uint8ArrayToHex(resultBigInt, false);
    const hexUint8Array = uint8ArrayToHex(resultUint8Array, false);

    const allMatch = hexString === hexBigInt && hexBigInt === hexUint8Array;
    results.push({
      name: 'Cross-compatibility: All input types produce same result',
      success: allMatch,
      message: allMatch
        ? '✓ String, BigInt, and Uint8Array inputs produce identical results'
        : `✗ Results differ - String: ${hexString.slice(0, 20)}..., BigInt: ${hexBigInt.slice(0, 20)}..., Uint8Array: ${hexUint8Array.slice(0, 20)}...`,
    });

    // Test uncompressed format with different input types
    const uncompressedString = getPublicKey(privateKeyHex, false);
    const uncompressedBigInt = getPublicKey(privateKeyBigInt, false);
    const uncompressedUint8Array = getPublicKey(privateKeyUint8Array, false);

    const uncompressedMatch =
      uint8ArrayToHex(uncompressedString, false) ===
        uint8ArrayToHex(uncompressedBigInt, false) &&
      uint8ArrayToHex(uncompressedBigInt, false) ===
        uint8ArrayToHex(uncompressedUint8Array, false);

    results.push({
      name: 'Cross-compatibility: Uncompressed format',
      success: uncompressedMatch,
      message: uncompressedMatch
        ? '✓ All input types produce identical uncompressed results'
        : '✗ Uncompressed results differ between input types',
    });

    // Test return type is Uint8Array
    results.push({
      name: 'Return type is Uint8Array',
      success: resultString instanceof Uint8Array,
      message:
        resultString instanceof Uint8Array
          ? '✓ Returns Uint8Array as expected'
          : '✗ Does not return Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'New input variants',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test BigInt edge cases
export const testBigIntEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test large valid BigInt
  try {
    const largeBigInt =
      0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140n; // N-1 (largest valid private key)
    const result = getPublicKey(largeBigInt, true);
    results.push({
      name: 'Large valid BigInt (N-1)',
      success: result.length === 33,
      message: `Large BigInt works: ${result.length} bytes`,
    });
  } catch (error) {
    results.push({
      name: 'Large valid BigInt (N-1)',
      success: false,
      message: `Error: ${error}`,
    });
  }

  // Test BigInt that's too large (should throw)
  try {
    const tooBigInt = 2n ** 256n; // Too large
    getPublicKey(tooBigInt, true);
    results.push({
      name: 'BigInt too large (should throw)',
      success: false,
      message: 'Should have thrown error for BigInt >= 2^256',
    });
  } catch (error) {
    results.push({
      name: 'BigInt too large (should throw)',
      success: true,
      message: '✓ Correctly throws error for BigInt >= 2^256',
    });
  }

  // Test zero BigInt (should throw)
  try {
    const zeroBigInt = 0n;
    getPublicKey(zeroBigInt, true);
    results.push({
      name: 'Zero BigInt (should throw)',
      success: false,
      message: 'Should have thrown error for zero BigInt',
    });
  } catch (error) {
    results.push({
      name: 'Zero BigInt (should throw)',
      success: true,
      message: '✓ Correctly throws error for zero BigInt',
    });
  }

  // Test negative BigInt (should throw)
  try {
    const negativeBigInt = -1n;
    getPublicKey(negativeBigInt, true);
    results.push({
      name: 'Negative BigInt (should throw)',
      success: false,
      message: 'Should have thrown error for negative BigInt',
    });
  } catch (error) {
    results.push({
      name: 'Negative BigInt (should throw)',
      success: true,
      message: '✓ Correctly throws error for negative BigInt',
    });
  }

  return results;
};

// Test Uint8Array edge cases
export const testUint8ArrayEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test wrong length Uint8Array (should throw)
  try {
    const wrongLength = new Uint8Array(31); // Too short
    getPublicKey(wrongLength, true);
    results.push({
      name: 'Wrong length Uint8Array (should throw)',
      success: false,
      message: 'Should have thrown error for wrong length Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'Wrong length Uint8Array (should throw)',
      success: true,
      message: '✓ Correctly throws error for wrong length Uint8Array',
    });
  }

  // Test empty Uint8Array (should throw)
  try {
    const empty = new Uint8Array(0);
    getPublicKey(empty, true);
    results.push({
      name: 'Empty Uint8Array (should throw)',
      success: false,
      message: 'Should have thrown error for empty Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'Empty Uint8Array (should throw)',
      success: true,
      message: '✓ Correctly throws error for empty Uint8Array',
    });
  }

  // Test all-zero Uint8Array (should throw error)
  try {
    const allZero = new Uint8Array(32); // All zeros
    getPublicKey(allZero, true);
    results.push({
      name: 'All-zero Uint8Array (invalid private key)',
      success: false,
      message: 'Should have thrown error for invalid private key',
    });
  } catch (error) {
    results.push({
      name: 'All-zero Uint8Array (invalid private key)',
      success: true,
      message: '✓ Correctly throws error for invalid private key',
    });
  }

  // Test valid random Uint8Array
  try {
    const randomKey = new Uint8Array(32);
    // Fill with a known valid private key
    randomKey.set([
      0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
      0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
      0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    ]);
    const result = getPublicKey(randomKey, true);
    results.push({
      name: 'Valid random Uint8Array',
      success: result.length === 33,
      message: `Valid Uint8Array produces ${result.length} bytes (expected 33)`,
    });
  } catch (error) {
    results.push({
      name: 'Valid random Uint8Array',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Compare with noble/secp256k1
export const testNobleComparison = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKey =
    '0000000000000000000000000000000000000000000000000000000000000001';

  try {
    // Test compressed
    const nativeCompressed = getPublicKey(privateKey, true);
    const privateKeyBytes = hexToUint8Array(privateKey);
    const jsCompressed = secp256k1.getPublicKey(privateKeyBytes, true);

    const nativeHex = uint8ArrayToHex(nativeCompressed, false);
    const jsHex = uint8ArrayToHex(jsCompressed, false);
    const compressedMatches = nativeHex === jsHex;

    results.push({
      name: 'Native vs JS - Compressed',
      success: compressedMatches,
      message: compressedMatches
        ? '✓ Results match'
        : `Native: ${nativeHex.slice(0, 20)}... JS: ${jsHex.slice(0, 20)}...`,
    });

    // Test uncompressed
    const nativeUncompressed = getPublicKey(privateKey, false);
    const jsUncompressed = secp256k1.getPublicKey(privateKeyBytes, false);

    const nativeUncompressedHex = uint8ArrayToHex(nativeUncompressed, false);
    const jsUncompressedHex = uint8ArrayToHex(jsUncompressed, false);
    const uncompressedMatches = nativeUncompressedHex === jsUncompressedHex;

    results.push({
      name: 'Native vs JS - Uncompressed',
      success: uncompressedMatches,
      message: uncompressedMatches
        ? '✓ Results match'
        : `Native: ${nativeUncompressedHex.slice(0, 20)}... JS: ${jsUncompressedHex.slice(0, 20)}...`,
    });
  } catch (error) {
    results.push({
      name: 'Noble comparison',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Error handling tests
export const testErrorHandling = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test invalid hex string
  try {
    getPublicKey('invalid_hex_string', true);
    results.push({
      name: 'Invalid hex string handling',
      success: false,
      message: 'Should have thrown error for invalid hex string',
    });
  } catch (error) {
    results.push({
      name: 'Invalid hex string handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  // Test wrong length key
  try {
    getPublicKey('deadbeef', true); // Too short
    results.push({
      name: 'Wrong length key handling',
      success: false,
      message: 'Should have thrown error for wrong length key',
    });
  } catch (error) {
    results.push({
      name: 'Wrong length key handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  // Test zero key (invalid)
  try {
    getPublicKey(
      '0000000000000000000000000000000000000000000000000000000000000000',
      true,
    );
    results.push({
      name: 'Zero key handling',
      success: false,
      message: 'Should have thrown error for zero key',
    });
  } catch (error) {
    results.push({
      name: 'Zero key handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  return results;
};
