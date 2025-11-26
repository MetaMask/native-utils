import { getPublicKeyEd25519 } from '@metamask/native-utils';
import { ed25519 } from '@noble/curves/ed25519';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';

// Test cases with known results from RFC 8032
const testCases = [
  {
    name: 'RFC 8032 Test Vector 1',
    privateKey:
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    expectedPublicKey:
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  },
  {
    name: 'RFC 8032 Test Vector 2',
    privateKey:
      '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    expectedPublicKey:
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  },
  {
    name: 'RFC 8032 Test Vector 3',
    privateKey:
      '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783',
    expectedPublicKey:
      '77d1d8ebacd13f4e2f8a40e28c4a63bc9ce3bfb69716334bcb28a33eb134086c',
  },
  {
    name: 'RFC 8032 Test Vector 4',
    privateKey:
      'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    expectedPublicKey:
      '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
  },
];

// Basic functionality test
export const testEd25519BasicFunctionality = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKey =
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

  try {
    const publicKey = getPublicKeyEd25519(privateKey);
    results.push({
      name: 'Ed25519 public key generation',
      success: publicKey.byteLength === 32,
      message: `Generated ${publicKey.byteLength} byte public key (expected 32)`,
    });

    // Test return type
    results.push({
      name: 'Ed25519 return type is Uint8Array',
      success: publicKey instanceof Uint8Array,
      message:
        publicKey instanceof Uint8Array
          ? '✓ Returns Uint8Array as expected'
          : '✗ Does not return Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 basic functionality',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test public key format
export const testEd25519PublicKeyFormat = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKey =
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

  try {
    // Test with string input
    const publicKeyFromString = getPublicKeyEd25519(privateKey);
    results.push({
      name: 'Ed25519 public key from string - length',
      success: publicKeyFromString.byteLength === 32,
      message: `Length: ${publicKeyFromString.byteLength} bytes (expected 32)`,
    });

    // Test with Uint8Array input
    const privateKeyBytes = hexToUint8Array(privateKey);
    const publicKeyFromBytes = getPublicKeyEd25519(privateKeyBytes);
    results.push({
      name: 'Ed25519 public key from Uint8Array - length',
      success: publicKeyFromBytes.byteLength === 32,
      message: `Length: ${publicKeyFromBytes.byteLength} bytes (expected 32)`,
    });

    // Test that both input types produce same result
    const hexString = uint8ArrayToHex(publicKeyFromString, false);
    const hexBytes = uint8ArrayToHex(publicKeyFromBytes, false);
    const match = hexString === hexBytes;
    results.push({
      name: 'Ed25519 string and Uint8Array inputs produce same result',
      success: match,
      message: match
        ? '✓ Both input types produce identical results'
        : `✗ Results differ - String: ${hexString.slice(0, 20)}..., Uint8Array: ${hexBytes.slice(0, 20)}...`,
    });

    // Test compressed parameter is ignored (Ed25519 has no compressed form)
    const publicKeyIgnoreCompressed = getPublicKeyEd25519(privateKey, true);
    const hexIgnoreCompressed = uint8ArrayToHex(
      publicKeyIgnoreCompressed,
      false,
    );
    const compressedMatch = hexString === hexIgnoreCompressed;
    results.push({
      name: 'Ed25519 compressed parameter is ignored',
      success: compressedMatch,
      message: compressedMatch
        ? '✓ Compressed parameter correctly ignored'
        : '✗ Compressed parameter affected output',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 public key format',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test known test vectors
export const testEd25519KnownVectors = (): TestResult[] => {
  const results: TestResult[] = [];

  for (const testCase of testCases) {
    try {
      const publicKey = getPublicKeyEd25519(testCase.privateKey);
      const hexResult = uint8ArrayToHex(publicKey, false);
      const matches = hexResult === testCase.expectedPublicKey;

      results.push({
        name: `${testCase.name}`,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Got: ${hexResult}\nExpected: ${testCase.expectedPublicKey}`,
      });
    } catch (error) {
      results.push({
        name: `${testCase.name}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
};

// Test input type variants
export const testEd25519InputVariants = (): TestResult[] => {
  const results: TestResult[] = [];
  const privateKeyHex =
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const privateKeyUint8Array = hexToUint8Array(privateKeyHex);

  try {
    // Test string input
    const resultString = getPublicKeyEd25519(privateKeyHex);
    results.push({
      name: 'Ed25519 string input format',
      success: resultString.length === 32,
      message: `String input produces ${resultString.length} bytes (expected 32)`,
    });

    // Test Uint8Array input
    const resultUint8Array = getPublicKeyEd25519(privateKeyUint8Array);
    results.push({
      name: 'Ed25519 Uint8Array input format',
      success: resultUint8Array.length === 32,
      message: `Uint8Array input produces ${resultUint8Array.length} bytes (expected 32)`,
    });

    // Test cross-compatibility: all input types should produce same result
    const hexString = uint8ArrayToHex(resultString, false);
    const hexUint8Array = uint8ArrayToHex(resultUint8Array, false);

    const allMatch = hexString === hexUint8Array;
    results.push({
      name: 'Ed25519 cross-compatibility: All input types produce same result',
      success: allMatch,
      message: allMatch
        ? '✓ String and Uint8Array inputs produce identical results'
        : `✗ Results differ - String: ${hexString.slice(0, 20)}..., Uint8Array: ${hexUint8Array.slice(0, 20)}...`,
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 input variants',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test Uint8Array edge cases
export const testEd25519Uint8ArrayEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test wrong length Uint8Array (should throw)
  try {
    const wrongLength = new Uint8Array(31); // Too short
    getPublicKeyEd25519(wrongLength);
    results.push({
      name: 'Ed25519 wrong length Uint8Array (should throw)',
      success: false,
      message: 'Should have thrown error for wrong length Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 wrong length Uint8Array (should throw)',
      success: true,
      message: '✓ Correctly throws error for wrong length Uint8Array',
    });
  }

  // Test empty Uint8Array (should throw)
  try {
    const empty = new Uint8Array(0);
    getPublicKeyEd25519(empty);
    results.push({
      name: 'Ed25519 empty Uint8Array (should throw)',
      success: false,
      message: 'Should have thrown error for empty Uint8Array',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 empty Uint8Array (should throw)',
      success: true,
      message: '✓ Correctly throws error for empty Uint8Array',
    });
  }

  // Test valid random Uint8Array
  try {
    const validKey = new Uint8Array(32);
    // Fill with a known valid private key from test vectors
    validKey.set(
      hexToUint8Array(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      ),
    );
    const result = getPublicKeyEd25519(validKey);
    results.push({
      name: 'Ed25519 valid random Uint8Array',
      success: result.length === 32,
      message: `Valid Uint8Array produces ${result.length} bytes (expected 32)`,
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 valid random Uint8Array',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Compare with noble/curves ed25519
export const testEd25519NobleComparison = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test multiple vectors
  const testVectors = [
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783',
    'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
  ];

  for (let i = 0; i < testVectors.length; i++) {
    const privateKey = testVectors[i]!;
    try {
      const nativePublicKey = getPublicKeyEd25519(privateKey);
      const privateKeyBytes = hexToUint8Array(privateKey);
      const noblePublicKey = ed25519.getPublicKey(privateKeyBytes);

      const nativeHex = uint8ArrayToHex(nativePublicKey, false);
      const nobleHex = uint8ArrayToHex(noblePublicKey, false);
      const matches = nativeHex === nobleHex;

      results.push({
        name: `Ed25519 Native vs Noble - Vector ${i + 1}`,
        success: matches,
        message: matches
          ? '✓ Results match'
          : `Native: ${nativeHex}\nNoble: ${nobleHex}`,
      });
    } catch (error) {
      results.push({
        name: `Ed25519 Native vs Noble - Vector ${i + 1}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
};

// Error handling tests
export const testEd25519ErrorHandling = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test invalid hex string
  try {
    getPublicKeyEd25519('invalid_hex_string');
    results.push({
      name: 'Ed25519 invalid hex string handling',
      success: false,
      message: 'Should have thrown error for invalid hex string',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 invalid hex string handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  // Test wrong length key (too short)
  try {
    getPublicKeyEd25519('deadbeef');
    results.push({
      name: 'Ed25519 wrong length key (too short) handling',
      success: false,
      message: 'Should have thrown error for wrong length key',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 wrong length key (too short) handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  // Test wrong length key (too long)
  try {
    getPublicKeyEd25519('deadbeef'.repeat(20)); // Too long
    results.push({
      name: 'Ed25519 wrong length key (too long) handling',
      success: false,
      message: 'Should have thrown error for wrong length key',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 wrong length key (too long) handling',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  // Test with 0x prefix (should fail - we don't accept prefixes in hex string)
  try {
    getPublicKeyEd25519(
      '0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    );
    results.push({
      name: 'Ed25519 hex string with 0x prefix (should throw)',
      success: false,
      message: 'Should have thrown error for hex string with 0x prefix',
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 hex string with 0x prefix (should throw)',
      success: true,
      message: '✓ Throws error as expected',
    });
  }

  return results;
};
