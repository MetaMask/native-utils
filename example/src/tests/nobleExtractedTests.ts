import { getPublicKey } from '@metamask/native-utils';
import * as secp256k1 from '@noble/secp256k1';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';

// Test vectors from noble/secp256k1 privates-2.txt
// All 46 comprehensive test vectors - we'll calculate expected values using noble directly
const PRIVATE_KEY_VECTORS = [
  // Basic sequential numbers
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
  '10',
  '11',
  '12',
  '13',
  '14',
  '15',
  '16',
  '17',
  '18',
  '19',
  '20',

  // Larger numbers
  '112233445566778899',
  '112233445566778899112233445566778899',

  // Very large numbers
  '28948022309329048855892746252171976963209391069768726095651290785379540373584',
  '57896044618658097711785492504343953926418782139537452191302581570759080747168', // N/2
  '86844066927987146567678238756515930889628173209306178286953872356138621120752', // 3N/4

  // Numbers close to curve order N (edge cases)
  '115792089237316195423570985008687907852837564279074904382605163141518161494317', // N-1
  '115792089237316195423570985008687907852837564279074904382605163141518161494318', // N-2
  '115792089237316195423570985008687907852837564279074904382605163141518161494319', // N-3
  '115792089237316195423570985008687907852837564279074904382605163141518161494320', // N-4
  '115792089237316195423570985008687907852837564279074904382605163141518161494321', // N-5
  '115792089237316195423570985008687907852837564279074904382605163141518161494322', // N-6
  '115792089237316195423570985008687907852837564279074904382605163141518161494323', // N-7
  '115792089237316195423570985008687907852837564279074904382605163141518161494324', // N-8
  '115792089237316195423570985008687907852837564279074904382605163141518161494325', // N-9
  '115792089237316195423570985008687907852837564279074904382605163141518161494326', // N-10
  '115792089237316195423570985008687907852837564279074904382605163141518161494327', // N-11
  '115792089237316195423570985008687907852837564279074904382605163141518161494328', // N-12
  '115792089237316195423570985008687907852837564279074904382605163141518161494329', // N-13
  '115792089237316195423570985008687907852837564279074904382605163141518161494330', // N-14
  '115792089237316195423570985008687907852837564279074904382605163141518161494331', // N-15
  '115792089237316195423570985008687907852837564279074904382605163141518161494332', // N-16
  '115792089237316195423570985008687907852837564279074904382605163141518161494333', // N-17
  '115792089237316195423570985008687907852837564279074904382605163141518161494334', // N-18
  '115792089237316195423570985008687907852837564279074904382605163141518161494335', // N-19
  '115792089237316195423570985008687907852837564279074904382605163141518161494336', // N-20
];

// Test type validation for getPublicKey - extracted from noble/secp256k1 basic.test.js
export const testNobleTypeValidation = (): TestResult[] => {
  const results: TestResult[] = [];

  const invalidInputs = [
    [0, '0'],
    [0n, '0n'],
    [-123n, '-123n'],
    [123, '123'],
    [123.456, '123.456'],
    [true, 'true'],
    [false, 'false'],
    [null, 'null'],
    [undefined, 'undefined'],
    ['', "''"],
    ['key', "'key'"],
    [{}, '{}'],
    [new Uint8Array([]), 'empty Uint8Array'],
    [new Uint8Array([0]), 'single byte Uint8Array'],
    [new Uint8Array([1]), 'single byte Uint8Array(1)'],
    [new Uint8Array(4096).fill(1), 'oversized Uint8Array'],
    [Array(32).fill(1), 'Array instead of Uint8Array'],
  ];

  for (const [input, description] of invalidInputs) {
    try {
      getPublicKey(input as any, true);
      results.push({
        name: `Type validation: ${description} (should throw)`,
        success: false,
        message: `Expected to throw for input: ${description}, but it didn't`,
      });
    } catch (error) {
      results.push({
        name: `Type validation: ${description} (should throw)`,
        success: true,
        message: `✓ Correctly throws error for ${description}`,
      });
    }
  }

  return results;
};

// Test known private key vectors from noble/secp256k1 - using noble directly for expected values
export const testNoblePrivateKeyVectors = (): TestResult[] => {
  const results: TestResult[] = [];

  for (const privateKeyStr of PRIVATE_KEY_VECTORS) {
    // Convert decimal string to hex, then pad to 32 bytes (64 hex chars)
    const privateKeyBigInt = BigInt(privateKeyStr);
    const privateKeyHex = privateKeyBigInt.toString(16);
    const privateKey = privateKeyHex.padStart(64, '0');

    try {
      // Get expected values from noble library directly
      const privateKeyBytes = hexToUint8Array(privateKey);
      const expectedCompressed = secp256k1.getPublicKey(privateKeyBytes, true);
      const expectedUncompressed = secp256k1.getPublicKey(
        privateKeyBytes,
        false,
      );

      // Test compressed format
      const nativeCompressed = getPublicKey(privateKey, true);
      const nativeCompressedHex = uint8ArrayToHex(nativeCompressed);
      const expectedCompressedHex = uint8ArrayToHex(expectedCompressed);

      const compressedMatches = nativeCompressedHex === expectedCompressedHex;
      results.push({
        name: `Noble vector ${privateKeyStr} - Compressed`,
        success: compressedMatches,
        message: compressedMatches
          ? '✓ Matches noble library result'
          : `Expected: ${expectedCompressedHex}, Got: ${nativeCompressedHex}`,
      });

      // Test uncompressed format
      const nativeUncompressed = getPublicKey(privateKey, false);
      const nativeUncompressedHex = uint8ArrayToHex(nativeUncompressed);
      const expectedUncompressedHex = uint8ArrayToHex(expectedUncompressed);

      const uncompressedMatches =
        nativeUncompressedHex === expectedUncompressedHex;
      results.push({
        name: `Noble vector ${privateKeyStr} - Uncompressed`,
        success: uncompressedMatches,
        message: uncompressedMatches
          ? '✓ Matches noble library result'
          : `Expected: ${expectedUncompressedHex}, Got: ${nativeUncompressedHex}`,
      });
    } catch (error) {
      results.push({
        name: `Noble vector ${privateKeyStr} - Error`,
        success: false,
        message: `Error processing vector: ${error}`,
      });
    }
  }

  return results;
};

// Test edge cases from noble/secp256k1 secp256k1.test.js
export const testNobleEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test invalid private keys that should throw
  const invalidPrivateKeys = [
    {
      key: '0000000000000000000000000000000000000000000000000000000000000000',
      description: 'zero private key',
    },
    {
      key: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
      description: 'private key >= curve order',
    },
    {
      key: 'invalid_hex_string',
      description: 'invalid hex string',
    },
    {
      key: 'deadbeef',
      description: 'too short hex string',
    },
    {
      key: 'deadbeef'.repeat(20),
      description: 'too long hex string',
    },
  ];

  for (const { key, description } of invalidPrivateKeys) {
    try {
      getPublicKey(key, true);
      results.push({
        name: `Edge case: ${description} (should throw)`,
        success: false,
        message: `Expected to throw for ${description}, but it didn't`,
      });
    } catch (error) {
      results.push({
        name: `Edge case: ${description} (should throw)`,
        success: true,
        message: `✓ Correctly throws error for ${description}`,
      });
    }
  }

  // Test valid edge cases
  const validPrivateKeys = [
    {
      key: '0000000000000000000000000000000000000000000000000000000000000001',
      description: 'minimum valid private key (1)',
    },
    {
      key: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
      description: 'maximum valid private key (n-1)',
    },
  ];

  for (const { key, description } of validPrivateKeys) {
    try {
      const result = getPublicKey(key, true);
      results.push({
        name: `Valid edge case: ${description}`,
        success: result.length === 33,
        message:
          result.length === 33
            ? `✓ Valid ${description} produces 33-byte compressed key`
            : `Expected 33 bytes, got ${result.length}`,
      });
    } catch (error) {
      results.push({
        name: `Valid edge case: ${description}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
};

// Test argument validation (missing arguments)
export const testNobleArgumentValidation = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test missing arguments
  try {
    // @ts-expect-error - testing missing argument
    getPublicKey();
    results.push({
      name: 'Missing arguments (should throw)',
      success: false,
      message: "Expected to throw for missing arguments, but it didn't",
    });
  } catch (error) {
    results.push({
      name: 'Missing arguments (should throw)',
      success: true,
      message: '✓ Correctly throws error for missing arguments',
    });
  }

  // Test wrong length Uint8Array
  const wrongLengthArrays = [
    new Uint8Array(31), // Too short
    new Uint8Array(33), // Too long
  ];

  for (const arr of wrongLengthArrays) {
    try {
      getPublicKey(arr, true);
      results.push({
        name: `Wrong length Uint8Array (${arr.length} bytes) (should throw)`,
        success: false,
        message: `Expected to throw for ${arr.length}-byte array, but it didn't`,
      });
    } catch (error) {
      results.push({
        name: `Wrong length Uint8Array (${arr.length} bytes) (should throw)`,
        success: true,
        message: `✓ Correctly throws error for ${arr.length}-byte array`,
      });
    }
  }

  return results;
};

// Test public key format validation
export const testNoblePublicKeyFormat = (): TestResult[] => {
  const results: TestResult[] = [];
  const testPrivateKey =
    '0000000000000000000000000000000000000000000000000000000000000001';

  try {
    // Test compressed format
    const compressed = getPublicKey(testPrivateKey, true);
    const compressedBytes = new Uint8Array(compressed);

    results.push({
      name: 'Compressed public key length',
      success: compressed.length === 33,
      message:
        compressed.length === 33
          ? '✓ Compressed key is 33 bytes'
          : `Expected 33 bytes, got ${compressed.length}`,
    });

    const firstByte = compressedBytes[0];
    const validPrefix =
      firstByte !== undefined && (firstByte === 0x02 || firstByte === 0x03);
    results.push({
      name: 'Compressed public key prefix',
      success: validPrefix,
      message: validPrefix
        ? `✓ Valid prefix: 0x${firstByte!.toString(16).padStart(2, '0')}`
        : `Invalid prefix: 0x${firstByte?.toString(16).padStart(2, '0') || 'undefined'} (expected 0x02 or 0x03)`,
    });

    // Test uncompressed format
    const uncompressed = getPublicKey(testPrivateKey, false);
    const uncompressedBytes = new Uint8Array(uncompressed);

    results.push({
      name: 'Uncompressed public key length',
      success: uncompressed.length === 65,
      message:
        uncompressed.length === 65
          ? '✓ Uncompressed key is 65 bytes'
          : `Expected 65 bytes, got ${uncompressed.length}`,
    });

    const firstByteUncompressed = uncompressedBytes[0];
    const validUncompressedPrefix =
      firstByteUncompressed !== undefined && firstByteUncompressed === 0x04;
    results.push({
      name: 'Uncompressed public key prefix',
      success: validUncompressedPrefix,
      message: validUncompressedPrefix
        ? `✓ Valid prefix: 0x${firstByteUncompressed!.toString(16).padStart(2, '0')}`
        : `Invalid prefix: 0x${firstByteUncompressed?.toString(16).padStart(2, '0') || 'undefined'} (expected 0x04)`,
    });
  } catch (error) {
    results.push({
      name: 'Public key format validation',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test hex string format variations - only formats that noble library actually supports
export const testNobleHexStringVariations = (): TestResult[] => {
  const results: TestResult[] = [];
  const baseKey =
    '0000000000000000000000000000000000000000000000000000000000000001';

  // Test different hex string formats that noble actually supports
  const hexVariations = [
    { key: baseKey, description: 'lowercase hex' },
    { key: baseKey.toUpperCase(), description: 'uppercase hex' },
  ];

  // Test hex strings with prefixes to verify they are rejected (noble doesn't support prefixes)
  const prefixVariations = [
    { key: '0x' + baseKey, description: 'with 0x prefix (should fail)' },
    {
      key: '0X' + baseKey.toUpperCase(),
      description: 'with 0X prefix (should fail)',
    },
  ];

  const referenceResult = getPublicKey(baseKey, true);
  const referenceHex = uint8ArrayToHex(referenceResult);

  // Test supported formats
  for (const { key, description } of hexVariations) {
    try {
      const result = getPublicKey(key, true);
      const resultHex = uint8ArrayToHex(result);
      const matches = resultHex === referenceHex;

      results.push({
        name: `Hex variation: ${description}`,
        success: matches,
        message: matches
          ? `✓ Produces same result as reference`
          : `Different result: ${resultHex} vs ${referenceHex}`,
      });
    } catch (error) {
      results.push({
        name: `Hex variation: ${description}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  // Test unsupported formats (should fail)
  for (const { key, description } of prefixVariations) {
    try {
      getPublicKey(key, true);
      results.push({
        name: `Hex variation: ${description}`,
        success: false,
        message: `Expected to fail but succeeded - noble doesn't support hex prefixes`,
      });
    } catch (error) {
      results.push({
        name: `Hex variation: ${description}`,
        success: true,
        message: `✓ Correctly fails as expected (noble doesn't support hex prefixes)`,
      });
    }
  }

  return results;
};

// Main function to run all noble extracted tests
export const runAllNobleExtractedTests = (): TestResult[] => {
  const results: TestResult[] = [];

  results.push(...testNobleTypeValidation());
  results.push(...testNoblePrivateKeyVectors());
  results.push(...testNobleEdgeCases());
  results.push(...testNobleArgumentValidation());
  results.push(...testNoblePublicKeyFormat());
  results.push(...testNobleHexStringVariations());

  return results;
};
