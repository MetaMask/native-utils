import { getPublicKeyEd25519 } from '@metamask/native-utils';
import { ed25519 } from '@noble/curves/ed25519';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';
import rfc8032Vectors from '../vectors/rfc8032-ed25519.json';
import ed25519OldVectors from '../vectors/ed25519_test_OLD.json';
import ed25519Vectors1024 from '../vectors/vectors.json';

// Test type validation for getPublicKeyEd25519 - extracted from noble/curves ed25519.test.ts
// Based on getTypeTestsNonUi8a() from noble-curves-example/test/utils.ts
export const testEd25519NobleTypeValidation = (): TestResult[] => {
  const results: TestResult[] = [];

  const invalidInputs = [
    [0, '0'],
    [123, '123'],
    [123.456, '123.456'],
    [-5n, '-5n'],
    [1.0000000000001, '1.0000000000001'],
    [10e9999, '10e9999'],
    [Infinity, 'Infinity'],
    [-Infinity, '-Infinity'],
    [NaN, 'NaN'],
    [true, 'true'],
    [false, 'false'],
    [null, 'null'],
    [undefined, 'undefined'],
    ['', '""'],
    ['1', '"1"'],
    ['1 ', '"1 "'],
    [' 1', '" 1"'],
    ['0xbe', '"0xbe"'],
    ['keys', '"keys"'],
    [new Uint8Array(4096).fill(1), 'ui8a(4096*[1])'],
    [new Uint16Array(32).fill(1), 'ui16a(32*[1])'],
    [new Uint32Array(32).fill(1), 'ui32a(32*[1])'],
    [new Float32Array(32), 'f32a(32*0)'],
    [new BigUint64Array(32).fill(1n), 'ui64a(32*[1])'],
    [new ArrayBuffer(100), 'arraybuf'],
    [Array(32).fill(1), 'array'],
    [new Uint8Array(33).fill(1), '>32 byte Uint8Array'],
  ];

  for (const [input, description] of invalidInputs) {
    try {
      getPublicKeyEd25519(input as any);
      results.push({
        name: `Ed25519 type validation: ${description} (should throw)`,
        success: false,
        message: `Expected to throw for input: ${description}, but it didn't`,
      });
    } catch (error) {
      results.push({
        name: `Ed25519 type validation: ${description} (should throw)`,
        success: true,
        message: `✓ Correctly throws error for ${description}`,
      });
    }
  }

  return results;
};

// Test RFC 8032 vectors extracted from noble/curves
export const testEd25519RFC8032Vectors = (): TestResult[] => {
  const results: TestResult[] = [];

  interface RFC8032Vector {
    priv: string;
    pub: string;
    msg: string;
    sig: string;
  }

  const vectors = rfc8032Vectors as RFC8032Vector[];

  for (let i = 0; i < vectors.length; i++) {
    const vec = vectors[i]!;
    try {
      // Test with native implementation
      const nativePublicKey = getPublicKeyEd25519(vec.priv);
      const nativeHex = uint8ArrayToHex(nativePublicKey, false);
      const matches = nativeHex === vec.pub;

      results.push({
        name: `RFC 8032 Vector ${i + 1}`,
        success: matches,
        message: matches
          ? '✓ Matches expected public key'
          : `Expected: ${vec.pub}\nGot: ${nativeHex}`,
      });

      // Also compare with noble
      const privateKeyBytes = hexToUint8Array(vec.priv);
      const noblePublicKey = ed25519.getPublicKey(privateKeyBytes);
      const nobleHex = uint8ArrayToHex(noblePublicKey, false);
      const matchesNoble = nativeHex === nobleHex;

      results.push({
        name: `RFC 8032 Vector ${i + 1} - Noble comparison`,
        success: matchesNoble,
        message: matchesNoble
          ? '✓ Matches noble library'
          : `Native: ${nativeHex}\nNoble: ${nobleHex}`,
      });
    } catch (error) {
      results.push({
        name: `RFC 8032 Vector ${i + 1}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
};

// Test old ed25519 vectors (wycheproof) - extracted from noble/curves
export const testEd25519OldVectors = (): TestResult[] => {
  const results: TestResult[] = [];

  interface Ed25519OldVector {
    testGroups: Array<{
      key: {
        sk: string;
        pk: string;
      };
      tests: Array<any>;
    }>;
  }

  const vectors = ed25519OldVectors as Ed25519OldVector;

  for (let g = 0; g < vectors.testGroups.length; g++) {
    const group = vectors.testGroups[g]!;
    const key = group.key;

    try {
      // Test public key generation
      const nativePublicKey = getPublicKeyEd25519(key.sk);
      const nativeHex = uint8ArrayToHex(nativePublicKey, false);
      const matches = nativeHex === key.pk;

      results.push({
        name: `Old Vector Group ${g + 1} - Public Key`,
        success: matches,
        message: matches
          ? '✓ Matches expected public key'
          : `Expected: ${key.pk}\nGot: ${nativeHex}`,
      });

      // Compare with noble
      const privateKeyBytes = hexToUint8Array(key.sk);
      const noblePublicKey = ed25519.getPublicKey(privateKeyBytes);
      const nobleHex = uint8ArrayToHex(noblePublicKey, false);
      const matchesNoble = nativeHex === nobleHex;

      results.push({
        name: `Old Vector Group ${g + 1} - Noble comparison`,
        success: matchesNoble,
        message: matchesNoble
          ? '✓ Matches noble library'
          : `Native: ${nativeHex}\nNoble: ${nobleHex}`,
      });
    } catch (error) {
      results.push({
        name: `Old Vector Group ${g + 1}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
};

// Test 1024 vectors from ed25519.cr.yp.to
// https://ed25519.cr.yp.to/python/sign.py
// https://ed25519.cr.yp.to/python/sign.input
export const testEd255191024Vectors = (): TestResult[] => {
  const results: TestResult[] = [];

  interface Vector1024 {
    privPub: string;
    priv: string;
    pub: string;
    msg: string;
    sig: string;
  }

  const vectors = ed25519Vectors1024 as Vector1024[];

  let failureCount = 0;
  const maxFailuresToReport = 5; // Don't spam with all failures

  for (let i = 0; i < vectors.length; i++) {
    const vec = vectors[i]!;

    try {
      // Helper function to pad hex and convert to bytes (matches bytes32 from noble test)
      const privBytes = hexToUint8Array(vec.priv.padStart(64, '0'));

      // Get public key from native implementation
      const nativePublicKey = getPublicKeyEd25519(privBytes);
      const nativeHex = uint8ArrayToHex(nativePublicKey, false);

      if (nativeHex !== vec.pub) {
        failureCount++;
        if (failureCount <= maxFailuresToReport) {
          results.push({
            name: `1024 Vector ${i + 1} - Mismatch`,
            success: false,
            message: `Expected: ${vec.pub}\nGot: ${nativeHex}`,
          });
        }
      }
    } catch (error) {
      failureCount++;
      if (failureCount <= maxFailuresToReport) {
        results.push({
          name: `1024 Vector ${i + 1} - Error`,
          success: false,
          message: `Error: ${error}`,
        });
      }
    }
  }

  // Report summary
  const totalVectors = vectors.length;

  if (failureCount === 0) {
    results.push({
      name: `1024 Vectors from ed25519.cr.yp.to`,
      success: true,
      message: `✓ All ${totalVectors} vectors passed`,
    });
  } else {
    results.push({
      name: `1024 Vectors Summary`,
      success: false,
      message: `Failed ${failureCount}/${totalVectors} vectors (showing first ${Math.min(failureCount, maxFailuresToReport)})`,
    });
  }

  return results;
};

// Test edge cases from noble/curves ed25519.test.ts
export const testEd25519NobleEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test that all-zero private key still works (Ed25519 accepts it, unlike secp256k1)
  // Actually, let's check what noble does
  try {
    const allZero = new Uint8Array(32); // All zeros
    const nativeResult = getPublicKeyEd25519(allZero);
    const nobleResult = ed25519.getPublicKey(allZero);

    const nativeHex = uint8ArrayToHex(nativeResult, false);
    const nobleHex = uint8ArrayToHex(nobleResult, false);
    const matches = nativeHex === nobleHex;

    results.push({
      name: 'Ed25519 all-zero private key',
      success: matches,
      message: matches
        ? '✓ All-zero key handled consistently with noble'
        : `Native: ${nativeHex}\nNoble: ${nobleHex}`,
    });
  } catch (error) {
    // Check if noble also threw
    let nobleThrew = false;
    try {
      ed25519.getPublicKey(new Uint8Array(32));
    } catch (e) {
      nobleThrew = true;
    }

    results.push({
      name: 'Ed25519 all-zero private key',
      success: nobleThrew,
      message: nobleThrew
        ? '✓ Both implementations reject all-zero key'
        : `Native threw but noble accepted: ${error}`,
    });
  }

  // Test all-ones private key
  try {
    const allOnes = new Uint8Array(32).fill(0xff);
    const nativeResult = getPublicKeyEd25519(allOnes);
    const nobleResult = ed25519.getPublicKey(allOnes);

    const nativeHex = uint8ArrayToHex(nativeResult, false);
    const nobleHex = uint8ArrayToHex(nobleResult, false);
    const matches = nativeHex === nobleHex;

    results.push({
      name: 'Ed25519 all-ones private key',
      success: matches,
      message: matches
        ? '✓ All-ones key matches noble'
        : `Native: ${nativeHex}\nNoble: ${nobleHex}`,
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 all-ones private key',
      success: false,
      message: `Error: ${error}`,
    });
  }

  // Test hex string case sensitivity
  const testKey =
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  try {
    const lowercase = getPublicKeyEd25519(testKey.toLowerCase());
    const uppercase = getPublicKeyEd25519(testKey.toUpperCase());

    const lowercaseHex = uint8ArrayToHex(lowercase, false);
    const uppercaseHex = uint8ArrayToHex(uppercase, false);
    const matches = lowercaseHex === uppercaseHex;

    results.push({
      name: 'Ed25519 hex string case insensitivity',
      success: matches,
      message: matches
        ? '✓ Lowercase and uppercase hex produce same result'
        : `Lowercase: ${lowercaseHex}\nUppercase: ${uppercaseHex}`,
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 hex string case insensitivity',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
};

// Test argument validation
export const testEd25519NobleArgumentValidation = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test missing arguments
  try {
    // @ts-expect-error - testing missing argument
    getPublicKeyEd25519();
    results.push({
      name: 'Ed25519 missing arguments (should throw)',
      success: false,
      message: "Expected to throw for missing arguments, but it didn't",
    });
  } catch (error) {
    results.push({
      name: 'Ed25519 missing arguments (should throw)',
      success: true,
      message: '✓ Correctly throws error for missing arguments',
    });
  }

  // Test wrong length Uint8Array
  const wrongLengthArrays = [
    { arr: new Uint8Array(31), desc: '31 bytes (too short)' },
    { arr: new Uint8Array(33), desc: '33 bytes (too long)' },
    { arr: new Uint8Array(64), desc: '64 bytes (too long)' },
  ];

  for (const { arr, desc } of wrongLengthArrays) {
    try {
      getPublicKeyEd25519(arr);
      results.push({
        name: `Ed25519 wrong length Uint8Array ${desc} (should throw)`,
        success: false,
        message: `Expected to throw for ${desc}, but it didn't`,
      });
    } catch (error) {
      results.push({
        name: `Ed25519 wrong length Uint8Array ${desc} (should throw)`,
        success: true,
        message: `✓ Correctly throws error for ${desc}`,
      });
    }
  }

  return results;
};

// Main function to run all noble extracted tests
export const runAllEd25519NobleExtractedTests = (): TestResult[] => {
  const results: TestResult[] = [];

  results.push(...testEd25519NobleTypeValidation());
  results.push(...testEd25519RFC8032Vectors());
  results.push(...testEd25519OldVectors());
  results.push(...testEd255191024Vectors());
  results.push(...testEd25519NobleEdgeCases());
  results.push(...testEd25519NobleArgumentValidation());

  return results;
};
