import { hmacSha512 } from '@metamask/native-utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import type { TestResult } from '../testUtils';

/**
 * Test basic HMAC-SHA512 functionality against @noble/hashes
 */
export function testHmacSha512Basic(): TestResult[] {
  const results: TestResult[] = [];

  try {
    // Test case 1: Simple key and data
    const key1 = new Uint8Array(32);
    key1.fill(0x01);
    const data1 = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

    const nativeResult1 = hmacSha512(key1, data1);
    const nobleResult1 = hmac(sha512, key1, data1);

    if (
      nativeResult1.length === nobleResult1.length &&
      nativeResult1.every((val, i) => val === nobleResult1[i])
    ) {
      results.push({
        name: 'Basic HMAC-SHA512 (simple key/data)',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult1.length} bytes`,
      });
    } else {
      results.push({
        name: 'Basic HMAC-SHA512 (simple key/data)',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult1.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult1.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // Test case 2: Empty key and data
    const emptyKey = new Uint8Array(0);
    const emptyData = new Uint8Array(0);

    const nativeResult2 = hmacSha512(emptyKey, emptyData);
    const nobleResult2 = hmac(sha512, emptyKey, emptyData);

    if (
      nativeResult2.length === nobleResult2.length &&
      nativeResult2.every((val, i) => val === nobleResult2[i])
    ) {
      results.push({
        name: 'HMAC-SHA512 with empty key/data',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult2.length} bytes`,
      });
    } else {
      results.push({
        name: 'HMAC-SHA512 with empty key/data',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult2.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult2.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // Test case 3: Different key sizes
    const shortKey = new Uint8Array(16);
    shortKey.fill(0x42);
    const longKey = new Uint8Array(128);
    longKey.fill(0x43);
    const testData = new Uint8Array(100);
    testData.fill(0x44);

    const nativeResult3 = hmacSha512(shortKey, testData);
    const nobleResult3 = hmac(sha512, shortKey, testData);

    if (
      nativeResult3.length === nobleResult3.length &&
      nativeResult3.every((val, i) => val === nobleResult3[i])
    ) {
      results.push({
        name: 'HMAC-SHA512 with short key',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult3.length} bytes`,
      });
    } else {
      results.push({
        name: 'HMAC-SHA512 with short key',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult3.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult3.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    const nativeResult4 = hmacSha512(longKey, testData);
    const nobleResult4 = hmac(sha512, longKey, testData);

    if (
      nativeResult4.length === nobleResult4.length &&
      nativeResult4.every((val, i) => val === nobleResult4[i])
    ) {
      results.push({
        name: 'HMAC-SHA512 with long key',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult4.length} bytes`,
      });
    } else {
      results.push({
        name: 'HMAC-SHA512 with long key',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult4.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult4.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }
  } catch (error) {
    results.push({
      name: 'Basic HMAC-SHA512 test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

/**
 * Test HMAC-SHA512 with RFC 4231 test vectors
 */
export function testHmacSha512RFC4231(): TestResult[] {
  const results: TestResult[] = [];

  try {
    // RFC 4231 Test Case 1
    const key1 = new Uint8Array([
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ]);
    const data1 = new Uint8Array([
      0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65,
    ]); // "Hi There"

    const nativeResult1 = hmacSha512(key1, data1);
    const nobleResult1 = hmac(sha512, key1, data1);

    if (
      nativeResult1.length === nobleResult1.length &&
      nativeResult1.every((val, i) => val === nobleResult1[i])
    ) {
      results.push({
        name: 'RFC 4231 Test Case 1',
        success: true,
        message: `Native and Noble results match. First 8 bytes: ${Array.from(
          nativeResult1.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}`,
      });
    } else {
      results.push({
        name: 'RFC 4231 Test Case 1',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult1.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult1.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // RFC 4231 Test Case 2
    const key2 = new Uint8Array([0x4a, 0x65, 0x66, 0x65]); // "Jefe"
    const data2 = new Uint8Array([
      0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
      0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
      0x69, 0x6e, 0x67, 0x3f,
    ]); // "what do ya want for nothing?"

    const nativeResult2 = hmacSha512(key2, data2);
    const nobleResult2 = hmac(sha512, key2, data2);

    if (
      nativeResult2.length === nobleResult2.length &&
      nativeResult2.every((val, i) => val === nobleResult2[i])
    ) {
      results.push({
        name: 'RFC 4231 Test Case 2',
        success: true,
        message: `Native and Noble results match. First 8 bytes: ${Array.from(
          nativeResult2.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}`,
      });
    } else {
      results.push({
        name: 'RFC 4231 Test Case 2',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult2.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult2.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // RFC 4231 Test Case 3
    const key3 = new Uint8Array(20);
    key3.fill(0xaa);
    const data3 = new Uint8Array(50);
    data3.fill(0xdd);

    const nativeResult3 = hmacSha512(key3, data3);
    const nobleResult3 = hmac(sha512, key3, data3);

    if (
      nativeResult3.length === nobleResult3.length &&
      nativeResult3.every((val, i) => val === nobleResult3[i])
    ) {
      results.push({
        name: 'RFC 4231 Test Case 3',
        success: true,
        message: `Native and Noble results match. First 8 bytes: ${Array.from(
          nativeResult3.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}`,
      });
    } else {
      results.push({
        name: 'RFC 4231 Test Case 3',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult3.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult3.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }
  } catch (error) {
    results.push({
      name: 'RFC 4231 test vectors',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

/**
 * Test HMAC-SHA512 with BIP32-specific scenarios
 */
export function testHmacSha512BIP32(): TestResult[] {
  const results: TestResult[] = [];

  try {
    // BIP32 normal derivation scenario
    const chainCode = new Uint8Array(32);
    chainCode.fill(0xaa);

    const publicKey = new Uint8Array(33);
    publicKey[0] = 0x02;
    publicKey.fill(0x03, 1);

    const index = new Uint8Array(4);
    index[3] = 0x01; // index 1

    const bip32Data = new Uint8Array(37);
    bip32Data.set(publicKey, 0);
    bip32Data.set(index, 33);

    const nativeResult1 = hmacSha512(chainCode, bip32Data);
    const nobleResult1 = hmac(sha512, chainCode, bip32Data);

    if (
      nativeResult1.length === nobleResult1.length &&
      nativeResult1.every((val, i) => val === nobleResult1[i])
    ) {
      results.push({
        name: 'BIP32 normal derivation',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult1.length} bytes`,
      });
    } else {
      results.push({
        name: 'BIP32 normal derivation',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult1.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult1.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // BIP32 hardened derivation scenario
    const privateKey = new Uint8Array(32);
    privateKey.fill(0x33);

    const hardenedIndex = new Uint8Array(4);
    hardenedIndex[0] = 0x80; // hardened index

    const hardenedData = new Uint8Array(37);
    hardenedData[0] = 0x00;
    hardenedData.set(privateKey, 1);
    hardenedData.set(hardenedIndex, 33);

    const nativeResult2 = hmacSha512(chainCode, hardenedData);
    const nobleResult2 = hmac(sha512, chainCode, hardenedData);

    if (
      nativeResult2.length === nobleResult2.length &&
      nativeResult2.every((val, i) => val === nobleResult2[i])
    ) {
      results.push({
        name: 'BIP32 hardened derivation',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult2.length} bytes`,
      });
    } else {
      results.push({
        name: 'BIP32 hardened derivation',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult2.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult2.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // BIP32 master seed scenario
    const masterSeed = new Uint8Array(64);
    masterSeed.fill(0x55);

    const bitcoinSeed = new Uint8Array([
      0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
    ]); // "Bitcoin seed"

    const nativeResult3 = hmacSha512(bitcoinSeed, masterSeed);
    const nobleResult3 = hmac(sha512, bitcoinSeed, masterSeed);

    if (
      nativeResult3.length === nobleResult3.length &&
      nativeResult3.every((val, i) => val === nobleResult3[i])
    ) {
      results.push({
        name: 'BIP32 master seed generation',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult3.length} bytes`,
      });
    } else {
      results.push({
        name: 'BIP32 master seed generation',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult3.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult3.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }
  } catch (error) {
    results.push({
      name: 'BIP32 HMAC-SHA512 test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

/**
 * Test HMAC-SHA512 edge cases
 */
export function testHmacSha512EdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  try {
    // Very large key (larger than SHA512 block size)
    const largeKey = new Uint8Array(200);
    largeKey.fill(0x99);
    const smallData = new Uint8Array([0x01, 0x02, 0x03]);

    const nativeResult1 = hmacSha512(largeKey, smallData);
    const nobleResult1 = hmac(sha512, largeKey, smallData);

    if (
      nativeResult1.length === nobleResult1.length &&
      nativeResult1.every((val, i) => val === nobleResult1[i])
    ) {
      results.push({
        name: 'Large key (>128 bytes)',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult1.length} bytes`,
      });
    } else {
      results.push({
        name: 'Large key (>128 bytes)',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult1.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult1.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // Very large data
    const smallKey = new Uint8Array([0x01, 0x02, 0x03]);
    const largeData = new Uint8Array(10000);
    largeData.fill(0x77);

    const nativeResult2 = hmacSha512(smallKey, largeData);
    const nobleResult2 = hmac(sha512, smallKey, largeData);

    if (
      nativeResult2.length === nobleResult2.length &&
      nativeResult2.every((val, i) => val === nobleResult2[i])
    ) {
      results.push({
        name: 'Large data (10KB)',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult2.length} bytes`,
      });
    } else {
      results.push({
        name: 'Large data (10KB)',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult2.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult2.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }

    // Single byte key and data
    const singleByteKey = new Uint8Array([0x42]);
    const singleByteData = new Uint8Array([0x24]);

    const nativeResult3 = hmacSha512(singleByteKey, singleByteData);
    const nobleResult3 = hmac(sha512, singleByteKey, singleByteData);

    if (
      nativeResult3.length === nobleResult3.length &&
      nativeResult3.every((val, i) => val === nobleResult3[i])
    ) {
      results.push({
        name: 'Single byte key and data',
        success: true,
        message: `Native and Noble results match. Length: ${nativeResult3.length} bytes`,
      });
    } else {
      results.push({
        name: 'Single byte key and data',
        success: false,
        message: `Results don't match. Native: ${Array.from(
          nativeResult3.slice(0, 8),
        )
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}..., Noble: ${Array.from(nobleResult3.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')}...`,
      });
    }
  } catch (error) {
    results.push({
      name: 'HMAC-SHA512 edge cases',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

/**
 * Run all HMAC-SHA512 tests
 */
export function runAllHmacSha512Tests(): TestResult[] {
  const results: TestResult[] = [];

  results.push(...testHmacSha512Basic());
  results.push(...testHmacSha512RFC4231());
  results.push(...testHmacSha512BIP32());
  results.push(...testHmacSha512EdgeCases());

  return results;
}
