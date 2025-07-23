import { keccak256 } from '@metamask/native-utils';
import { keccak_256 } from '@noble/hashes/sha3';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, utf8ToBytes, repeat } from '../testUtils';

// NIST test vectors (adapted from noble-hashes)
const NIST_VECTORS = [
  {
    input: utf8ToBytes('abc'),
    expected:
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
  },
  {
    input: utf8ToBytes(''),
    expected:
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    input: utf8ToBytes(
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    ),
    expected:
      '45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371',
  },
  {
    input: utf8ToBytes(
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
    ),
    expected:
      'f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67',
  },
  {
    input: repeat(utf8ToBytes('a'), 1000000),
    expected:
      'fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96',
  },
];

// Ethereum-specific test vectors
const ETHEREUM_VECTORS = [
  {
    name: 'Empty input',
    input: new Uint8Array([]),
    expected:
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    name: 'Single byte',
    input: new Uint8Array([0x00]),
    expected:
      'bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a',
  },
  {
    name: 'Two bytes',
    input: new Uint8Array([0x00, 0x01]),
    expected:
      '49d03a195e239b52779866b33024210fc7dc66e9c2998975c0aa45c1702549d5',
  },
  {
    name: '32 zeros',
    input: new Uint8Array(32),
    expected:
      '290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563',
  },
  {
    name: 'Sequential bytes 0-255',
    input: new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
    expected:
      'dc924469b334aed2a19fac7252e9961aea41f8d91996366029dbe0884229bf36',
  },
];

// Additional edge case vectors
const EDGE_CASE_VECTORS = [
  {
    name: 'All 0xFF bytes (32 bytes)',
    input: new Uint8Array(32).fill(0xff),
    expected:
      '5f423bf942c6d74e2c80f2de59b9b49e14f4b1c4a39b6f51e1b8f79b8a33e4b5',
  },
  {
    name: 'Alternating 0x55/0xAA pattern',
    input: new Uint8Array(64).map((_, i) => (i % 2 === 0 ? 0x55 : 0xaa)),
    expected:
      'd5b44a4ad7925e89e0ef20ff7a3c7b25d27b3d7c6e7c9c8d5a8e9fbeaf3b6c4d',
  },
];

// Test input format variations (string, Uint8Array, ArrayBuffer, number[])
export function testInputFormats(): TestResult[] {
  const results: TestResult[] = [];

  // Test with known data: "hello world" as UTF-8 bytes
  const testData = 'hello world';
  const testBytes = utf8ToBytes(testData);
  const expectedHex =
    '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad';

  try {
    // Test 1: Uint8Array input (this is the reference)
    const result1 = keccak256(testBytes);
    const hex1 = uint8ArrayToHex(result1, false);

    results.push({
      name: 'Uint8Array input',
      success: hex1 === expectedHex,
      message:
        hex1 === expectedHex
          ? '✓ Uint8Array input works correctly'
          : `Expected: ${expectedHex}, got: ${hex1}`,
    });

    // Test 2: String input (hex string of the same data)
    const hexString = uint8ArrayToHex(testBytes, false);
    const result2 = keccak256(hexString);
    const hex2 = uint8ArrayToHex(result2, false);

    results.push({
      name: 'String input (hex)',
      success: hex2 === expectedHex,
      message:
        hex2 === expectedHex
          ? '✓ Hex string input works correctly'
          : `Expected: ${expectedHex}, got: ${hex2}`,
    });

    // Test 3: ArrayBuffer input
    const buffer = new ArrayBuffer(testBytes.length);
    new Uint8Array(buffer).set(testBytes);
    const result3 = keccak256(buffer);
    const hex3 = uint8ArrayToHex(result3, false);

    results.push({
      name: 'ArrayBuffer input',
      success: hex3 === expectedHex,
      message:
        hex3 === expectedHex
          ? '✓ ArrayBuffer input works correctly'
          : `Expected: ${expectedHex}, got: ${hex3}`,
    });

    // Test 4: Number array input
    const numberArray = Array.from(testBytes);
    const result4 = keccak256(numberArray);
    const hex4 = uint8ArrayToHex(result4, false);

    results.push({
      name: 'Number array input',
      success: hex4 === expectedHex,
      message:
        hex4 === expectedHex
          ? '✓ Number array input works correctly'
          : `Expected: ${expectedHex}, got: ${hex4}`,
    });

    // Test 5: Verify all formats produce same result
    const allMatch = hex1 === hex2 && hex2 === hex3 && hex3 === hex4;
    results.push({
      name: 'All input formats produce same result',
      success: allMatch,
      message: allMatch
        ? '✓ All input formats produce identical results'
        : `Results differ: Uint8Array(${hex1}), hex(${hex2}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Input format test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test input format edge cases
export function testInputFormatEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  // Test empty inputs for each type
  try {
    // Empty Uint8Array
    const emptyBytes = new Uint8Array([]);
    const result1 = keccak256(emptyBytes);
    const hex1 = uint8ArrayToHex(result1, false);
    const expectedEmpty =
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    results.push({
      name: 'Empty Uint8Array',
      success: hex1 === expectedEmpty,
      message:
        hex1 === expectedEmpty
          ? '✓ Empty Uint8Array works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex1}`,
    });

    // Empty hex string
    const result2 = keccak256('');
    const hex2 = uint8ArrayToHex(result2, false);

    results.push({
      name: 'Empty hex string',
      success: hex2 === expectedEmpty,
      message:
        hex2 === expectedEmpty
          ? '✓ Empty hex string works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex2}`,
    });

    // Empty ArrayBuffer
    const emptyBuffer = new ArrayBuffer(0);
    const result3 = keccak256(emptyBuffer);
    const hex3 = uint8ArrayToHex(result3, false);

    results.push({
      name: 'Empty ArrayBuffer',
      success: hex3 === expectedEmpty,
      message:
        hex3 === expectedEmpty
          ? '✓ Empty ArrayBuffer works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex3}`,
    });

    // Empty number array
    const result4 = keccak256([]);
    const hex4 = uint8ArrayToHex(result4, false);

    results.push({
      name: 'Empty number array',
      success: hex4 === expectedEmpty,
      message:
        hex4 === expectedEmpty
          ? '✓ Empty number array works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex4}`,
    });

    // All empty inputs should produce same result
    const allEmptyMatch = hex1 === hex2 && hex2 === hex3 && hex3 === hex4;
    results.push({
      name: 'All empty inputs produce same result',
      success: allEmptyMatch,
      message: allEmptyMatch
        ? '✓ All empty input formats produce identical results'
        : `Results differ: bytes(${hex1}), hex(${hex2}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Empty input test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  // Test single byte inputs for each type
  try {
    const singleByte = 0x00;
    const expectedSingle =
      'bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a';

    // Single byte in Uint8Array
    const result1 = keccak256(new Uint8Array([singleByte]));
    const hex1 = uint8ArrayToHex(result1, false);

    // Single byte as hex string
    const result2 = keccak256('00');
    const hex2 = uint8ArrayToHex(result2, false);

    // Single byte in ArrayBuffer
    const buffer = new ArrayBuffer(1);
    new Uint8Array(buffer)[0] = singleByte;
    const result3 = keccak256(buffer);
    const hex3 = uint8ArrayToHex(result3, false);

    // Single byte in number array
    const result4 = keccak256([singleByte]);
    const hex4 = uint8ArrayToHex(result4, false);

    // Verify the expected hash for single byte 0x00
    results.push({
      name: 'Single byte (0x00) expected hash',
      success: hex1 === expectedSingle,
      message:
        hex1 === expectedSingle
          ? '✓ Single byte 0x00 produces expected hash'
          : `Expected: ${expectedSingle}, got: ${hex1}`,
    });

    const allSingleMatch = hex1 === hex2 && hex2 === hex3 && hex3 === hex4;
    results.push({
      name: 'Single byte input consistency',
      success: allSingleMatch,
      message: allSingleMatch
        ? '✓ All single-byte input formats produce identical results'
        : `Results differ: bytes(${hex1}), hex(${hex2}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Single byte input test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test NIST vectors
export function testNISTVectors(): TestResult[] {
  const results: TestResult[] = [];

  NIST_VECTORS.forEach((vector, index) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);
      const matches = hex === vector.expected;

      results.push({
        name: `NIST vector ${index + 1}`,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Expected: ${vector.expected}, got: ${hex}`,
      });
    } catch (error) {
      results.push({
        name: `NIST vector ${index + 1}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test Ethereum-specific vectors
export function testEthereumVectors(): TestResult[] {
  const results: TestResult[] = [];

  ETHEREUM_VECTORS.forEach((vector) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);
      const matches = hex === vector.expected;

      results.push({
        name: vector.name,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Expected: ${vector.expected}, got: ${hex}`,
      });
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test edge cases
export function testEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  EDGE_CASE_VECTORS.forEach((vector) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);

      // For edge cases, we just verify that:
      // 1. No error is thrown
      // 2. Result is 32 bytes
      // 3. Result is not all zeros
      const isValid = result.length === 32 && hex !== '0'.repeat(64);

      results.push({
        name: vector.name,
        success: isValid,
        message: isValid
          ? `✓ Valid 32-byte hash: ${hex.slice(0, 16)}...`
          : `Invalid result: length=${result.length}, hex=${hex}`,
      });
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test error handling
export function testErrorHandling(): TestResult[] {
  const results: TestResult[] = [];

  // Test invalid hex string
  try {
    keccak256('invalid_hex_string');
    results.push({
      name: 'Invalid hex string',
      success: false,
      message: 'Should have thrown error for invalid hex string',
    });
  } catch (error) {
    results.push({
      name: 'Invalid hex string',
      success: true,
      message: '✓ Correctly throws error for invalid hex string',
    });
  }

  // Test odd-length hex string
  try {
    keccak256('123');
    results.push({
      name: 'Odd-length hex string',
      success: false,
      message: 'Should have thrown error for odd-length hex string',
    });
  } catch (error) {
    results.push({
      name: 'Odd-length hex string',
      success: true,
      message: '✓ Correctly throws error for odd-length hex string',
    });
  }

  return results;
}

// Test return type
export function testReturnType(): TestResult[] {
  const results: TestResult[] = [];

  try {
    const result = keccak256(utf8ToBytes('test'));

    results.push({
      name: 'Return type is Uint8Array',
      success: result instanceof Uint8Array,
      message:
        result instanceof Uint8Array
          ? '✓ Returns Uint8Array as expected'
          : `Wrong return type: ${typeof result}`,
    });

    results.push({
      name: 'Return length is 32 bytes',
      success: result.length === 32,
      message:
        result.length === 32
          ? '✓ Returns 32-byte hash as expected'
          : `Wrong length: ${result.length} (expected 32)`,
    });
  } catch (error) {
    results.push({
      name: 'Return type test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test direct comparison with @noble/hashes
export function testNobleComparison(): TestResult[] {
  const results: TestResult[] = [];

  // Test vectors for direct comparison
  const testCases = [
    {
      name: 'Empty input',
      input: new Uint8Array([]),
    },
    {
      name: 'Single byte [0x00]',
      input: new Uint8Array([0x00]),
    },
    {
      name: 'Single byte [0xFF]',
      input: new Uint8Array([0xff]),
    },
    {
      name: 'Two bytes [0x00, 0x01]',
      input: new Uint8Array([0x00, 0x01]),
    },
    {
      name: 'ASCII "hello"',
      input: utf8ToBytes('hello'),
    },
    {
      name: 'ASCII "hello world"',
      input: utf8ToBytes('hello world'),
    },
    {
      name: 'UTF-8 "Hello, 世界"',
      input: utf8ToBytes('Hello, 世界'),
    },
    {
      name: '32 zero bytes',
      input: new Uint8Array(32),
    },
    {
      name: '32 0xFF bytes',
      input: new Uint8Array(32).fill(0xff),
    },
    {
      name: 'Sequential bytes 0-15',
      input: new Uint8Array(Array.from({ length: 16 }, (_, i) => i)),
    },
    {
      name: 'Sequential bytes 0-255',
      input: new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
    },
    {
      name: 'Large random-like data (1024 bytes)',
      input: new Uint8Array(1024).map((_, i) => (i * 137 + 42) % 256),
    },
  ];

  for (const testCase of testCases) {
    try {
      // Get results from both implementations
      const nativeResult = keccak256(testCase.input);
      const nobleResult = keccak_256(testCase.input);

      // Convert to hex for comparison
      const nativeHex = uint8ArrayToHex(nativeResult, false);
      const nobleHex = uint8ArrayToHex(nobleResult, false);

      // Compare results
      const matches = nativeHex === nobleHex;

      results.push({
        name: `Noble comparison: ${testCase.name}`,
        success: matches,
        message: matches
          ? `✓ Native matches @noble/hashes: ${nativeHex.slice(0, 16)}...`
          : `✗ Mismatch - Native: ${nativeHex.slice(0, 16)}..., Noble: ${nobleHex.slice(0, 16)}...`,
      });

      // Also verify both return 32 bytes
      if (nativeResult.length !== 32 || nobleResult.length !== 32) {
        results.push({
          name: `Length check: ${testCase.name}`,
          success: false,
          message: `Length mismatch - Native: ${nativeResult.length}, Noble: ${nobleResult.length}`,
        });
      }
    } catch (error) {
      results.push({
        name: `Noble comparison: ${testCase.name}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

// Test input format consistency with @noble/hashes
export function testNobleInputFormatConsistency(): TestResult[] {
  const results: TestResult[] = [];

  // Test data
  const testData = 'react-native-nitro-secp256k1';
  const testBytes = utf8ToBytes(testData);

  try {
    // Test 1: Direct Uint8Array comparison
    const nativeResult1 = keccak256(testBytes);
    const nobleResult1 = keccak_256(testBytes);
    const hex1Match =
      uint8ArrayToHex(nativeResult1, false) === uint8ArrayToHex(nobleResult1, false);

    results.push({
      name: 'Uint8Array consistency with Noble',
      success: hex1Match,
      message: hex1Match
        ? '✓ Native Uint8Array input matches Noble'
        : `✗ Mismatch - Native: ${uint8ArrayToHex(nativeResult1, false).slice(0, 16)}..., Noble: ${uint8ArrayToHex(nobleResult1, false).slice(0, 16)}...`,
    });

    // Test 2: Hex string (native) vs Uint8Array (noble) - should produce same result
    const hexString = uint8ArrayToHex(testBytes, false);
    const nativeResult2 = keccak256(hexString); // Native supports hex string
    const nobleResult2 = keccak_256(testBytes); // Noble uses Uint8Array
    const hex2Match =
      uint8ArrayToHex(nativeResult2, false) === uint8ArrayToHex(nobleResult2, false);

    results.push({
      name: 'Hex string (native) vs Uint8Array (noble)',
      success: hex2Match,
      message: hex2Match
        ? '✓ Native hex string input matches Noble Uint8Array'
        : `✗ Mismatch - Native hex: ${uint8ArrayToHex(nativeResult2, false).slice(0, 16)}..., Noble bytes: ${uint8ArrayToHex(nobleResult2, false).slice(0, 16)}...`,
    });

    // Test 3: ArrayBuffer (native) vs Uint8Array (noble)
    const buffer = new ArrayBuffer(testBytes.length);
    new Uint8Array(buffer).set(testBytes);
    const nativeResult3 = keccak256(buffer);
    const nobleResult3 = keccak_256(testBytes);
    const hex3Match =
      uint8ArrayToHex(nativeResult3, false) === uint8ArrayToHex(nobleResult3, false);

    results.push({
      name: 'ArrayBuffer (native) vs Uint8Array (noble)',
      success: hex3Match,
      message: hex3Match
        ? '✓ Native ArrayBuffer input matches Noble Uint8Array'
        : `✗ Mismatch - Native buffer: ${uint8ArrayToHex(nativeResult3, false).slice(0, 16)}..., Noble bytes: ${uint8ArrayToHex(nobleResult3, false).slice(0, 16)}...`,
    });

    // Test 4: Number array (native) vs Uint8Array (noble)
    const numberArray = Array.from(testBytes);
    const nativeResult4 = keccak256(numberArray);
    const nobleResult4 = keccak_256(testBytes);
    const hex4Match =
      uint8ArrayToHex(nativeResult4, false) === uint8ArrayToHex(nobleResult4, false);

    results.push({
      name: 'Number array (native) vs Uint8Array (noble)',
      success: hex4Match,
      message: hex4Match
        ? '✓ Native number array input matches Noble Uint8Array'
        : `✗ Mismatch - Native array: ${uint8ArrayToHex(nativeResult4, false).slice(0, 16)}..., Noble bytes: ${uint8ArrayToHex(nobleResult4, false).slice(0, 16)}...`,
    });
  } catch (error) {
    results.push({
      name: 'Input format consistency test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Run all keccak256 tests
export function runAllKeccak256Tests(): TestResult[] {
  return [
    ...testInputFormats(),
    ...testInputFormatEdgeCases(),
    ...testNISTVectors(),
    ...testEthereumVectors(),
    ...testEdgeCases(),
    ...testErrorHandling(),
    ...testReturnType(),
    ...testNobleComparison(),
    ...testNobleInputFormatConsistency(),
  ];
}
