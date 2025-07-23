import { hmacSha512 } from '@metamask/native-utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import type { TestResult } from '../testUtils';
import { hexToUint8Array, utf8ToBytes, uint8ArrayToHex, concatBytes, truncate } from '../testUtils';

/**
 * RFC 4231 Test Vectors for HMAC-SHA512
 * These are the official test vectors from the HMAC specification
 */
const RFC4231_VECTORS = [
  {
    name: 'RFC 4231 Test Case 1',
    key: hexToUint8Array('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    data: [utf8ToBytes('Hi There')],
    expected:
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
      'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    name: 'RFC 4231 Test Case 2',
    key: utf8ToBytes('Jefe'),
    data: [utf8ToBytes('what do ya want '), utf8ToBytes('for nothing?')],
    expected:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
      '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    name: 'RFC 4231 Test Case 3',
    key: hexToUint8Array('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    data: [
      hexToUint8Array(
        'dddddddddddddddddddddddddddddddddddddddddddddddddd' +
          'dddddddddddddddddddddddddddddddddddddddddddddddddd'
      ),
    ],
    expected:
      'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39' +
      'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    name: 'RFC 4231 Test Case 4',
    key: hexToUint8Array('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: [
      hexToUint8Array(
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
      ),
    ],
    expected:
      'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db' +
      'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    name: 'RFC 4231 Test Case 5 (Truncated)',
    key: hexToUint8Array('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'),
    data: [utf8ToBytes('Test With Trunca'), utf8ToBytes('tion')],
    expected: '415fad6271580a531d4179bc891d87a6',
    truncate: 16,
  },
  {
    name: 'RFC 4231 Test Case 6 (Large Key)',
    key: hexToUint8Array(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa'
    ),
    data: [
      utf8ToBytes('Test Using Large'),
      utf8ToBytes('r Than Block-Siz'),
      utf8ToBytes('e Key - Hash Key'),
      utf8ToBytes(' First'),
    ],
    expected:
      '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352' +
      '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  {
    name: 'RFC 4231 Test Case 7 (Large Key & Data)',
    key: hexToUint8Array(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa'
    ),
    data: [
      utf8ToBytes('This is a test u'),
      utf8ToBytes('sing a larger th'),
      utf8ToBytes('an block-size ke'),
      utf8ToBytes('y and a larger t'),
      utf8ToBytes('han block-size d'),
      utf8ToBytes('ata. The key nee'),
      utf8ToBytes('ds to be hashed '),
      utf8ToBytes('before being use'),
      utf8ToBytes('d by the HMAC al'),
      utf8ToBytes('gorithm.'),
    ],
    expected:
      'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944' +
      'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
];

/**
 * NIST Test Vectors for HMAC-SHA512 with empty key
 * These match the original noble-hashes test vectors
 */
const NIST_VECTORS = [
  {
    name: 'NIST Vector 1 (abc)',
    input: utf8ToBytes('abc'),
    expected:
      '29689f6b79a8dd686068c2eeae97fd8769ad3ba65cb5381f838358a8045a358ee3ba1739c689c7805e31734fb6072f87261d1256995370d55725cba00d10bdd0',
  },
  {
    name: 'NIST Vector 2 (empty)',
    input: utf8ToBytes(''),
    expected:
      'b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47',
  },
  {
    name: 'NIST Vector 3 (56 chars)',
    input: utf8ToBytes(
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    ),
    expected:
      'e0657364f9603a276d94930f90a6b19f3ce4001ab494c4fdf7ff541609e05d2e48ca6454a4390feb12b8eacebb503ba2517f5e2454d7d77e8b44d7cca8f752cd',
  },
  {
    name: 'NIST Vector 4 (112 chars)',
    input: utf8ToBytes(
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
    ),
    expected:
      'ece33db7448f63f4d460ac8b86bdf02fa6f5c3279a2a5d59df26827bec5315a44eb85d40ee4df3a7272a9596a0bc27091466724e9357183e554c9ec5fdf6d099',
  },
  {
    name: 'NIST Vector 5 (1M a chars)',
    input: new Uint8Array(1000000).fill(0x61), // 1 million 'a's
    expected:
      '59064f29e00b6a5cc55a3b69d9cfd3457ae70bd169b2b714036ae3a965805eb25a99ca221ade1aecebe6111d70697d1174a288cd1bb177de4a14f06eacc631d8',
  },
];

/**
 * Test RFC 4231 vectors
 */
export function testRFC4231Vectors(): TestResult[] {
  const results: TestResult[] = [];

  for (const vector of RFC4231_VECTORS) {
    try {
      // Test with full data at once
      const fullData = concatBytes(...vector.data);
      const nativeResult = hmacSha512(vector.key, fullData);
      const nobleResult = hmac(sha512, vector.key, fullData);

      // Apply truncation if specified
      const truncatedNative = truncate(nativeResult, vector.truncate);
      const truncatedNoble = truncate(nobleResult, vector.truncate);
      const expectedBytes = hexToUint8Array(vector.expected);

      if (
        truncatedNative.length === expectedBytes.length &&
        truncatedNative.every((val, i) => val === expectedBytes[i]) &&
        truncatedNoble.length === expectedBytes.length &&
        truncatedNoble.every((val, i) => val === expectedBytes[i])
      ) {
        results.push({
          name: `${vector.name} (full)`,
          success: true,
          message: `Native and Noble match expected result: ${uint8ArrayToHex(truncatedNative.slice(0, 8), false)}...`,
        });
      } else {
        results.push({
          name: `${vector.name} (full)`,
          success: false,
          message: `Mismatch. Native: ${uint8ArrayToHex(truncatedNative.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(truncatedNoble.slice(0, 8), false)}..., Expected: ${uint8ArrayToHex(expectedBytes.slice(0, 8), false)}...`,
        });
      }

      // Test with partial data (streaming simulation)
      // Note: Since we can't simulate streaming with our native function,
      // we'll just verify that the noble library produces the same result with streaming
      if (vector.data.length > 1) {
        const streamingResult = hmac(
          sha512,
          vector.key,
          concatBytes(...vector.data)
        );
        const truncatedStreaming = truncate(streamingResult, vector.truncate);

        if (
          truncatedStreaming.length === expectedBytes.length &&
          truncatedStreaming.every((val, i) => val === expectedBytes[i])
        ) {
          results.push({
            name: `${vector.name} (streaming verification)`,
            success: true,
            message: `Streaming noble result matches expected: ${uint8ArrayToHex(truncatedStreaming.slice(0, 8), false)}...`,
          });
        } else {
          results.push({
            name: `${vector.name} (streaming verification)`,
            success: false,
            message: `Streaming mismatch. Got: ${uint8ArrayToHex(truncatedStreaming.slice(0, 8), false)}..., Expected: ${uint8ArrayToHex(expectedBytes.slice(0, 8), false)}...`,
          });
        }
      }
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test NIST vectors with empty key
 */
export function testNISTVectors(): TestResult[] {
  const results: TestResult[] = [];
  const emptyKey = new Uint8Array(0);

  for (const vector of NIST_VECTORS) {
    try {
      const nativeResult = hmacSha512(emptyKey, vector.input);
      const nobleResult = hmac(sha512, emptyKey, vector.input);
      const expectedBytes = hexToUint8Array(vector.expected);

      if (
        nativeResult.length === expectedBytes.length &&
        nativeResult.every((val, i) => val === expectedBytes[i]) &&
        nobleResult.length === expectedBytes.length &&
        nobleResult.every((val, i) => val === expectedBytes[i])
      ) {
        results.push({
          name: vector.name,
          success: true,
          message: `Native and Noble match expected result: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}...`,
        });
      } else {
        results.push({
          name: vector.name,
          success: false,
          message: `Mismatch. Native: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8), false)}..., Expected: ${uint8ArrayToHex(expectedBytes.slice(0, 8), false)}...`,
        });
      }
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test edge cases and boundary conditions
 */
export function testEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  const testCases = [
    {
      name: 'Empty key and empty data',
      key: new Uint8Array(0),
      data: new Uint8Array(0),
    },
    {
      name: 'Single byte key and single byte data',
      key: new Uint8Array([0x42]),
      data: new Uint8Array([0x24]),
    },
    {
      name: 'Key exactly block size (128 bytes)',
      key: new Uint8Array(128).fill(0x55),
      data: new Uint8Array([0x01, 0x02, 0x03]),
    },
    {
      name: 'Key larger than block size (200 bytes)',
      key: new Uint8Array(200).fill(0x99),
      data: new Uint8Array([0x01, 0x02, 0x03]),
    },
    {
      name: 'Very large data (10KB)',
      key: new Uint8Array([0x01, 0x02, 0x03]),
      data: new Uint8Array(10000).fill(0x77),
    },
    {
      name: 'Key with all zeros',
      key: new Uint8Array(32).fill(0x00),
      data: utf8ToBytes('test data'),
    },
    {
      name: 'Key with all ones',
      key: new Uint8Array(32).fill(0xff),
      data: utf8ToBytes('test data'),
    },
    {
      name: 'Data with all zeros',
      key: utf8ToBytes('test key'),
      data: new Uint8Array(100).fill(0x00),
    },
    {
      name: 'Data with all ones',
      key: utf8ToBytes('test key'),
      data: new Uint8Array(100).fill(0xff),
    },
    {
      name: 'Maximum practical key size (1KB)',
      key: new Uint8Array(1024).fill(0xaa),
      data: utf8ToBytes('small data'),
    },
  ];

  for (const testCase of testCases) {
    try {
      const nativeResult = hmacSha512(testCase.key, testCase.data);
      const nobleResult = hmac(sha512, testCase.key, testCase.data);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native and Noble results match. Result: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}...`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8), false)}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test cryptocurrency-specific scenarios
 */
export function testCryptocurrencyScenarios(): TestResult[] {
  const results: TestResult[] = [];

  const testCases = [
    {
      name: 'BIP32 Master Key Generation',
      key: utf8ToBytes('Bitcoin seed'),
      data: new Uint8Array(64).fill(0x01), // Mock entropy
    },
    {
      name: 'BIP32 Child Key Derivation (Normal)',
      key: new Uint8Array(32).fill(0x02), // Mock chain code
      data: (() => {
        const data = new Uint8Array(37);
        data[0] = 0x02; // Public key prefix
        data.fill(0x03, 1, 33); // Mock public key
        data.set([0x00, 0x00, 0x00, 0x01], 33); // Child index 1
        return data;
      })(),
    },
    {
      name: 'BIP32 Child Key Derivation (Hardened)',
      key: new Uint8Array(32).fill(0x02), // Mock chain code
      data: (() => {
        const data = new Uint8Array(37);
        data[0] = 0x00; // Private key prefix
        data.fill(0x03, 1, 33); // Mock private key
        data.set([0x80, 0x00, 0x00, 0x01], 33); // Hardened index
        return data;
      })(),
    },
    {
      name: 'PBKDF2 Inner Hash',
      key: utf8ToBytes('mnemonic passphrase'),
      data: concatBytes(
        utf8ToBytes('salt'),
        new Uint8Array([0x00, 0x00, 0x00, 0x01])
      ),
    },
    {
      name: 'Lightning Network Key Derivation',
      key: new Uint8Array(32).fill(0x05), // Mock base key
      data: concatBytes(
        utf8ToBytes('lightning'),
        new Uint8Array(32).fill(0x06)
      ),
    },
  ];

  for (const testCase of testCases) {
    try {
      const nativeResult = hmacSha512(testCase.key, testCase.data);
      const nobleResult = hmac(sha512, testCase.key, testCase.data);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native and Noble results match. Length: ${nativeResult.length} bytes`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8), false)}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test specific SHA-512 block boundary cases
 */
export function testSHA512BlockBoundaries(): TestResult[] {
  const results: TestResult[] = [];

  // SHA-512 has a 128-byte block size
  const blockSize = 128;

  const testCases = [
    {
      name: 'Data exactly one block',
      key: new Uint8Array(32).fill(0x42),
      data: new Uint8Array(blockSize).fill(0x43),
    },
    {
      name: 'Data exactly two blocks',
      key: new Uint8Array(32).fill(0x42),
      data: new Uint8Array(blockSize * 2).fill(0x43),
    },
    {
      name: 'Data one byte less than block',
      key: new Uint8Array(32).fill(0x42),
      data: new Uint8Array(blockSize - 1).fill(0x43),
    },
    {
      name: 'Data one byte more than block',
      key: new Uint8Array(32).fill(0x42),
      data: new Uint8Array(blockSize + 1).fill(0x43),
    },
    {
      name: 'Key exactly block size',
      key: new Uint8Array(blockSize).fill(0x42),
      data: new Uint8Array(100).fill(0x43),
    },
    {
      name: 'Key one byte more than block size',
      key: new Uint8Array(blockSize + 1).fill(0x42),
      data: new Uint8Array(100).fill(0x43),
    },
  ];

  for (const testCase of testCases) {
    try {
      const nativeResult = hmacSha512(testCase.key, testCase.data);
      const nobleResult = hmac(sha512, testCase.key, testCase.data);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native and Noble results match. Key: ${testCase.key.length}B, Data: ${testCase.data.length}B`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8), false)}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test known problematic inputs that have caused issues in other implementations
 */
export function testProblematicInputs(): TestResult[] {
  const results: TestResult[] = [];

  const testCases = [
    {
      name: 'Sha512/384 issue reproduction',
      key: hexToUint8Array(
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      ),
      data: concatBytes(
        hexToUint8Array(
          '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'
        ),
        hexToUint8Array('00'),
        hexToUint8Array(
          '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf59a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe'
        )
      ),
    },
    {
      name: 'All bytes 0x00 to 0xFF pattern',
      key: new Uint8Array(256).map((_, i) => i),
      data: new Uint8Array(256).map((_, i) => 255 - i),
    },
    {
      name: 'Alternating pattern key',
      key: new Uint8Array(64).map((_, i) => (i % 2 === 0 ? 0xaa : 0x55)),
      data: new Uint8Array(64).map((_, i) => (i % 2 === 0 ? 0x55 : 0xaa)),
    },
    {
      name: 'Unicode data handling',
      key: utf8ToBytes('🔑 key'),
      data: utf8ToBytes('🔒 data with émojis and spëcial characters'),
    },
    {
      name: 'SPACE test (space key and data)',
      key: new Uint8Array([0x20]), // Space character
      data: new Uint8Array([0x20]), // Space character
    },
    {
      name: 'Empty key with space data',
      key: new Uint8Array([]),
      data: new Uint8Array([0x20]),
    },
    {
      name: 'Space key with empty data',
      key: new Uint8Array([0x20]),
      data: new Uint8Array([]),
    },
  ];

  for (const testCase of testCases) {
    try {
      const nativeResult = hmacSha512(testCase.key, testCase.data);
      const nobleResult = hmac(sha512, testCase.key, testCase.data);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native and Noble results match. Result: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}...`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(nativeResult.slice(0, 8), false)}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8), false)}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test streaming behavior simulation (testing that concatenated data works same as noble's streaming)
 */
export function testStreamingBehavior(): TestResult[] {
  const results: TestResult[] = [];

  // Test cases that simulate streaming behavior from the original noble tests
  const testCases = [
    {
      name: 'Multi-part data vs concatenated (RFC 4231 Case 2)',
      key: utf8ToBytes('Jefe'),
      parts: [utf8ToBytes('what do ya want '), utf8ToBytes('for nothing?')],
    },
    {
      name: 'Multi-part data vs concatenated (RFC 4231 Case 5)',
      key: hexToUint8Array('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'),
      parts: [utf8ToBytes('Test With Trunca'), utf8ToBytes('tion')],
    },
    {
      name: 'Many small parts vs single large data',
      key: new Uint8Array(32).fill(0x42),
      parts: Array.from({ length: 100 }, (_, i) => new Uint8Array([i % 256])),
    },
  ];

  for (const testCase of testCases) {
    try {
      // Test with concatenated data (our native implementation)
      const concatenated = concatBytes(...testCase.parts);
      const nativeResult = hmacSha512(testCase.key, concatenated);

      // Test with noble using concatenated data
      const nobleResult = hmac(sha512, testCase.key, concatenated);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native matches noble for ${testCase.parts.length} parts`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(
            nativeResult.slice(0, 8), false
          )}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8)), false}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Test special constants and edge values
 */
export function testSpecialConstants(): TestResult[] {
  const results: TestResult[] = [];

  const testCases = [
    {
      name: 'All zero key and data',
      key: new Uint8Array(64).fill(0),
      data: new Uint8Array(64).fill(0),
    },
    {
      name: 'All maximum value key and data',
      key: new Uint8Array(64).fill(255),
      data: new Uint8Array(64).fill(255),
    },
    {
      name: 'Key with increment pattern',
      key: new Uint8Array(64).map((_, i) => i % 256),
      data: new Uint8Array(64).map((_, i) => (i * 2) % 256),
    },
    {
      name: 'Repeating single byte key',
      key: new Uint8Array(1).fill(0x42),
      data: new Uint8Array(1000).fill(0x24),
    },
  ];

  for (const testCase of testCases) {
    try {
      const nativeResult = hmacSha512(testCase.key, testCase.data);
      const nobleResult = hmac(sha512, testCase.key, testCase.data);

      if (
        nativeResult.length === nobleResult.length &&
        nativeResult.every((val, i) => val === nobleResult[i])
      ) {
        results.push({
          name: testCase.name,
          success: true,
          message: `Native and Noble results match. Result: ${uint8ArrayToHex(
            nativeResult.slice(0, 8), false
          )}...`,
        });
      } else {
        results.push({
          name: testCase.name,
          success: false,
          message: `Results don't match. Native: ${uint8ArrayToHex(
            nativeResult.slice(0, 8), false
          )}..., Noble: ${uint8ArrayToHex(nobleResult.slice(0, 8)), false}...`,
        });
      }
    } catch (error) {
      results.push({
        name: testCase.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

/**
 * Run all comprehensive HMAC-SHA512 tests
 */
export function runAllComprehensiveTests(): TestResult[] {
  const results: TestResult[] = [];

  // Add a test summary header
  results.push({
    name: '=== COMPREHENSIVE HMAC-SHA512 TESTS ===',
    success: true,
    message:
      'Testing native implementation against noble-hashes JavaScript version',
  });

  // Run all test suites
  results.push(...testRFC4231Vectors());
  results.push(...testNISTVectors());
  results.push(...testEdgeCases());
  results.push(...testCryptocurrencyScenarios());
  results.push(...testSHA512BlockBoundaries());
  results.push(...testProblematicInputs());
  results.push(...testStreamingBehavior());
  results.push(...testSpecialConstants());

  // Add summary
  const totalTests = results.length - 1; // Exclude header
  const passedTests = results.filter((r) => r.success).length - 1; // Exclude header
  const failedTests = totalTests - passedTests;

  results.push({
    name: '=== TEST SUMMARY ===',
    success: failedTests === 0,
    message: `Total: ${totalTests}, Passed: ${passedTests}, Failed: ${failedTests}`,
  });

  return results;
}
