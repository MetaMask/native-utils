import { hmacSha512 } from '@metamask/native-utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import {
  hexToUint8Array,
  utf8ToBytes,
  uint8ArrayToHex,
  concatBytes,
  truncate,
} from '../testUtils';

export interface ValidationResult {
  testCase: number;
  success: boolean;
  expectedHex: string;
  nativeHex: string;
  nobleHex: string;
  message: string;
}

/**
 * Exact RFC 4231 test vectors from the noble-hashes library
 */
const RFC4231_EXACT_VECTORS = [
  {
    testCase: 1,
    key: hexToUint8Array('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    data: [utf8ToBytes('Hi There')],
    expectedSha512:
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
      'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    testCase: 2,
    key: utf8ToBytes('Jefe'),
    data: [utf8ToBytes('what do ya want '), utf8ToBytes('for nothing?')],
    expectedSha512:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
      '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    testCase: 3,
    key: hexToUint8Array('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    data: [
      hexToUint8Array(
        'dddddddddddddddddddddddddddddddddddddddddddddddddd' +
          'dddddddddddddddddddddddddddddddddddddddddddddddddd',
      ),
    ],
    expectedSha512:
      'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39' +
      'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    testCase: 4,
    key: hexToUint8Array('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: [
      hexToUint8Array(
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
      ),
    ],
    expectedSha512:
      'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db' +
      'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    testCase: 5,
    key: hexToUint8Array('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'),
    data: [utf8ToBytes('Test With Trunca'), utf8ToBytes('tion')],
    expectedSha512: '415fad6271580a531d4179bc891d87a6',
    truncate: 16,
  },
  {
    testCase: 6,
    key: hexToUint8Array(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa',
    ),
    data: [
      utf8ToBytes('Test Using Large'),
      utf8ToBytes('r Than Block-Siz'),
      utf8ToBytes('e Key - Hash Key'),
      utf8ToBytes(' First'),
    ],
    expectedSha512:
      '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352' +
      '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  {
    testCase: 7,
    key: hexToUint8Array(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa',
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
    expectedSha512:
      'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944' +
      'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
];

/**
 * Validate all RFC 4231 test vectors exactly
 */
export function validateRFC4231Vectors(): ValidationResult[] {
  const results: ValidationResult[] = [];

  for (const vector of RFC4231_EXACT_VECTORS) {
    const fullData = concatBytes(...vector.data);

    // Test native implementation
    const nativeResult = hmacSha512(vector.key, fullData);
    const truncatedNative = truncate(nativeResult, vector.truncate);
    const nativeHex = uint8ArrayToHex(truncatedNative, false);

    // Test noble implementation
    const nobleResult = hmac(sha512, vector.key, fullData);
    const truncatedNoble = truncate(nobleResult, vector.truncate);
    const nobleHex = uint8ArrayToHex(truncatedNoble, false);

    // Expected result
    const expectedHex = vector.expectedSha512;

    const success = nativeHex === expectedHex && nobleHex === expectedHex;

    results.push({
      testCase: vector.testCase,
      success,
      expectedHex,
      nativeHex,
      nobleHex,
      message: success
        ? `RFC 4231 Test Case ${vector.testCase} - All match`
        : `RFC 4231 Test Case ${vector.testCase} - Mismatch detected`,
    });
  }

  return results;
}

/**
 * Validate NIST vectors exactly
 */
export function validateNISTVectors(): ValidationResult[] {
  const results: ValidationResult[] = [];
  const emptyKey = new Uint8Array(0);

  const nistVectors = [
    {
      testCase: 1,
      input: utf8ToBytes('abc'),
      expected:
        '29689f6b79a8dd686068c2eeae97fd8769ad3ba65cb5381f838358a8045a358ee3ba1739c689c7805e31734fb6072f87261d1256995370d55725cba00d10bdd0',
    },
    {
      testCase: 2,
      input: utf8ToBytes(''),
      expected:
        'b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47',
    },
    {
      testCase: 3,
      input: utf8ToBytes(
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      ),
      expected:
        'e0657364f9603a276d94930f90a6b19f3ce4001ab494c4fdf7ff541609e05d2e48ca6454a4390feb12b8eacebb503ba2517f5e2454d7d77e8b44d7cca8f752cd',
    },
    {
      testCase: 4,
      input: utf8ToBytes(
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
      ),
      expected:
        'ece33db7448f63f4d460ac8b86bdf02fa6f5c3279a2a5d59df26827bec5315a44eb85d40ee4df3a7272a9596a0bc27091466724e9357183e554c9ec5fdf6d099',
    },
    {
      testCase: 5,
      input: new Uint8Array(1000000).fill(0x61), // 1 million 'a's
      expected:
        '59064f29e00b6a5cc55a3b69d9cfd3457ae70bd169b2b714036ae3a965805eb25a99ca221ade1aecebe6111d70697d1174a288cd1bb177de4a14f06eacc631d8',
    },
  ];

  for (const vector of nistVectors) {
    // Test native implementation
    const nativeResult = hmacSha512(emptyKey, vector.input);
    const nativeHex = uint8ArrayToHex(nativeResult, false);

    // Test noble implementation
    const nobleResult = hmac(sha512, emptyKey, vector.input);
    const nobleHex = uint8ArrayToHex(nobleResult, false);

    const success =
      nativeHex === vector.expected && nobleHex === vector.expected;

    results.push({
      testCase: vector.testCase,
      success,
      expectedHex: vector.expected,
      nativeHex,
      nobleHex,
      message: success
        ? `NIST Vector ${vector.testCase} - All match`
        : `NIST Vector ${vector.testCase} - Mismatch detected`,
    });
  }

  return results;
}

/**
 * Run complete validation
 */
export function runCompleteValidation(): ValidationResult[] {
  const results: ValidationResult[] = [];

  results.push(...validateRFC4231Vectors());
  results.push(...validateNISTVectors());

  return results;
}
