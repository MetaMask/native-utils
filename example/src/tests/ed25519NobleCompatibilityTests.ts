import { getPublicKeyEd25519 as nativeGetPublicKeyEd25519 } from '@metamask/native-utils';
import { ed25519 } from '@noble/curves/ed25519';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';

export interface Ed25519VerificationResult {
  privateKey: string;
  nativePublicKey: string;
  noblePublicKey: string;
  matches: boolean;
}

/**
 * Verify Ed25519 public key generation matches noble/curves implementation
 */
export const verifyEd25519PublicKeyImplementation = (
  privateKeyStr: string,
): Ed25519VerificationResult => {
  // Pad private key to 32 bytes (64 hex chars)
  const privateKey = privateKeyStr.padStart(64, '0');

  // Test with native implementation
  const nativePublicKey = nativeGetPublicKeyEd25519(privateKey);

  // Test with noble implementation
  const privateKeyBytes = hexToUint8Array(privateKey);
  const noblePublicKey = ed25519.getPublicKey(privateKeyBytes);

  // Convert to hex strings for comparison
  const nativePublicKeyHex = uint8ArrayToHex(nativePublicKey);
  const noblePublicKeyHex = uint8ArrayToHex(noblePublicKey);

  return {
    privateKey: privateKey,
    nativePublicKey: nativePublicKeyHex,
    noblePublicKey: noblePublicKeyHex,
    matches: nativePublicKeyHex === noblePublicKeyHex,
  };
};

/**
 * Test multiple Ed25519 vectors against noble/curves
 */
export const verifyMultipleEd25519Vectors = (): Ed25519VerificationResult[] => {
  // Use a diverse set of test vectors
  const testVectors = [
    // Simple sequential numbers
    '1',
    '2',
    '3',
    '4',
    '5',

    // Hex patterns
    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',

    // RFC 8032 test vectors
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783',
    'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',

    // Edge cases
    '0000000000000000000000000000000000000000000000000000000000000001', // Min
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', // Max
  ];

  return testVectors.map(verifyEd25519PublicKeyImplementation);
};

/**
 * Test Ed25519 public key generation with Uint8Array input
 */
export const verifyEd25519Uint8ArrayInput = (): Ed25519VerificationResult[] => {
  const results: Ed25519VerificationResult[] = [];

  // Test with Uint8Array inputs
  const testVectors = [
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
  ];

  for (const privateKeyHex of testVectors) {
    const privateKeyBytes = hexToUint8Array(privateKeyHex);

    // Test with native implementation
    const nativePublicKey = nativeGetPublicKeyEd25519(privateKeyBytes);

    // Test with noble implementation
    const noblePublicKey = ed25519.getPublicKey(privateKeyBytes);

    // Convert to hex strings for comparison
    const nativePublicKeyHex = uint8ArrayToHex(nativePublicKey);
    const noblePublicKeyHex = uint8ArrayToHex(noblePublicKey);

    results.push({
      privateKey: privateKeyHex,
      nativePublicKey: nativePublicKeyHex,
      noblePublicKey: noblePublicKeyHex,
      matches: nativePublicKeyHex === noblePublicKeyHex,
    });
  }

  return results;
};

/**
 * Comprehensive comparison test - tests many random-looking keys
 */
export const comprehensiveEd25519Comparison = (
  count: number = 100,
): {
  passed: number;
  failed: number;
  failures: Ed25519VerificationResult[];
} => {
  let passed = 0;
  let failed = 0;
  const failures: Ed25519VerificationResult[] = [];

  for (let i = 0; i < count; i++) {
    // Generate deterministic but varied private keys
    const privateKey = new Uint8Array(32);
    for (let j = 0; j < 32; j++) {
      privateKey[j] = (i * 17 + j * 13 + i * j * 7) % 256;
    }

    try {
      const nativePublicKey = nativeGetPublicKeyEd25519(privateKey);
      const noblePublicKey = ed25519.getPublicKey(privateKey);

      const nativeHex = uint8ArrayToHex(nativePublicKey);
      const nobleHex = uint8ArrayToHex(noblePublicKey);

      if (nativeHex === nobleHex) {
        passed++;
      } else {
        failed++;
        failures.push({
          privateKey: uint8ArrayToHex(privateKey),
          nativePublicKey: nativeHex,
          noblePublicKey: nobleHex,
          matches: false,
        });
      }
    } catch (error) {
      failed++;
      failures.push({
        privateKey: uint8ArrayToHex(privateKey),
        nativePublicKey: 'ERROR',
        noblePublicKey: 'ERROR',
        matches: false,
      });
    }
  }

  return { passed, failed, failures };
};
