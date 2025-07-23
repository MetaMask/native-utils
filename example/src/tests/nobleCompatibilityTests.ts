import { getPublicKey as nativeGetPublicKey } from '@metamask/native-utils';
import * as secp256k1 from '@noble/secp256k1';
import { uint8ArrayToHex, hexToUint8Array } from '../testUtils';

export interface VerificationResult {
  privateKey: string;
  nativeCompressed: string;
  nobleCompressed: string;
  nativeUncompressed: string;
  nobleUncompressed: string;
  matches: boolean;
}

// Helper functions are now imported from testUtils

export const verifyPublicKeyImplementation = (
  privateKeyStr: string
): VerificationResult => {
  // Pad private key to 32 bytes (64 hex chars)
  const privateKey = privateKeyStr.padStart(64, '0');

  // Test with native implementation
  const nativeCompressed = nativeGetPublicKey(privateKey, true);
  const nativeUncompressed = nativeGetPublicKey(privateKey, false);

  // Test with noble implementation
  const privateKeyBytes = hexToUint8Array(privateKey);
  const nobleCompressed = secp256k1.getPublicKey(privateKeyBytes, true);
  const nobleUncompressed = secp256k1.getPublicKey(privateKeyBytes, false);

  // Convert to hex strings for comparison
  const nativeCompressedHex = uint8ArrayToHex(nativeCompressed);
  const nobleCompressedHex = uint8ArrayToHex(nobleCompressed);
  const nativeUncompressedHex = uint8ArrayToHex(nativeUncompressed);
  const nobleUncompressedHex = uint8ArrayToHex(nobleUncompressed);

  return {
    privateKey: privateKey,
    nativeCompressed: nativeCompressedHex,
    nobleCompressed: nobleCompressedHex,
    nativeUncompressed: nativeUncompressedHex,
    nobleUncompressed: nobleUncompressedHex,
    matches:
      nativeCompressedHex === nobleCompressedHex &&
      nativeUncompressedHex === nobleUncompressedHex,
  };
};

// Test multiple vectors
export const verifyMultipleVectors = (): VerificationResult[] => {
  const testVectors = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'];
  return testVectors.map(verifyPublicKeyImplementation);
};
