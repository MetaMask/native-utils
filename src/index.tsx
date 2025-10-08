import { NitroModules } from 'react-native-nitro-modules';
import type { NativeUtils } from './NativeUtils.nitro';
import {
  bigintToBytes,
  uint8ArrayToArrayBuffer,
  arrayBufferToUint8Array,
  numberArrayToUint8Array,
} from './utils';

const NativeUtilsHybridObject =
  NitroModules.createHybridObject<NativeUtils>('NativeUtils');

export function multiply(a: number, b: number): number {
  return NativeUtilsHybridObject.multiply(a, b);
}

/** Uint8Array alias for compatibility */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
export type Hex = Bytes | string;
/** Private key can be hex string, Uint8Array, or bigint. */
export type PrivKey = Hex | bigint;

/**
 * Generate a public key from a private key using the secp256k1 elliptic curve.
 * This is a fast native implementation that matches the noble/secp256k1 API.
 *
 * @param privateKey - The private key as a hex string, Uint8Array, or bigint
 * @param isCompressed - Whether to return compressed (33 bytes) or uncompressed (65 bytes) public key
 * @returns Uint8Array containing the public key bytes
 */
export function getPublicKey(
  privateKey: PrivKey,
  isCompressed: boolean = true,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof privateKey === 'string') {
    // Use the string version (C++ will handle hex validation)
    result = NativeUtilsHybridObject.toPublicKey(privateKey, isCompressed);
  } else if (typeof privateKey === 'bigint') {
    // Convert bigint to bytes (basic validation here, detailed validation in C++)
    const privateKeyBytes = bigintToBytes(privateKey);
    const privateKeyBuffer = uint8ArrayToArrayBuffer(privateKeyBytes);
    result = NativeUtilsHybridObject.toPublicKeyFromBytes(
      privateKeyBuffer,
      isCompressed,
    );
  } else if (privateKey instanceof Uint8Array) {
    // Convert Uint8Array to ArrayBuffer (C++ will handle length and scalar validation)
    if (privateKey.length !== 32) {
      throw new Error('Uint8Array expected');
    }
    const privateKeyBuffer = uint8ArrayToArrayBuffer(privateKey);
    result = NativeUtilsHybridObject.toPublicKeyFromBytes(
      privateKeyBuffer,
      isCompressed,
    );
  } else {
    throw new Error('Private key must be a hex string, Uint8Array, or bigint');
  }

  // Convert result from ArrayBuffer to Uint8Array to match noble's API
  return arrayBufferToUint8Array(result);
}

/**
 * Compute Keccak-256 hash using native implementation.
 * Accepts multiple input types for maximum flexibility.
 *
 * @param data - The data to hash as string (hex), number[], ArrayBuffer, or Uint8Array
 * @returns Uint8Array containing the 32-byte Keccak-256 hash
 */
export function keccak256(
  data: string | number[] | ArrayBuffer | Uint8Array,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof data === 'string') {
    // Assume hex string, use the string version (C++ will handle hex validation)
    result = NativeUtilsHybridObject.keccak256(data);
  } else if (Array.isArray(data)) {
    // Convert number array to Uint8Array, then to ArrayBuffer
    const bytes = numberArrayToUint8Array(data);
    const buffer = uint8ArrayToArrayBuffer(bytes);
    result = NativeUtilsHybridObject.keccak256FromBytes(buffer);
  } else if (data instanceof ArrayBuffer) {
    // Use ArrayBuffer directly
    result = NativeUtilsHybridObject.keccak256FromBytes(data);
  } else if (data instanceof Uint8Array) {
    // Convert Uint8Array to ArrayBuffer
    const buffer = uint8ArrayToArrayBuffer(data);
    result = NativeUtilsHybridObject.keccak256FromBytes(buffer);
  } else {
    throw new Error(
      'Data must be a hex string, number[], ArrayBuffer, or Uint8Array',
    );
  }

  // Convert result from ArrayBuffer to Uint8Array to match common crypto library APIs
  return arrayBufferToUint8Array(result);
}

/**
 * Returns the ethereum address of a given public key using native C++ implementation.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 * @returns Uint8Array containing the 20-byte Ethereum address
 */
export function pubToAddress(
  pubKey: Uint8Array,
  sanitize: boolean = false,
): Uint8Array {
  const pubKeyBuffer = uint8ArrayToArrayBuffer(pubKey);

  const result = NativeUtilsHybridObject.pubToAddress(pubKeyBuffer, sanitize);

  return arrayBufferToUint8Array(result);
}

/**
 * Compute HMAC-SHA512 using native implementation for better performance.
 *
 * @param key - The HMAC key as Uint8Array
 * @param data - The data to authenticate as Uint8Array
 * @returns Uint8Array containing the 64-byte HMAC-SHA512 result
 */
export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  const keyBuffer = uint8ArrayToArrayBuffer(key);
  const dataBuffer = uint8ArrayToArrayBuffer(data);

  const result = NativeUtilsHybridObject.hmacSha512(keyBuffer, dataBuffer);

  return arrayBufferToUint8Array(result);
}
