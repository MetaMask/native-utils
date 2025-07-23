import type { HybridObject } from 'react-native-nitro-modules';

export interface NitroSecp256k1
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  multiply(a: number, b: number): number;
  toPublicKey(privateKey: string, isCompressed: boolean): ArrayBuffer;
  toPublicKeyFromBytes(
    privateKey: ArrayBuffer,
    isCompressed: boolean
  ): ArrayBuffer;
  hmacSha512(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
  pubToAddress(pubKey: ArrayBuffer, sanitize: boolean): ArrayBuffer;
  keccak256(data: string): ArrayBuffer;
  keccak256FromBytes(data: ArrayBuffer): ArrayBuffer;
}
