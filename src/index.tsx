import { NitroModules } from 'react-native-nitro-modules';
import type { NativeUtils } from './NativeUtils.nitro';

const NativeUtilsHybridObject =
  NitroModules.createHybridObject<NativeUtils>('NativeUtils');

export function multiply(a: number, b: number): number {
  return NativeUtilsHybridObject.multiply(a, b);
}
