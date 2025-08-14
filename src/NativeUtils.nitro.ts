import type { HybridObject } from 'react-native-nitro-modules';

export interface NativeUtils
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  multiply(a: number, b: number): number;
}
