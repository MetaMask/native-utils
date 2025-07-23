import { pubToAddress } from '@metamask/native-utils';
import { publicToAddress as ethereumjsPublicToAddress } from '@ethereumjs/util';
import { hexToUint8Array, calculateStats } from '../testUtils';

export type BenchmarkResult = {
  testName: string;
  native: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    iops: number;
    standardDeviation: number;
  };
  javascript: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    iops: number;
    standardDeviation: number;
  };
  comparison: {
    speedupFactor: number;
    nativeIsFaster: boolean;
    performanceGain: number;
  };
};

// Helper functions are now imported from testUtils

// Benchmark function template
async function benchmarkFunction(
  testName: string,
  nativeImpl: () => Uint8Array,
  jsImpl: () => Uint8Array,
  iterations: number = 1000
): Promise<BenchmarkResult> {
  const nativeTimes: number[] = [];
  const jsTimes: number[] = [];

  // Warm up both implementations
  for (let i = 0; i < 10; i++) {
    nativeImpl();
    jsImpl();
  }

  // Benchmark native implementation
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    nativeImpl();
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  // Small delay to prevent interference
  await new Promise((resolve) => setTimeout(resolve, 10));

  // Benchmark JavaScript implementation
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    jsImpl();
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const nativeStats = calculateStats(nativeTimes);
  const jsStats = calculateStats(jsTimes);

  const speedupFactor = jsStats.averageTime / nativeStats.averageTime;
  const nativeIsFaster = nativeStats.averageTime < jsStats.averageTime;
  const performanceGain =
    ((jsStats.averageTime - nativeStats.averageTime) / jsStats.averageTime) *
    100;

  return {
    testName,
    native: nativeStats,
    javascript: jsStats,
    comparison: {
      speedupFactor,
      nativeIsFaster,
      performanceGain,
    },
  };
}

// Benchmark 64-byte public key conversion
export async function benchmark64BytePublicKey(): Promise<BenchmarkResult> {
  const pubKey = hexToUint8Array(
    '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  );

  return benchmarkFunction(
    '64-byte Public Key → Address',
    () => pubToAddress(pubKey, false),
    () => ethereumjsPublicToAddress(pubKey, false),
    1000
  );
}

// Benchmark 65-byte SEC1 public key conversion with sanitization
export async function benchmark65BytePublicKeyWithSanitize(): Promise<BenchmarkResult> {
  const pubKey = hexToUint8Array(
    '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  );

  return benchmarkFunction(
    '65-byte SEC1 Public Key → Address (sanitized)',
    () => pubToAddress(pubKey, true),
    () => ethereumjsPublicToAddress(pubKey, true),
    1000
  );
}

// Benchmark with multiple different public keys
export async function benchmarkMultiplePublicKeys(): Promise<BenchmarkResult> {
  const pubKeys = [
    hexToUint8Array(
      '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    ),
    hexToUint8Array(
      '0x4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
    ),
    hexToUint8Array(
      '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    ),
    hexToUint8Array(
      '0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
    ),
  ];

  let keyIndex = 0;

  return benchmarkFunction(
    'Multiple Public Keys → Address',
    () => {
      const result = pubToAddress(pubKeys[keyIndex % pubKeys.length]!, false);
      keyIndex++;
      if (!result) throw new Error('Native function returned undefined');
      return result;
    },
    () => {
      const result = ethereumjsPublicToAddress(
        pubKeys[keyIndex % pubKeys.length]!,
        false
      );
      keyIndex++;
      if (!result) throw new Error('JavaScript function returned undefined');
      return result;
    },
    2000
  );
}

// Benchmark mixed operations (with and without sanitization)
export async function benchmarkMixedOperations(): Promise<BenchmarkResult> {
  const pubKeys64 = [
    hexToUint8Array(
      '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    ),
    hexToUint8Array(
      '0x4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
    ),
  ];

  const pubKeys65 = [
    hexToUint8Array(
      '0x043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    ),
    hexToUint8Array(
      '0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'
    ),
  ];

  let operationIndex = 0;

  return benchmarkFunction(
    'Mixed Operations (64-byte & 65-byte)',
    () => {
      const isEven = operationIndex % 2 === 0;
      const keyIndex = Math.floor(operationIndex / 2) % 2;
      operationIndex++;

      let result: Uint8Array;
      if (isEven) {
        result = pubToAddress(pubKeys64[keyIndex]!, false);
      } else {
        result = pubToAddress(pubKeys65[keyIndex]!, true);
      }

      if (!result) throw new Error('Native function returned undefined');
      return result;
    },
    () => {
      const isEven = operationIndex % 2 === 0;
      const keyIndex = Math.floor(operationIndex / 2) % 2;
      operationIndex++;

      let result: Uint8Array;
      if (isEven) {
        result = ethereumjsPublicToAddress(pubKeys64[keyIndex]!, false);
      } else {
        result = ethereumjsPublicToAddress(pubKeys65[keyIndex]!, true);
      }

      if (!result) throw new Error('JavaScript function returned undefined');
      return result;
    },
    1000
  );
}

// Run all benchmarks
export async function runAllPubToAddressBenchmarks(): Promise<
  BenchmarkResult[]
> {
  const results: BenchmarkResult[] = [];

  console.log('Running pubToAddress benchmarks...');

  results.push(await benchmark64BytePublicKey());
  results.push(await benchmark65BytePublicKeyWithSanitize());
  results.push(await benchmarkMultiplePublicKeys());
  results.push(await benchmarkMixedOperations());

  return results;
}

// Quick benchmark for immediate feedback
export async function quickPubToAddressBenchmark(): Promise<string> {
  const pubKey = hexToUint8Array(
    '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  );

  const iterations = 100;
  const nativeTimes: number[] = [];
  const jsTimes: number[] = [];

  // Warm up
  for (let i = 0; i < 5; i++) {
    pubToAddress(pubKey, false);
    ethereumjsPublicToAddress(pubKey, false);
  }

  // Benchmark native
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    pubToAddress(pubKey, false);
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  // Benchmark JavaScript
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    ethereumjsPublicToAddress(pubKey, false);
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const nativeAvg =
    nativeTimes.reduce((sum, time) => sum + time, 0) / nativeTimes.length;
  const jsAvg = jsTimes.reduce((sum, time) => sum + time, 0) / jsTimes.length;
  const speedup = jsAvg / nativeAvg;

  return (
    `🚀 pubToAddress Quick Benchmark (${iterations} iterations):\n` +
    `Native: ${nativeAvg.toFixed(3)}ms avg (${(1000 / nativeAvg).toFixed(0)} ops/sec)\n` +
    `JavaScript: ${jsAvg.toFixed(3)}ms avg (${(1000 / jsAvg).toFixed(0)} ops/sec)\n` +
    `Speedup: ${speedup.toFixed(2)}x ${speedup > 1 ? 'faster' : 'slower'} 🎯`
  );
}

// Format benchmark results for display
export function formatPubToAddressBenchmarkResults(
  results: BenchmarkResult[]
): string {
  let output = '🏆 pubToAddress Performance Benchmark Results:\n\n';

  results.forEach((result, index) => {
    output += `${index + 1}. ${result.testName}\n`;
    output += `   Native:     ${result.native.averageTime.toFixed(3)}ms avg (${result.native.iops.toFixed(0)} ops/sec)\n`;
    output += `   JavaScript: ${result.javascript.averageTime.toFixed(3)}ms avg (${result.javascript.iops.toFixed(0)} ops/sec)\n`;
    output += `   Speedup:    ${result.comparison.speedupFactor.toFixed(2)}x ${result.comparison.nativeIsFaster ? 'faster' : 'slower'}\n`;
    output += `   Gain:       ${result.comparison.performanceGain.toFixed(1)}% improvement\n`;
    output += `   Std Dev:    Native ±${result.native.standardDeviation.toFixed(3)}ms, JS ±${result.javascript.standardDeviation.toFixed(3)}ms\n\n`;
  });

  // Calculate overall statistics
  const totalSpeedup =
    results.reduce((sum, r) => sum + r.comparison.speedupFactor, 0) /
    results.length;
  const totalGain =
    results.reduce((sum, r) => sum + r.comparison.performanceGain, 0) /
    results.length;

  output += `📊 Overall Performance Summary:\n`;
  output += `   Average Speedup: ${totalSpeedup.toFixed(2)}x\n`;
  output += `   Average Gain: ${totalGain.toFixed(1)}% improvement\n`;
  output += `   All tests faster: ${results.every((r) => r.comparison.nativeIsFaster) ? 'Yes ✅' : 'No ❌'}\n`;

  return output;
}
