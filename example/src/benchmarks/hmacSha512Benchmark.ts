import { hmacSha512 } from '@metamask/native-utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';

export interface BenchmarkResult {
  testName: string;
  native: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
  };
  javascript: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
  };
  comparison: {
    speedupFactor: number;
    nativeIsFaster: boolean;
    percentageImprovement: number;
  };
}

/**
 * Benchmark HMAC-SHA512 performance for BIP32 operations
 */
export async function benchmarkHmacSha512BIP32(
  iterations: number = 1000,
): Promise<BenchmarkResult> {
  // Prepare test data similar to BIP32 operations
  const chainCode = new Uint8Array(32);
  chainCode.fill(0xaa);

  const publicKey = new Uint8Array(33);
  publicKey[0] = 0x02;
  publicKey.fill(0x03, 1);

  const index = new Uint8Array(4);
  index[3] = 0x01;

  const bip32Data = new Uint8Array(37);
  bip32Data.set(publicKey, 0);
  bip32Data.set(index, 33);

  // Benchmark native implementation
  const nativeTimes: number[] = [];
  let nativeStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    hmacSha512(chainCode, bip32Data);
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  const nativeEnd = performance.now();
  const nativeTotalTime = nativeEnd - nativeStart;

  // Benchmark JavaScript implementation
  const jsTimes: number[] = [];
  let jsStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    hmac(sha512, chainCode, bip32Data);
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const jsEnd = performance.now();
  const jsTotalTime = jsEnd - jsStart;

  // Calculate statistics
  const nativeAvg = nativeTimes.reduce((a, b) => a + b, 0) / nativeTimes.length;
  const nativeMin = Math.min(...nativeTimes);
  const nativeMax = Math.max(...nativeTimes);
  const nativeIops = 1000 / nativeAvg;

  const jsAvg = jsTimes.reduce((a, b) => a + b, 0) / jsTimes.length;
  const jsMin = Math.min(...jsTimes);
  const jsMax = Math.max(...jsTimes);
  const jsIops = 1000 / jsAvg;

  const speedupFactor = jsAvg / nativeAvg;
  const nativeIsFaster = nativeAvg < jsAvg;
  const percentageImprovement = ((jsAvg - nativeAvg) / jsAvg) * 100;

  return {
    testName: 'HMAC-SHA512 BIP32 Operation',
    native: {
      totalTime: nativeTotalTime,
      averageTime: nativeAvg,
      minTime: nativeMin,
      maxTime: nativeMax,
      operations: iterations,
      iops: nativeIops,
    },
    javascript: {
      totalTime: jsTotalTime,
      averageTime: jsAvg,
      minTime: jsMin,
      maxTime: jsMax,
      operations: iterations,
      iops: jsIops,
    },
    comparison: {
      speedupFactor,
      nativeIsFaster,
      percentageImprovement,
    },
  };
}

/**
 * Benchmark different BIP32 scenarios
 */
export async function benchmarkBIP32Scenarios(
  iterations: number = 500,
): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];

  // Test 1: Normal derivation (public key + index)
  const chainCode = new Uint8Array(32);
  chainCode.fill(0xaa);
  const publicKey = new Uint8Array(33);
  publicKey[0] = 0x02;
  publicKey.fill(0x03, 1);
  const index = new Uint8Array(4);
  index[3] = 0x01;
  const normalData = new Uint8Array(37);
  normalData.set(publicKey, 0);
  normalData.set(index, 33);

  const normalResult = await benchmarkScenario(
    'Normal Derivation',
    chainCode,
    normalData,
    iterations,
  );
  results.push(normalResult);

  // Test 2: Hardened derivation (0x00 + private key + index)
  const privateKey = new Uint8Array(32);
  privateKey.fill(0x33);
  const hardenedIndex = new Uint8Array(4);
  hardenedIndex[0] = 0x80;
  const hardenedData = new Uint8Array(37);
  hardenedData[0] = 0x00;
  hardenedData.set(privateKey, 1);
  hardenedData.set(hardenedIndex, 33);

  const hardenedResult = await benchmarkScenario(
    'Hardened Derivation',
    chainCode,
    hardenedData,
    iterations,
  );
  results.push(hardenedResult);

  // Test 3: Master seed generation
  const masterSeed = new Uint8Array(64);
  masterSeed.fill(0x55);
  const bitcoinSeed = new Uint8Array([
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
  ]); // "Bitcoin seed"

  const masterResult = await benchmarkScenario(
    'Master Seed Generation',
    bitcoinSeed,
    masterSeed,
    iterations,
  );
  results.push(masterResult);

  return results;
}

/**
 * Helper function to benchmark a specific scenario
 */
async function benchmarkScenario(
  testName: string,
  key: Uint8Array,
  data: Uint8Array,
  iterations: number,
): Promise<BenchmarkResult> {
  // Benchmark native implementation
  const nativeTimes: number[] = [];
  const nativeStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    hmacSha512(key, data);
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  const nativeEnd = performance.now();
  const nativeTotalTime = nativeEnd - nativeStart;

  // Benchmark JavaScript implementation
  const jsTimes: number[] = [];
  const jsStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    hmac(sha512, key, data);
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const jsEnd = performance.now();
  const jsTotalTime = jsEnd - jsStart;

  // Calculate statistics
  const nativeAvg = nativeTimes.reduce((a, b) => a + b, 0) / nativeTimes.length;
  const nativeMin = Math.min(...nativeTimes);
  const nativeMax = Math.max(...nativeTimes);
  const nativeIops = 1000 / nativeAvg;

  const jsAvg = jsTimes.reduce((a, b) => a + b, 0) / jsTimes.length;
  const jsMin = Math.min(...jsTimes);
  const jsMax = Math.max(...jsTimes);
  const jsIops = 1000 / jsAvg;

  const speedupFactor = jsAvg / nativeAvg;
  const nativeIsFaster = nativeAvg < jsAvg;
  const percentageImprovement = ((jsAvg - nativeAvg) / jsAvg) * 100;

  return {
    testName,
    native: {
      totalTime: nativeTotalTime,
      averageTime: nativeAvg,
      minTime: nativeMin,
      maxTime: nativeMax,
      operations: iterations,
      iops: nativeIops,
    },
    javascript: {
      totalTime: jsTotalTime,
      averageTime: jsAvg,
      minTime: jsMin,
      maxTime: jsMax,
      operations: iterations,
      iops: jsIops,
    },
    comparison: {
      speedupFactor,
      nativeIsFaster,
      percentageImprovement,
    },
  };
}
