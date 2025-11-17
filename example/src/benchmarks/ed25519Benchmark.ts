import { getPublicKeyEd25519 } from '@metamask/native-utils';
import { ed25519 } from '@noble/curves/ed25519';

export interface BenchmarkResult {
  testName: string;
  native: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
    standardDeviation: number;
  };
  javascript: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
    standardDeviation: number;
  };
  comparison: {
    speedupFactor: number;
    nativeIsFaster: boolean;
    performanceGain: number;
  };
}

/**
 * Helper function to calculate standard deviation
 */
function calculateStandardDeviation(values: number[], mean: number): number {
  const squareDiffs = values.map((value) => Math.pow(value - mean, 2));
  const avgSquareDiff =
    squareDiffs.reduce((sum, value) => sum + value, 0) / values.length;
  return Math.sqrt(avgSquareDiff);
}

/**
 * Generate random private key for testing
 */
function generateRandomPrivateKey(): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Benchmark a specific scenario
 */
async function benchmarkScenario(
  testName: string,
  privateKeyBytes: Uint8Array,
  iterations: number,
): Promise<BenchmarkResult> {
  const privateKeyHex = uint8ArrayToHex(privateKeyBytes);

  // Warm up both implementations
  for (let i = 0; i < 10; i++) {
    getPublicKeyEd25519(privateKeyHex);
    ed25519.getPublicKey(privateKeyBytes);
  }

  // Benchmark native implementation
  const nativeTimes: number[] = [];
  const nativeStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    getPublicKeyEd25519(privateKeyHex);
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  const nativeEnd = performance.now();
  const nativeTotalTime = nativeEnd - nativeStart;

  // Small delay between runs
  await new Promise((resolve) => setTimeout(resolve, 10));

  // Benchmark JavaScript implementation
  const jsTimes: number[] = [];
  const jsStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    ed25519.getPublicKey(privateKeyBytes);
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const jsEnd = performance.now();
  const jsTotalTime = jsEnd - jsStart;

  // Calculate statistics
  const nativeAvg = nativeTimes.reduce((a, b) => a + b, 0) / nativeTimes.length;
  const nativeMin = Math.min(...nativeTimes);
  const nativeMax = Math.max(...nativeTimes);
  const nativeStdDev = calculateStandardDeviation(nativeTimes, nativeAvg);
  const nativeIops = 1000 / nativeAvg;

  const jsAvg = jsTimes.reduce((a, b) => a + b, 0) / jsTimes.length;
  const jsMin = Math.min(...jsTimes);
  const jsMax = Math.max(...jsTimes);
  const jsStdDev = calculateStandardDeviation(jsTimes, jsAvg);
  const jsIops = 1000 / jsAvg;

  const speedupFactor = jsAvg / nativeAvg;
  const nativeIsFaster = nativeAvg < jsAvg;
  const performanceGain = ((jsAvg - nativeAvg) / jsAvg) * 100;

  return {
    testName,
    native: {
      totalTime: nativeTotalTime,
      averageTime: nativeAvg,
      minTime: nativeMin,
      maxTime: nativeMax,
      operations: iterations,
      iops: nativeIops,
      standardDeviation: nativeStdDev,
    },
    javascript: {
      totalTime: jsTotalTime,
      averageTime: jsAvg,
      minTime: jsMin,
      maxTime: jsMax,
      operations: iterations,
      iops: jsIops,
      standardDeviation: jsStdDev,
    },
    comparison: {
      speedupFactor,
      nativeIsFaster,
      performanceGain,
    },
  };
}

/**
 * Run all Ed25519 benchmarks
 */
export async function runAllEd25519Benchmarks(
  iterations: number = 200,
): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];

  // Test 1: Random key #1
  const randomKey1 = generateRandomPrivateKey();
  const result1 = await benchmarkScenario(
    'Random Ed25519 Key #1',
    randomKey1,
    iterations,
  );
  results.push(result1);

  // Small delay between tests
  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 2: Random key #2
  const randomKey2 = generateRandomPrivateKey();
  const result2 = await benchmarkScenario(
    'Random Ed25519 Key #2',
    randomKey2,
    iterations,
  );
  results.push(result2);

  // Small delay between tests
  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 3: RFC 8032 Test Vector 1
  const rfcKey1 = new Uint8Array([
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
    0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
  ]);
  const result3 = await benchmarkScenario(
    'RFC 8032 Test Vector 1',
    rfcKey1,
    iterations,
  );
  results.push(result3);

  // Small delay between tests
  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 4: RFC 8032 Test Vector 2
  const rfcKey2 = new Uint8Array([
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46,
    0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
  ]);
  const result4 = await benchmarkScenario(
    'RFC 8032 Test Vector 2',
    rfcKey2,
    iterations,
  );
  results.push(result4);

  return results;
}
