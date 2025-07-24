import { getPublicKey } from '@metamask/native-utils';
import * as secp256k1 from '@noble/secp256k1';

export interface BenchmarkResult {
  testName: string;
  iterations: number;
  totalRuns: number;

  native: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    medianTime: number;
    standardDeviation: number;
    iops: number;
    timings: number[];
  };

  javascript: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    medianTime: number;
    standardDeviation: number;
    iops: number;
    timings: number[];
  };

  comparison: {
    speedupFactor: number;
    nativeIsFaster: boolean;
    percentageDifference: number;
  };
}

export interface BenchmarkSuite {
  results: BenchmarkResult[];
  summary: {
    totalTests: number;
    nativeWins: number;
    jsWins: number;
    averageSpeedup: number;
    totalNativeTime: number;
    totalJsTime: number;
    overallIopsNative: number;
    overallIopsJs: number;
  };
}

import { hexToUint8Array, calculateStats } from '../testUtils';

// Single benchmark test
async function runSingleBenchmark(
  testName: string,
  privateKey: string,
  compressed: boolean,
  iterations: number = 100,
  runs: number = 5,
): Promise<BenchmarkResult> {
  const privateKeyBytes = hexToUint8Array(privateKey);
  const nativeTimings: number[] = [];
  const jsTimings: number[] = [];

  // Warm up both implementations
  for (let i = 0; i < 10; i++) {
    getPublicKey(privateKey, compressed);
    secp256k1.getPublicKey(privateKeyBytes, compressed);
  }

  // Run multiple test runs for statistical accuracy
  for (let run = 0; run < runs; run++) {
    // Benchmark native implementation
    const nativeStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      getPublicKey(privateKey, compressed);
    }
    const nativeEnd = performance.now();
    nativeTimings.push(nativeEnd - nativeStart);

    // Small delay between runs to avoid interference
    await new Promise((resolve) => setTimeout(resolve, 10));

    // Benchmark JavaScript implementation
    const jsStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      secp256k1.getPublicKey(privateKeyBytes, compressed);
    }
    const jsEnd = performance.now();
    jsTimings.push(jsEnd - jsStart);

    // Small delay between runs
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  const nativeStats = calculateStats(nativeTimings);
  const jsStats = calculateStats(jsTimings);

  // Calculate comparison metrics
  const speedupFactor = jsStats.averageTime / nativeStats.averageTime;
  const nativeIsFaster = speedupFactor > 1;
  const percentageDifference =
    (Math.abs(jsStats.averageTime - nativeStats.averageTime) /
      Math.max(jsStats.averageTime, nativeStats.averageTime)) *
    100;

  return {
    testName,
    iterations,
    totalRuns: runs,
    native: nativeStats,
    javascript: jsStats,
    comparison: {
      speedupFactor,
      nativeIsFaster,
      percentageDifference,
    },
  };
}

// Generate random private key for testing
function generateRandomPrivateKey(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Comprehensive benchmark suite
export async function runBenchmarkSuite(
  progressCallback?: (current: number, total: number, testName: string) => void,
): Promise<BenchmarkSuite> {
  const testCases = [
    {
      name: 'Random Key #1 (Compressed)',
      privateKey: generateRandomPrivateKey(),
      compressed: true,
      iterations: 100,
      runs: 5,
    },
    {
      name: 'Random Key #1 (Uncompressed)',
      privateKey: generateRandomPrivateKey(),
      compressed: false,
      iterations: 100,
      runs: 5,
    },
  ];

  const results: BenchmarkResult[] = [];
  const totalTests = testCases.length;

  for (let i = 0; i < testCases.length; i++) {
    const testCase = testCases[i];

    if (!testCase) {
      continue;
    }

    if (progressCallback) {
      progressCallback(i + 1, totalTests, testCase.name);
    }

    const result = await runSingleBenchmark(
      testCase.name,
      testCase.privateKey,
      testCase.compressed,
      testCase.iterations,
      testCase.runs,
    );

    results.push(result);

    // Small delay between test cases
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  // Calculate summary statistics
  const nativeWins = results.filter((r) => r.comparison.nativeIsFaster).length;
  const jsWins = results.filter((r) => !r.comparison.nativeIsFaster).length;
  const averageSpeedup =
    results.reduce((sum, r) => sum + r.comparison.speedupFactor, 0) /
    results.length;
  const totalNativeTime = results.reduce(
    (sum, r) => sum + r.native.totalTime,
    0,
  );
  const totalJsTime = results.reduce(
    (sum, r) => sum + r.javascript.totalTime,
    0,
  );

  // Calculate overall IOPS
  const totalNativeOperations = results.reduce(
    (sum, r) => sum + r.iterations * r.totalRuns,
    0,
  );
  const totalJsOperations = results.reduce(
    (sum, r) => sum + r.iterations * r.totalRuns,
    0,
  );
  const overallIopsNative =
    totalNativeTime > 0 ? (totalNativeOperations / totalNativeTime) * 1000 : 0;
  const overallIopsJs =
    totalJsTime > 0 ? (totalJsOperations / totalJsTime) * 1000 : 0;

  return {
    results,
    summary: {
      totalTests,
      nativeWins,
      jsWins,
      averageSpeedup,
      totalNativeTime,
      totalJsTime,
      overallIopsNative,
      overallIopsJs,
    },
  };
}
