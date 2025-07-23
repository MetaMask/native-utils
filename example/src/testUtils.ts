export interface TestResult {
  name: string;
  success: boolean;
  message: string;
  duration?: number;
}

/**
 * Convert hex string to Uint8Array
 * Handles both '0x' prefixed and plain hex strings
 */
export function hexToUint8Array(hex: string): Uint8Array {
  // Remove 0x prefix if present
  const cleanHex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;

  // Ensure even length
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }

  return bytes;
}

/**
 * Convert Uint8Array to hex string
 * @param bytes - The bytes to convert
 * @param withPrefix - Whether to include '0x' prefix (default: true)
 */
export function uint8ArrayToHex(bytes: Uint8Array, withPrefix: boolean = true): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  
  return withPrefix ? '0x' + hex : hex;
}

/**
 * Convert UTF-8 string to Uint8Array
 */
export function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Truncate array to specified length
 */
export function truncate(arr: Uint8Array, length?: number): Uint8Array {
  if (length === undefined) return arr;
  return arr.slice(0, length);
}

/**
 * Repeat buffer n times
 */
export function repeat(buf: Uint8Array, times: number): Uint8Array {
  const result = new Uint8Array(buf.length * times);
  for (let i = 0; i < times; i++) {
    result.set(buf, i * buf.length);
  }
  return result;
}

/**
 * Statistical helper functions for benchmarks
 */
export function calculateStats(timings: number[]) {
  if (timings.length === 0) {
    return {
      totalTime: 0,
      averageTime: 0,
      minTime: 0,
      maxTime: 0,
      medianTime: 0,
      standardDeviation: 0,
      iops: 0,
      timings: [],
    };
  }

  const sorted = [...timings].sort((a, b) => a - b);
  const total = timings.reduce((sum, time) => sum + time, 0);
  const average = total / timings.length;
  const min = sorted[0] ?? 0;
  const max = sorted[sorted.length - 1] ?? 0;
  const median =
    sorted.length % 2 === 0
      ? ((sorted[sorted.length / 2 - 1] ?? 0) +
          (sorted[sorted.length / 2] ?? 0)) /
        2
      : (sorted[Math.floor(sorted.length / 2)] ?? 0);

  // Calculate standard deviation
  const variance =
    timings.reduce((sum, time) => sum + Math.pow(time - average, 2), 0) /
    timings.length;
  const standardDeviation = Math.sqrt(variance);

  // Calculate IOPS (operations per second)
  const iops = average > 0 ? 1000 / average : 0;

  return {
    totalTime: total,
    averageTime: average,
    minTime: min,
    maxTime: max,
    medianTime: median,
    standardDeviation: standardDeviation,
    iops: iops,
    timings: timings,
  };
}
