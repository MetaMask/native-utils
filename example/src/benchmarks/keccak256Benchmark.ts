import { keccak256 } from '@metamask/native-utils';
import { keccak_256 } from '@noble/hashes/sha3';
import { hexToUint8Array, calculateStats, utf8ToBytes, repeat } from '../testUtils';

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

// Benchmark small string input
export async function benchmarkSmallString(): Promise<BenchmarkResult> {
  const testInput = 'abc';
  const testInputBytes = utf8ToBytes(testInput);

  return benchmarkFunction(
    'Small String ("abc")',
    () => keccak256(testInputBytes),
    () => keccak_256(testInputBytes),
    2000
  );
}



// Benchmark 32-byte private key
export async function benchmarkPrivateKey(): Promise<BenchmarkResult> {
  const privateKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  return benchmarkFunction(
    '32-byte Private Key (hex string)',
    () => keccak256(privateKeyHex),
    () => keccak_256(hexToUint8Array('0x' + privateKeyHex)),
    1500
  );
}

// Benchmark 64-byte public key
export async function benchmarkPublicKey(): Promise<BenchmarkResult> {
  const publicKeyBytes = hexToUint8Array(
    '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  );

  return benchmarkFunction(
    '64-byte Public Key (Uint8Array)',
    () => keccak256(publicKeyBytes),
    () => keccak_256(publicKeyBytes),
    1500
  );
}

// Benchmark medium-size input (BIP32 seed)
export async function benchmarkBIP32Seed(): Promise<BenchmarkResult> {
  const seedPhrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seedBytes = utf8ToBytes(seedPhrase);

  return benchmarkFunction(
    'BIP32 Seed Phrase (96 bytes)',
    () => keccak256(seedBytes),
    () => keccak_256(seedBytes),
    1000
  );
}

// Benchmark transaction data
export async function benchmarkTransactionData(): Promise<BenchmarkResult> {
  // Simulate a typical Ethereum transaction payload
  const txData = new Uint8Array(Array.from({ length: 256 }, (_, i) => i % 256));

  return benchmarkFunction(
    'Transaction Data (256 bytes)',
    () => keccak256(txData),
    () => keccak_256(txData),
    1000
  );
}



// Benchmark realistic ETH address checksumming (EIP-55)
export async function benchmarkETHAddressChecksum(): Promise<BenchmarkResult> {
  // Real Ethereum addresses from various sources
  const addresses = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    '0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640',
    '0xA0b86991c04FF420c0d2630C4CF54B8aE7FB6D93d',
    '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    '0x6B175474E89094C44Da98b954EedeAC495271d0F',
    '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
    '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
    '0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0',
    '0x3845badAde8e6dDD04A9f89e6A9D2A1ad2b2a6EF',
    '0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE',
    '0x4Fabb145d64652a948D72533023f6E7A623C7C53',
  ];

  // Native implementation of EIP-55 checksum
  const checksumAddressNative = (address: string): string => {
    const cleanAddr = address.toLowerCase().replace('0x', '');
    const hash = keccak256(utf8ToBytes(cleanAddr));
    
    let checksumAddress = '0x';
    for (let i = 0; i < cleanAddr.length; i++) {
      const char = cleanAddr[i];
      if (!char) continue;
      
      if (char >= '0' && char <= '9') {
        checksumAddress += char;
      } else {
        // Use the hash byte to determine case
        const hashByteIndex = Math.floor(i / 2);
        const hashByte = hash[hashByteIndex];
        if (hashByte === undefined) continue;
        
        const nibble = i % 2 === 0 ? (hashByte >> 4) & 0xF : hashByte & 0xF;
        checksumAddress += nibble >= 8 ? char.toUpperCase() : char;
      }
    }
    return checksumAddress;
  };

  // Noble implementation of EIP-55 checksum
  const checksumAddressNoble = (address: string): string => {
    const cleanAddr = address.toLowerCase().replace('0x', '');
    const hash = keccak_256(utf8ToBytes(cleanAddr));
    
    let checksumAddress = '0x';
    for (let i = 0; i < cleanAddr.length; i++) {
      const char = cleanAddr[i];
      if (!char) continue;
      
      if (char >= '0' && char <= '9') {
        checksumAddress += char;
      } else {
        // Use the hash byte to determine case
        const hashByteIndex = Math.floor(i / 2);
        const hashByte = hash[hashByteIndex];
        if (hashByte === undefined) continue;
        
        const nibble = i % 2 === 0 ? (hashByte >> 4) & 0xF : hashByte & 0xF;
        checksumAddress += nibble >= 8 ? char.toUpperCase() : char;
      }
    }
    return checksumAddress;
  };

  return benchmarkFunction(
    'ETH Address Checksum (EIP-55)',
    () => {
      // Process all addresses with native implementation and return last result
      let result = '';
      addresses.forEach(addr => {
        result = checksumAddressNative(addr);
      });
      return utf8ToBytes(result);
    },
    () => {
      // Process all addresses with Noble implementation and return last result
      let result = '';
      addresses.forEach(addr => {
        result = checksumAddressNoble(addr);
      });
      return utf8ToBytes(result);
    },
    200 // Lower iterations since we're doing more work per iteration
  );
}

// Benchmark hex string vs bytes comparison
export async function benchmarkHexVsBytes(): Promise<BenchmarkResult> {
  const hexString = '0123456789abcdef'.repeat(8); // 64 bytes as hex (no 0x prefix)
  const bytesInput = hexToUint8Array('0x' + hexString);

  const nativeTimes: number[] = [];
  const jsTimes: number[] = [];
  const iterations = 1500;

  // Warm up
  for (let i = 0; i < 10; i++) {
    keccak256(hexString);
    keccak256(bytesInput);
  }

  // Benchmark native hex input
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    keccak256(hexString);
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  await new Promise((resolve) => setTimeout(resolve, 10));

  // Benchmark native bytes input
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    keccak256(bytesInput);
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
    testName: 'Hex String vs Bytes Input (Native)',
    native: nativeStats,
    javascript: jsStats,
    comparison: {
      speedupFactor,
      nativeIsFaster,
      performanceGain,
    },
  };
}

// Format benchmark results for display
export function formatKeccak256BenchmarkResults(results: BenchmarkResult[]): string {
  let output = '\n🔍 Keccak256 Benchmark Results\n';
  output += '=' .repeat(50) + '\n\n';

  let totalNativeTime = 0;
  let totalJsTime = 0;
  let nativeWins = 0;

  for (const result of results) {
    totalNativeTime += result.native.totalTime;
    totalJsTime += result.javascript.totalTime;
    if (result.comparison.nativeIsFaster) nativeWins++;

    output += `📊 ${result.testName}\n`;
    output += `   🚀 Native: ${result.native.averageTime.toFixed(3)}ms avg | ${result.native.iops.toFixed(0)} ops/sec\n`;
    output += `   📜 Noble: ${result.javascript.averageTime.toFixed(3)}ms avg | ${result.javascript.iops.toFixed(0)} ops/sec\n`;
    output += `   ⚡ Result: ${result.comparison.speedupFactor.toFixed(2)}x ${result.comparison.nativeIsFaster ? 'faster' : 'slower'} (${result.comparison.performanceGain.toFixed(1)}% gain)\n`;
    output += `   📈 Range: ${result.native.minTime.toFixed(3)}-${result.native.maxTime.toFixed(3)}ms (Native) | ${result.javascript.minTime.toFixed(3)}-${result.javascript.maxTime.toFixed(3)}ms (Noble)\n\n`;
  }

  output += `📊 Summary: ${nativeWins}/${results.length} tests won by native\n`;
  output += `⚡ Average speedup: ${(totalJsTime / totalNativeTime).toFixed(2)}x\n`;
  output += `🏆 Overall performance: ${((totalJsTime - totalNativeTime) / totalJsTime * 100).toFixed(1)}% improvement\n`;

  return output;
}

// Run all keccak256 benchmarks
export async function runAllKeccak256Benchmarks(): Promise<BenchmarkResult[]> {
  console.log('🚀 Starting Keccak256 benchmarks...');
  
  const benchmarks = [
    { name: 'Small String', fn: benchmarkSmallString },
    { name: 'Private Key', fn: benchmarkPrivateKey },
    { name: 'Public Key', fn: benchmarkPublicKey },
    { name: 'BIP32 Seed', fn: benchmarkBIP32Seed },
    { name: 'Transaction Data', fn: benchmarkTransactionData },
    { name: 'ETH Address Checksum', fn: benchmarkETHAddressChecksum },
    { name: 'Hex vs Bytes', fn: benchmarkHexVsBytes },
  ];

  const results: BenchmarkResult[] = [];
  
  for (let i = 0; i < benchmarks.length; i++) {
    const benchmark = benchmarks[i]!;
    console.log(`📊 Running ${benchmark.name} benchmark... (${i + 1}/${benchmarks.length})`);
    const result = await benchmark.fn();
    results.push(result);
    
    // Small delay between benchmarks
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  console.log('✅ All Keccak256 benchmarks completed!');
  console.log(formatKeccak256BenchmarkResults(results));
  
  return results;
} 