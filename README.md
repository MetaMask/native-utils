# MetaMask Native Utils

This is a collection of native utils (mostly crypto functions) for MetaMask mobile app implemented using Nitro modules and C++.

## Features

- Super fast crypto functions (e.g. `keccak256`, `secp256k1`, `hmacSha512`)
- It uses [official Bitcoin Core library](https://github.com/bitcoin-core/secp256k1) for secp256k1
- More than 300 tests to ensure correctness and compatibility with JS implementations (test cases are directly ported from `@noble/secp256k1`, `@noble/hashes`, `@ethereumjs/util`)
- Benchmarks are included to show the performance improvements

## Performance comparison 🚀

Device: Pixel 4a 5G (Android 14)

- `getPublicKey` - ~133x faster than `@noble/secp256k1` (1068ms => 8ms)
- `hmacSha512` - ~144x faster than `@noble/hashes`
- `pubToAddress` - ~110x faster than `@ethereumjs/util`
- `keccak256` - ~140x faster than `@noble/hashes`

Take benchmarks with a grain of salt, as they are not always representative of real-world performance, but even my measurements in real mobile app showed massive performance improvements.

## Installation

`yarn add @metamask/native-utils`

## Usage

```typescript
import {
  keccak256,
  getPublicKey,
  hmacSha512,
  pubToAddress,
  multiply,
} from '@metamask/native-utils';

// Basic arithmetic (demo function)
const result = multiply(3, 7); // 21

// Keccak-256 hashing - replaces @noble/hashes/sha3.keccak_256
// Accepts multiple input types for maximum flexibility
const hash1 = keccak256('deadbeef'); // from hex string
const hash2 = keccak256(new Uint8Array([0xde, 0xad, 0xbe, 0xef])); // from Uint8Array
const hash3 = keccak256([222, 173, 190, 239]); // from number array

// Generate secp256k1 public keys - replaces @noble/secp256k1.getPublicKey
const privateKey =
  '0000000000000000000000000000000000000000000000000000000000000001';
const compressedPubKey = getPublicKey(privateKey, true); // 33 bytes compressed
const uncompressedPubKey = getPublicKey(privateKey, false); // 65 bytes uncompressed

// Also supports Uint8Array and bigint private keys (same API as @noble/secp256k1)
const privateKeyBytes = new Uint8Array(32).fill(1, 31); // private key as bytes
const privateKeyBigInt = 1n; // private key as bigint
const pubKeyFromBytes = getPublicKey(privateKeyBytes);
const pubKeyFromBigInt = getPublicKey(privateKeyBigInt);

// HMAC-SHA512 authentication - replaces @noble/hashes/hmac + @noble/hashes/sha2
const key = new Uint8Array(32).fill(0x01);
const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
const hmacResult = hmacSha512(key, data); // 64-byte result

// Convert public key to Ethereum address - replaces @ethereumjs/util.publicToAddress
const publicKey = new Uint8Array([
  // 64-byte public key (without 0x04 prefix)
  0x3a, 0x44, 0x3d, 0x83, 0x81, 0xa6, 0x79, 0x8a, 0x70, 0xc6, 0xff, 0x93,
  // ... rest of the bytes
]);
const address = pubToAddress(publicKey); // 20-byte Ethereum address

// For SEC1-encoded public keys (with 0x04 prefix), use sanitize option
const sec1PublicKey = new Uint8Array([
  0x04, // SEC1 prefix
  0x3a,
  0x44,
  0x3d,
  0x83,
  0x81,
  0xa6,
  0x79,
  0x8a,
  0x70,
  0xc6,
  0xff,
  0x93,
  // ... rest of the bytes
]);
const addressFromSec1 = pubToAddress(sec1PublicKey, true); // sanitize = true
```

## Contributing

### Setup

- Install the current LTS version of [Node.js](https://nodejs.org)
  - If you are using [nvm](https://github.com/creationix/nvm#installation) (recommended) running `nvm install` will install the latest version and running `nvm use` will automatically choose the right node version for you.
- Install [Yarn](https://yarnpkg.com) v4 via [Corepack](https://github.com/nodejs/corepack?tab=readme-ov-file#how-to-install)
- Run `yarn install` to install dependencies and run any required post-install scripts
- Run `git submodule update --init --recursive` to initialize the submodules

### Running the example app

- Go into the `example` directory
- Run `yarn ios` to run the example app on iOS
- Run `yarn android` to run the example app on Android

### Running benchmarks

To run the benchmarks, it's recommended to run the example in release mode.

- Run `yarn android:release` to run the example app on Android
- Run `yarn ios:release` to run the example app on iOS

### Testing and Linting

All testing should be done using Example app.

### Release & Publishing

The project follows the same release process as the other libraries in the MetaMask organization. The GitHub Actions [`action-create-release-pr`](https://github.com/MetaMask/action-create-release-pr) and [`action-publish-release`](https://github.com/MetaMask/action-publish-release) are used to automate the release process; see those repositories for more information about how they work.

1. Choose a release version.
   - The release version should be chosen according to SemVer. Analyze the changes to see whether they include any breaking changes, new features, or deprecations, then choose the appropriate SemVer version. See [the SemVer specification](https://semver.org/) for more information.

2. If this release is backporting changes onto a previous release, then ensure there is a major version branch for that version (e.g. `1.x` for a `v1` backport release).
   - The major version branch should be set to the most recent release with that major version. For example, when backporting a `v1.0.2` release, you'd want to ensure there was a `1.x` branch that was set to the `v1.0.1` tag.

3. Trigger the [`workflow_dispatch`](https://docs.github.com/en/actions/reference/events-that-trigger-workflows#workflow_dispatch) event [manually](https://docs.github.com/en/actions/managing-workflow-runs/manually-running-a-workflow) for the `Create Release Pull Request` action to create the release PR.
   - For a backport release, the base branch should be the major version branch that you ensured existed in step 2. For a normal release, the base branch should be the main branch for that repository (which should be the default value).
   - This should trigger the [`action-create-release-pr`](https://github.com/MetaMask/action-create-release-pr) workflow to create the release PR.

4. Update the changelog to move each change entry into the appropriate change category ([See here](https://keepachangelog.com/en/1.0.0/#types) for the full list of change categories, and the correct ordering), and edit them to be more easily understood by users of the package.
   - Generally any changes that don't affect consumers of the package (e.g. lockfile changes or development environment changes) are omitted. Exceptions may be made for changes that might be of interest despite not having an effect upon the published package (e.g. major test improvements, security improvements, improved documentation, etc.).
   - Try to explain each change in terms that users of the package would understand (e.g. avoid referencing internal variables/concepts).
   - Consolidate related changes into one change entry if it makes it easier to explain.
   - Run `yarn auto-changelog validate --rc` to check that the changelog is correctly formatted.

5. Review and QA the release.
   - If changes are made to the base branch, the release branch will need to be updated with these changes and review/QA will need to restart again. As such, it's probably best to avoid merging other PRs into the base branch while review is underway.

6. Squash & Merge the release.
   - This should trigger the [`action-publish-release`](https://github.com/MetaMask/action-publish-release) workflow to tag the final release commit and publish the release on GitHub.

7. Publish the release on npm.
   - Wait for the `publish-release` GitHub Action workflow to finish. This should trigger a second job (`publish-npm`), which will wait for a run approval by the [`npm publishers`](https://github.com/orgs/MetaMask/teams/npm-publishers) team.
   - Approve the `publish-npm` job (or ask somebody on the npm publishers team to approve it for you).
   - Once the `publish-npm` job has finished, check npm to verify that it has been published.
