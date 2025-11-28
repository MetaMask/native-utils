# @metamask/native-utils

This library provides mostly cryptographic functions implemented in C++ for React Native. These functions are intended to polyfill of libraries like [@noble/hashes](https://www.npmjs.com/package/@noble/hashes), [@noble/curves](https://www.npmjs.com/package/@noble/curves), [@ethereumjs/util](https://github.com/ethereumjs/ethereumjs-monorepo), [js-sha3](https://www.npmjs.com/package/js-sha3), etc.

## Installation

`yarn add @metamask/native-utils react-native-nitro-modules`

## Performance

Because this library is running C++ code, it is significantly faster than the JavaScript implementations of the same functions. Here are some benchmarks (running on a mobile device):

| Operation                    | Native                | JavaScript            | Speedup  |
| :--------------------------- | :-------------------- | :-------------------- | :------- |
| **secp256k1 Key Generation** | 1.135 ms (881 ops/s)  | 269.55 ms (4 ops/s)   | **237x** |
| **Ed25519 Key Generation**   | 0.014 ms (73k ops/s)  | 1.79 ms (560 ops/s)   | **130x** |
| **Public Key to Address**    | 0.002 ms (599k ops/s) | 0.316 ms (3.1k ops/s) | **189x** |
| **Keccak256** (32 bytes)     | 0.002 ms (402k ops/s) | 0.297 ms (3.3k ops/s) | **120x** |
| **HMAC-SHA512**              | 0.007 ms (145k ops/s) | 0.621 ms (1.6k ops/s) | **90x**  |

## Usage

```typescript
import {
  getPublicKey,
  getPublicKeyEd25519,
  keccak256,
  pubToAddress,
  hmacSha512,
} from '@metamask/native-utils';

// Generate secp256k1 public key (compressed by default)
const privateKey =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const publicKey = getPublicKey(privateKey);

// Generate Ed25519 public key
const ed25519PrivKey = 'a'.repeat(64); // 32 bytes as hex
const ed25519PubKey = getPublicKeyEd25519(ed25519PrivKey);

// Compute Keccak-256 hash
const hash = keccak256('hello');

// Get Ethereum address from public key
const uncompressedPubKey = getPublicKey(privateKey, false);
const ethAddress = pubToAddress(uncompressedPubKey);

// Compute HMAC-SHA512
const key = new Uint8Array([1, 2, 3]);
const data = new Uint8Array([4, 5, 6]);
const mac = hmacSha512(key, data);
```

## API

### `getPublicKey(privateKey, isCompressed?)`

Generate secp256k1 public key. Matches `@noble/secp256k1` API.

- `privateKey: string | Uint8Array | bigint` — hex string, bytes, or bigint
- `isCompressed?: boolean` — compressed (33 bytes) or uncompressed (65 bytes). Default: `true`
- **Returns:** `Uint8Array`

### `getPublicKeyEd25519(privateKey)`

Generate Ed25519 public key. Matches `@noble/curves` ed25519 API.

- `privateKey: string | Uint8Array` — 32-byte key as hex (64 chars) or bytes
- **Returns:** `Uint8Array` (32 bytes)

### `keccak256(data)`

Compute Keccak-256 hash. Matches `@noble/hashes` keccak_256 API.

- `data: string | number[] | ArrayBuffer | Uint8Array` — strings are UTF-8 encoded
- **Returns:** `Uint8Array` (32 bytes)

### `pubToAddress(pubKey, sanitize?)`

Get Ethereum address from public key. Matches `@ethereumjs/util` pubToAddress API.

- `pubKey: Uint8Array` — uncompressed public key (or any format if sanitize enabled)
- `sanitize?: boolean` — accept other key formats. Default: `false`
- **Returns:** `Uint8Array` (20 bytes)

### `hmacSha512(key, data)`

Compute HMAC-SHA512.

- `key: Uint8Array` — HMAC key
- `data: Uint8Array` — data to authenticate
- **Returns:** `Uint8Array` (64 bytes)

## Contributing

### Setup

- Install the current LTS version of [Node.js](https://nodejs.org)
  - If you are using [nvm](https://github.com/creationix/nvm#installation) (recommended) running `nvm install` will install the latest version and running `nvm use` will automatically choose the right node version for you.
- Install [Yarn](https://yarnpkg.com) v4 via [Corepack](https://github.com/nodejs/corepack?tab=readme-ov-file#how-to-install)
- Run `yarn install` to install dependencies.
- Run `yarn build` to build the library and mostly to generate the Nitrogen specs (it's enought to just run `yarn nitrogen`)

### Running the example app

1. Add `"workspaces": ["example"]` to your root `package.json` and run `yarn install` in the root directory. This is necessary because if "workspaces" are field is defined, it's not possible to publish the package. Then run `yarn install`.
2. Run `yarn android` to build the Android app.
3. Run `yarn android:release` to build the Android app in release mode. (strongly recommended for benchmarking).

### Testing and Linting

Because this library is running native code is not possible to run tests using Jest. You need to run the example app and run the tests manually.

### Nitro

This library is using Nitro modules bridge JS to C++ code. Most important thing to know is that when you change/add/remove any exposed function in `NativeUtils.nitro.ts` file, you need to run `yarn nitrogen` to regenerate the Nitrogen specs (in `nitrogen/generated` directory).

Please follow the [Nitro Modules documentation](https://nitro.margelo.com/docs/what-is-nitro) to learn more.

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
