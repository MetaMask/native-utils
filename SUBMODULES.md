# Submodule Dependencies

This file documents the exact commit hashes for all Git submodules used in this project.

## cpp/secp256k1

- **Repository**: https://github.com/bitcoin-core/secp256k1.git
- **Pinned Commit**: `a660a4976efe880bae7982ee410b9e0dc59ac983`
- **Version**: v0.7.0
- **Date Pinned**: 2025-09-12
- **Reason**: Latest stable commit with security fixes
- **⚠️ WARNING**: Do not update without security review - affects cryptographic operations

## cpp/botan

- **Repository**: https://github.com/randombit/botan.git
- **Pinned Commit**: `07e1cfe0a06b224bbb37ad534736924931184246`
- **Version**: v3.9.0
- **Date Pinned**: 2025-09-18
- **Reason**: Latest stable release
- **⚠️ WARNING**: Do not update without security review - affects cryptographic operations

## Updating Submodules

To update a submodule:

1. Navigate to the submodule directory: `cd cpp/<submodule-name>`
2. Fetch latest changes: `git fetch origin`
3. Check out desired commit: `git checkout <new-commit-hash>`
4. Return to root: `cd ../..`
5. Update this documentation file
6. Update scripts/verify-submodules.sh with the new expected commit hash
7. Commit the changes: `git add . && git commit -m "Update <submodule-name> to <new-commit-hash>"`

## Verification

To verify current pinned commits:

```bash
git submodule status
```
