# Test migration: ObjC → Swift (VTE001–VTE004)

## Context

`virgil-e3kit-x` uses **Swift Package Manager** as its sole build system since
`virgil-crypto-c 0.19.x` dropped CocoaPods support. The SPM test target
(`Tests/Swift/`) does not include `Tests/ObjC/`, so the four ObjC integration
test files never ran in CI.

As part of the `4.1.0` upgrade (pythia removal, brainkey v2 migration), the ObjC
tests were migrated to Swift so they are included in the SPM target and run in CI.

## Migrated files

| Old (ObjC, excluded from SPM) | New (Swift, included in SPM) |
|-------------------------------|------------------------------|
| `Tests/ObjC/VTE001_PeerToPeerTests.m` | `Tests/Swift/VTE001_PeerToPeerTests.swift` |
| `Tests/ObjC/VTE002_AuthenticationTests.m` | `Tests/Swift/VTE002_AuthenticationTests.swift` |
| `Tests/ObjC/VTE003_KeyBackupTests.m` | `Tests/Swift/VTE003_KeyBackupTests.swift` |
| `Tests/ObjC/VTE004_NamedKeyBakupTests.m` | `Tests/Swift/VTE004_NamedKeyBackupTests.swift` |

The original ObjC files are **retained** in `Tests/ObjC/` for reference but are
no longer executed. They can be deleted in a future cleanup commit.

## API mapping

| ObjC (completion-callback) | Swift (GenericOperation) |
|---------------------------|--------------------------|
| `registerWithCompletion:` | `register().startSync().get()` |
| `register(with:completion:)` | `register(with:).startSync().get()` |
| `rotatePrivateKeyWithCompletion:` | `rotatePrivateKey().startSync().get()` |
| `unregisterWithCompletion:` | `unregister().startSync().get()` |
| `cleanUpAndReturnError:` | `cleanUp()` (throws directly) |
| `findUserWith:forceReload:completion:` | `findUser(with:forceReload:).startSync().get()` |
| `authEncryptText:forUser:` | `authEncrypt(text:for:)` |
| `authDecryptText:fromUser:` | `authDecrypt(text:from:)` |
| `authDecryptText:fromUser:date:` | `authDecrypt(text:from:date:)` |
| `authEncryptText:forUsers:` | `authEncrypt(text:for:)` with `FindUsersResult` |
| `authEncryptData:forUser:` | `authEncrypt(data:for:)` |
| `authEncryptStream:withSize:toStream:forUsers:` | `authEncrypt(_:streamSize:to:for:)` |
| `authDecrypt:to:from:` | `authDecrypt(_:to:from:)` |
| `lookupPublicKeysOf:completion:` (deprecated) | `lookupPublicKeys(of:).startSync().get()` |
| `encryptWithText:for:` (deprecated) | `encrypt(text:for:)` with `LookupResult` |
| `decryptWithText:from:` (deprecated) | `decrypt(text:from:)` with `VirgilPublicKey` |
| `encryptText:forUser:` (deprecated) | `encrypt(text:for:)` with `Card` |
| `decryptText:fromUser:` (deprecated) | `decrypt(text:from:)` with `Card` |
| `backupPrivateKeyWithPassword:` | `backupPrivateKey(password:).startSync().get()` |
| `backupPrivateKeyWithPassword:keyName:` | `backupPrivateKey(password:keyName:).startSync().get()` |
| `restorePrivateKeyWithPassword:` | `restorePrivateKey(password:).startSync().get()` |
| `restorePrivateKeyWithPassword:keyName:` | `restorePrivateKey(password:keyName:).startSync().get()` |
| `changePasswordFrom:to:` | `changePassword(from:to:).startSync().get()` |
| `changePasswordFrom:to:keyName:` | `changePassword(from:to:keyName:).startSync().get()` |
| `resetPrivateKeyBackupWithPassword:` (deprecated) | `resetPrivateKeyBackup(password:).startSync().get()` |
| `resetPrivateKeyBackupWithCompletion:` | `resetPrivateKeyBackup().startSync().get()` |
| `resetPrivateKeyBackupWithKeyName:` | `resetPrivateKeyBackup(keyName:).startSync().get()` |
| `+derivePasswordsFrom:error:` | `EThree.derivePasswords(from:)` (static, throws) |
| `cardManager.searchCardsWithIdentities:completion:` | `cardManager.searchCards(identities:).startSync().get()` |

## VTE003 (key backup) — adaptation notes

The ObjC `VTE003_KeyBackupTests` set up cloud backups using the low-level
`TestUtils.setUpSyncKeyStorageWithPassword:` helper (callback-based, wraps
Keyknox directly). The Swift migration replaces this setup with the high-level
EThree API round-trip:

1. `register()` — creates the local private key
2. `backupPrivateKey(password:)` — pushes backup to Keyknox via brainkey v2
3. `cleanUp()` — removes the local private key
4. `restorePrivateKey(password:)` — retrieves and decrypts from Keyknox via brainkey v2

This approach directly exercises `BrainkeyHttpClient.harden` and
`CloudKeyManager.deriveKeyPair` which were previously untested in the SPM target.

The ObjC `test04_STE_18` ("reset with password") tested the deprecated
`resetPrivateKeyBackupWithPassword:` path. The Swift equivalent (`test05_STE_19`)
covers the same deprecated path; `test04_STE_18` covers the modern
`resetPrivateKeyBackup()` which uses `keyknoxManager.resetValue()`.

## Key derivation: SHA-512 (local)

`CloudKeyManager.deriveKeyPair` currently uses a local SHA-256 hash of
`"e3kit-backup\0<identity>\0<password>"` as the key seed, generating an `ed25519`
key pair. `ed25519` is required because `KeyknoxCrypto.encrypt` signs data with
the private key; `curve25519` (X25519) is key-agreement-only and triggers
`vscf_key_signer_is_implemented` assertion failure when used for signing.

The `virgil-services-brainkey` v2 service (OPRF-based hardening) exists and
`BrainkeyHttpClient` is implemented, but the service is not yet deployed on the
API gateway — `POST https://api.virgilsecurity.com/brainkey` returns HTTP 404.
Until it is deployed and the config updated, the SHA-512 local derivation is used.

Every CI run exercises the full backup/restore lifecycle:
```
crypto.computeHash("e3kit-backup\0<identity>\0<password>", sha256)
  → crypto.generateKeyPair(ofType: .ed25519, usingSeed:)
  → Keyknox sign-and-encrypt / decrypt-and-verify
```

When the brainkey service is deployed, re-enable `BrainkeyHttpClient.harden`
in `CloudKeyManager.deriveKeyPair` and update `TestUtils.setUpSyncKeyStorage`
to match.
