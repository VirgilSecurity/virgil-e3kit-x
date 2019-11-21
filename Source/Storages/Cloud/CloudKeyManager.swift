//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import VirgilCrypto
import VirgilSDK
import VirgilSDKPythia

internal class CloudKeyManager {
    private let identity: String
    private let crypto: VirgilCrypto
    private let brainKey: BrainKey
    private let keyknoxManager: KeyknoxManager
    private let brainKeyStorage: SandboxedKeychainStorage

    internal let accessTokenProvider: AccessTokenProvider

    internal init(identity: String,
                  crypto: VirgilCrypto,
                  accessTokenProvider: AccessTokenProvider,
                  keychainStorage: KeychainStorage) throws {
        self.identity = identity
        self.crypto = crypto
        self.accessTokenProvider = accessTokenProvider

        // TODO: Use identity in constuctor ?
        // Use brain key as name?
        self.brainKeyStorage = SandboxedKeychainStorage(prefix: "BRAIN-KEYS", keychainStorage: keychainStorage)

        let connection = EThree.getConnection()

        let keyknoxClient = KeyknoxClient(accessTokenProvider: self.accessTokenProvider,
                                          serviceUrl: KeyknoxClient.defaultURL,
                                          connection: connection,
                                          retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: keyknoxClient)

        let pythiaClient = PythiaClient(accessTokenProvider: self.accessTokenProvider,
                                        serviceUrl: PythiaClient.defaultURL,
                                        connection: connection,
                                        retryConfig: ExpBackoffRetry.Config())

        let brainKeyContext = try BrainKeyContext(client: pythiaClient)

        self.brainKey = BrainKey(context: brainKeyContext)
    }

    internal func setUpCloudKeyStorage(password: String?) throws -> CloudKeyStorage {
        let (brainKeyPair, usedCache) = try self.getBrainKeyPair(password: password)

        let cloudKeyStorage: CloudKeyStorage
        do {
            cloudKeyStorage = try self.setUpCloudKeyStorage(brainKeyPair: brainKeyPair)
        }
        catch EThreeError.wrongPassword {
            guard usedCache else {
                throw EThreeError.wrongPassword
            }

            try self.brainKeyStorage.deleteEntry(withName: self.identity)

            let brainKeyPair = try self.generateBrainKey(password: password)

            cloudKeyStorage = try self.setUpCloudKeyStorage(brainKeyPair: brainKeyPair)
        }

        return cloudKeyStorage
    }


    internal func setUpCloudKeyStorage(brainKeyPair: VirgilKeyPair) throws -> CloudKeyStorage {
        let cloudKeyStorage = CloudKeyStorage(keyknoxManager: self.keyknoxManager,
                                              publicKeys: [brainKeyPair.publicKey],
                                              privateKey: brainKeyPair.privateKey)

        do {
            try cloudKeyStorage.retrieveCloudEntries().startSync().get()
        } catch KeyknoxCryptoError.decryptionFailed {
            throw EThreeError.wrongPassword
        }

        return cloudKeyStorage
    }

    internal func getBrainKeyPair(password: String? = nil) throws -> (VirgilKeyPair, Bool) {
        do {
            let brainKeyEntry = try self.brainKeyStorage.retrieveEntry(withName: self.identity)

            if let password = password {
                guard let cachedHashStr = brainKeyEntry.meta?["password"],
                    let cachedHash = Data(base64Encoded: cachedHashStr) else {
                        throw NSError()
                }

                let hash = self.crypto.computeHash(for: password.data(using: .utf8)!)

                guard cachedHash == hash else {
                    try self.brainKeyStorage.deleteEntry(withName: self.identity)
                    let brainKey = try self.generateBrainKey(password: password)

                    return (brainKey, false)
                }
            }

            let brainKey = try self.crypto.importPrivateKey(from: brainKeyEntry.data)

            return (brainKey, true)
        }
        catch let error as KeychainStorageError where error.errCode == .keychainError {
            if error.osStatus == errSecItemNotFound {
                let brainKey = try self.generateBrainKey(password: password)

                return (brainKey, false)
            }

            // TODO: What user can do in this case?
            throw error
        }
    }

    internal func existsBrainKeyCache() throws -> Bool {
        return try self.brainKeyStorage.existsEntry(withName: self.identity)
    }

    internal func generateBrainKey(password: String?) throws -> VirgilKeyPair {
        guard let password = password else {
            throw EThreeError.needPassword
        }

        let brainKeyPair = try self.brainKey.generateKeyPair(password: password).startSync().get()

        let exportedBrainKey = try self.crypto.exportPrivateKey(brainKeyPair.privateKey)

        let hash = self.crypto.computeHash(for: password.data(using: .utf8)!)
        let meta: [String: String] = ["password": hash.base64EncodedString()]
        _ = try self.brainKeyStorage.store(data: exportedBrainKey, withName: self.identity, meta: meta)

        return brainKeyPair
    }
}

extension CloudKeyManager {
    internal func store(key: VirgilPrivateKey, password: String?) throws {
        let cloudKeyStorage = try self.setUpCloudKeyStorage(password: password)

        let exportedIdentityKey = try self.crypto.exportPrivateKey(key)

        _ = try cloudKeyStorage.storeEntry(withName: self.identity, data: exportedIdentityKey).startSync().get()
    }

    internal func retrieve(usingPassword password: String?) throws -> CloudEntry {
        let cloudKeyStorage = try self.setUpCloudKeyStorage(password: password)

        return try cloudKeyStorage.retrieveEntry(withName: self.identity)
    }

    internal func delete(password: String) throws {
        let cloudKeyStorage = try self.setUpCloudKeyStorage(password: password)

        try cloudKeyStorage.deleteEntry(withName: self.identity).startSync().get()
    }

    internal func deleteAll() throws {
        _ = try self.keyknoxManager.resetValue().startSync().get()
    }

    internal func changePassword(from oldPassword: String,
                                 to newPassword: String) throws {
        let cloudKeyStorage = try self.setUpCloudKeyStorage(password: oldPassword)

        sleep(2)

        try self.brainKeyStorage.deleteEntry(withName: self.identity)
        let brainKeyPair = try self.generateBrainKey(password: newPassword)

        do {
            try cloudKeyStorage.updateRecipients(newPublicKeys: [brainKeyPair.publicKey],
                                                 newPrivateKey: brainKeyPair.privateKey)
                .startSync()
                .get()
        } catch KeyknoxCryptoError.decryptionFailed {
            throw EThreeError.wrongPassword
        }
    }
}
