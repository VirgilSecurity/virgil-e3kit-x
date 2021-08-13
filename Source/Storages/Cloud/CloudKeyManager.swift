//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

    internal let accessTokenProvider: AccessTokenProvider

    private var namedKeysRoot: String  { "e3kit" }
    private var namedKeysPath: String { "backup" }

    internal init(identity: String,
                  crypto: VirgilCrypto,
                  accessTokenProvider: AccessTokenProvider,
                  keyknoxServiceUrl: URL,
                  pythiaServiceUrl: URL) throws {
        self.identity = identity
        self.crypto = crypto
        self.accessTokenProvider = accessTokenProvider

        let connection = EThree.getConnection()

        let keyknoxClient = KeyknoxClient(accessTokenProvider: self.accessTokenProvider,
                                          serviceUrl: keyknoxServiceUrl,
                                          connection: connection,
                                          retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: keyknoxClient)

        let pythiaClient = PythiaClient(accessTokenProvider: self.accessTokenProvider,
                                        serviceUrl: pythiaServiceUrl,
                                        connection: connection,
                                        retryConfig: ExpBackoffRetry.Config())

        let brainKeyContext = try BrainKeyContext(client: pythiaClient)

        self.brainKey = BrainKey(context: brainKeyContext)
    }

    internal func setUpCloudKeyStorage(password: String) throws -> CloudKeyStorage {
        let brainKeyPair = try self.brainKey.generateKeyPair(password: password).startSync().get()

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

    private func pullKeyValue(named keyName: String, brainKeyPair: VirgilKeyPair) throws -> KeyknoxValue {
        let pullParams = KeyknoxPullParams(identity: self.identity,
                                           root: self.namedKeysRoot,
                                           path: self.namedKeysPath,
                                           key: keyName)

        let keyknoxValue = try self.keyknoxManager
            .pullValue(params: pullParams,
                       publicKeys: [brainKeyPair.publicKey],
                       privateKey: brainKeyPair.privateKey)
            .startSync()
            .get()

        return keyknoxValue
    }

    private func pushKeyValue(named keyName: String, data: Data, hash: Data?, brainKeyPair: VirgilKeyPair) throws {
        let pushParams = KeyknoxPushParams(identities: [self.identity],
                                           root: self.namedKeysRoot,
                                           path: self.namedKeysPath,
                                           key: keyName)

        _ = try self.keyknoxManager
            .pushValue(params: pushParams,
                       data: data,
                       previousHash: hash,
                       publicKeys: [brainKeyPair.publicKey],
                       privateKey: brainKeyPair.privateKey)
            .startSync()
            .get()
    }
}

extension CloudKeyManager {
    internal func store(key: VirgilPrivateKey, keyName: String?, usingPassword password: String) throws {
        if let keyName = keyName {
            try self.store(key: key, keyName: keyName, usingPassword: password)
        } else {
            try self.store(key: key, usingPassword: password)
        }
    }

    internal func retrieve(usingPassword password: String, keyName: String?) throws -> CloudEntry {
        if let keyName = keyName {
            return try self.retrieve(usingPassword: password, keyName: keyName)
        } else {
            return try self.retrieve(usingPassword: password)
        }
    }

    internal func delete(keyName: String?, password: String) throws {
        if let keyName = keyName {
            try self.delete(keyName: keyName, password: password)
        } else {
            try self.delete(password: password)
        }
    }

    internal func changePassword(from oldPassword: String,
                                 to newPassword: String,
                                 keyName: String?) throws {
        if let keyName = keyName {
            try self.changePassword(from: oldPassword, to: newPassword, keyName: keyName)
        } else {
            try self.changePassword(from: oldPassword, to: newPassword)
        }
    }


    internal func delete(keyName: String?) throws {
        if let keyName = keyName {
            try self.delete(keyName: keyName)
        } else {
            try self.deleteAll()
        }
    }
}

// MARK: Main Key

extension CloudKeyManager {
    internal func store(key: VirgilPrivateKey, usingPassword password: String) throws {
        let cloudKeyStorage = try self.setUpCloudKeyStorage(password: password)

        let exportedIdentityKey = try self.crypto.exportPrivateKey(key)

        _ = try cloudKeyStorage.storeEntry(withName: self.identity, data: exportedIdentityKey).startSync().get()
    }

    internal func retrieve(usingPassword password: String) throws -> CloudEntry {
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

        let brainKeyPair = try self.brainKey.generateKeyPair(password: newPassword).startSync().get()

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

// MARK: Named Keys

extension CloudKeyManager {
    internal func store(key: VirgilPrivateKey, keyName: String, usingPassword password: String) throws {
        let exportedIdentityKey = try self.crypto.exportPrivateKey(key)

        let brainKeyPair = try self.brainKey.generateKeyPair(password: password).startSync().get()

        let keyknoxValue = try self.pullKeyValue(named: keyName, brainKeyPair: brainKeyPair)

        guard keyknoxValue.value.isEmpty, keyknoxValue.meta.isEmpty else {
            throw CloudKeyStorageError.entryAlreadyExists
        }

        let now = Date()
        let cloudEntry = CloudEntry(name: self.identity,
                                    data: exportedIdentityKey,
                                    creationDate: now,
                                    modificationDate: now,
                                    meta: nil)

        let data = try JSONEncoder().encode(cloudEntry)

        try self.pushKeyValue(named: keyName, data: data, hash: keyknoxValue.keyknoxHash, brainKeyPair: brainKeyPair)
    }

    internal func retrieve(usingPassword password: String, keyName: String) throws -> CloudEntry {
        let brainKeyPair = try self.brainKey.generateKeyPair(password: password).startSync().get()

        do {
            let keyknoxValue = try self.pullKeyValue(named: keyName, brainKeyPair: brainKeyPair)

            return try JSONDecoder().decode(CloudEntry.self, from: keyknoxValue.value)
        }
        catch KeyknoxCryptoError.decryptionFailed {
            throw EThreeError.wrongPassword
        }
    }

    internal func delete(keyName: String) throws {
        let params = KeyknoxResetParams(root: self.namedKeysRoot, path: namedKeysPath, key: keyName)
        _ = try self.keyknoxManager.resetValue(params: params).startSync().get()
    }

    internal func changePassword(from oldPassword: String,
                                 to newPassword: String,
                                 keyName: String) throws {
        let brainKeyPair = try self.brainKey.generateKeyPair(password: oldPassword).startSync().get()

        let keyknoxValue = try self.pullKeyValue(named: keyName, brainKeyPair: brainKeyPair)

        guard keyknoxValue.value.isEmpty || keyknoxValue.meta.isEmpty else {
            throw CloudKeyStorageError.entryAlreadyExists
        }

        sleep(2)

        let newBrainKeyPair = try self.brainKey.generateKeyPair(password: newPassword).startSync().get()

        try self.pushKeyValue(named: keyName, data: keyknoxValue.value, hash: keyknoxValue.keyknoxHash, brainKeyPair: newBrainKeyPair)
    }
}
