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

internal class OnlyOnUseKeyStorage: LocalKeyStorage {
    internal let identity: String
    internal let crypto: VirgilCrypto

    private let keychainStorage: KeychainStorage
    private let options: KeychainQueryOptions

    internal required init(params: LocalKeyStorageParams) throws {
        self.identity = params.identity
        self.crypto = params.crypto

        let storageParams = try params.keychainStorageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: storageParams)

        self.options = KeychainQueryOptions()

    #if os(iOS)
        self.options.biometricallyProtected = params.biometricProtection

        if let biometricPromt = params.biometricPromt {
            options.biometricPromt = biometricPromt
        }
    #endif
    }

    internal func retrieve(name: String) throws -> Data? {
        do {
            let keyEntry = try self.keychainStorage.retrieveEntry(withName: name, queryOptions: self.options)

            return keyEntry.data
        } catch let error as KeychainStorageError {
            if error.errCode == .keychainError, let osStatus = error.osStatus, osStatus == errSecItemNotFound {
                return nil
            }

            throw error
        }
    }

    internal func loadKeyPair() throws -> VirgilKeyPair? {
        var keyPair: VirgilKeyPair?
        if let data = try self.retrieve(name: self.identity) {
            keyPair = try self.crypto.importPrivateKey(from: data)
        } else {
        #if os(iOS)
            keyPair = try self.loadBackup()
        #endif
        }

        return keyPair
    }

    internal func store(data: Data) throws {
        _ = try self.keychainStorage.store(data: data,
                                           withName: self.identity,
                                           meta: nil,
                                           queryOptions: self.options)
    }

    internal func getKeyPair() throws -> VirgilKeyPair {
        guard let keyPair = try self.loadKeyPair() else {
            throw EThreeError.missingPrivateKey
        }

        return keyPair
    }

    internal func exists() throws -> Bool {
        let exists = try self.keychainStorage.existsEntry(withName: self.identity)

        #if os(iOS)
        guard exists else {
            return try self.keychainStorage.existsEntry(withName: self.backupName)
        }
        #endif

        return exists
    }

    internal func delete() throws {
        try self.keychainStorage.deleteEntry(withName: self.identity, queryOptions: self.options)
    }

    #if os(iOS)
    private var backupName: String {
        return "E3KIT-BACKUP-" + self.identity
    }

    private func store(backup data: Data) throws {
        _ = try self.keychainStorage.store(data: data,
                                           withName: self.backupName,
                                           meta: nil)
    }

    private func deleteBackup() throws {
        try self.keychainStorage.deleteEntry(withName: self.backupName)
    }

    private func loadBackup() throws -> VirgilKeyPair? {
        guard let data = try self.retrieve(name: self.backupName) else {
            return nil
        }

        try self.store(data: data)

        try self.deleteBackup()

        return try self.crypto.importPrivateKey(from: data)
    }

    internal func setBiometricProtection(to value: Bool) throws {
        guard self.options.biometricallyProtected != value else {
            return
        }

        guard try self.exists() else {
            self.options.biometricallyProtected = value
            return
        }

        let data = try self.crypto.exportPrivateKey(self.getKeyPair().privateKey)

        try self.store(backup: data)

        try self.delete()
        self.options.biometricallyProtected = value
        try self.store(data: data)

        try self.deleteBackup()
    }
    #endif
}
