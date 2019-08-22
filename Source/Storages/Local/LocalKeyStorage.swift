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

internal class LocalKeyStorage {
    internal let identity: String
    internal let crypto: VirgilCrypto

    private var keyPair: VirgilKeyPair?
    private let keychainStorage: KeychainStorage
    private let options: KeychainQueryOptions
    private let loadKeyStrategy: LoadKeyStrategy

    internal required init(identity: String,
                           crypto: VirgilCrypto,
                           keychainStorage: KeychainStorage,
                           loadKeyStrategy: LoadKeyStrategy,
                           options: KeychainQueryOptions = KeychainQueryOptions()) throws {
        self.identity = identity
        self.crypto = crypto
        self.keychainStorage = keychainStorage
        self.loadKeyStrategy = loadKeyStrategy
        self.options = options

        switch self.loadKeyStrategy {
        case .instant:
            self.keyPair = try self.loadKeyPair()
        case .onFirstNeed, .onlyOnUse: break
        }
    }

#if os(iOS)
    internal convenience init(identity: String,
                              crypto: VirgilCrypto,
                              keychainStorage: KeychainStorage,
                              loadKeyStrategy: LoadKeyStrategy,
                              biometricProtection: Bool,
                              biometricPromt: String? = nil) throws {
        let options = KeychainQueryOptions()
        options.biometricallyProtected = biometricProtection

        if let biometricPromt = biometricPromt {
            options.biometricPromt = biometricPromt
        }

        try self.init(identity: identity,
                      crypto: crypto,
                      keychainStorage: keychainStorage,
                      loadKeyStrategy: loadKeyStrategy,
                      options: options)
    }

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
#endif

    private func retrieve(name: String) throws -> Data? {
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

    private func loadKeyPair() throws -> VirgilKeyPair? {
        if let data = try self.retrieve(name: self.identity) {
            return try self.crypto.importPrivateKey(from: data)
        } else {
        #if os(iOS)
            return try self.loadBackup()
        #endif
        }
    }

    private func existsEntry() throws -> Bool {
        let exists = try self.keychainStorage.existsEntry(withName: self.identity)

    #if os(iOS)
        guard exists else {
            return try self.keychainStorage.existsEntry(withName: self.backupName)
        }
    #endif

        return exists
    }
}

extension LocalKeyStorage {
    internal func getKeyPair() throws -> VirgilKeyPair {
        let loaded: VirgilKeyPair?

        switch self.loadKeyStrategy {
        case .instant:
            loaded = self.keyPair
        case .onFirstNeed:
            loaded = try self.keyPair ?? self.loadKeyPair()
        case .onlyOnUse:
            loaded = try self.loadKeyPair()
        }

        guard let keyPair = loaded else {
            throw EThreeError.missingPrivateKey
        }

        return keyPair
    }

    internal func store(data: Data) throws {
        let keyEntry = try self.keychainStorage.store(data: data,
                                                      withName: self.identity,
                                                      meta: nil,
                                                      queryOptions: self.options)

        switch self.loadKeyStrategy {
        case .instant: break
        case .onFirstNeed, .onlyOnUse:
            self.keyPair = try self.crypto.importPrivateKey(from: keyEntry.data)
        }
    }

    internal func exists() throws -> Bool {
        switch self.loadKeyStrategy {
        case .instant:
            return self.keyPair != nil
        case .onFirstNeed, .onlyOnUse:
            return try self.existsEntry()
        }
    }

    internal func delete() throws {
        try self.keychainStorage.deleteEntry(withName: self.identity, queryOptions: self.options)

        self.keyPair = nil
    }

#if os(iOS)
    internal func setBiometricProtection(to value: Bool) throws {
        guard self.options.biometricallyProtected != value, self.keyPair != nil else {
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
