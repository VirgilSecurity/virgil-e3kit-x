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

import VirgilSDK
import VirgilCrypto

internal class FileTempKeysStorage {
    internal let identity: String

    private let crypto: VirgilCrypto
    private let fileSystem: FileSystem
    private let identityKeyPair: VirgilKeyPair

    private let defaultName: String = "default"

    internal struct TempKey: Codable {
        internal fileprivate(set) var key: Data
        internal let type: KeyType
    }

    internal enum KeyType: String, Codable {
        case `private`
        case `public`
    }

    internal init(appGroup: String?, identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair) throws {
        self.identity = identity
        self.crypto = crypto
        self.identityKeyPair = identityKeyPair

        self.fileSystem = FileSystem(appGroup: appGroup,
                                     prefix: "VIRGIL-E3KIT",
                                     userIdentifier: identity,
                                     pathComponents: ["UNSAFE-KEYS"])
    }

    private func encode(key: Data, type: KeyType) throws -> Data {
        var data = key

        if type == .private {
            data = try self.crypto.authEncrypt(data,
                                               with: self.identityKeyPair.privateKey,
                                               for: [self.identityKeyPair.publicKey])
        }

        let temporaryKey = TempKey(key: data, type: type)

        return try JSONEncoder().encode(temporaryKey)
    }

    private func decode(data: Data) throws -> TempKey {
        var tempKey = try JSONDecoder().decode(TempKey.self, from: data)

        if tempKey.type == .private {
            tempKey.key = try self.crypto.authDecrypt(tempKey.key,
                                                      with: self.identityKeyPair.privateKey,
                                                      usingOneOf: [self.identityKeyPair.publicKey])
        }

        return tempKey
    }
}

extension FileTempKeysStorage {
    internal func store(_ key: VirgilPrivateKey, identity: String) throws {
        let keyData = try self.crypto.exportPrivateKey(key)

        let data = try self.encode(key: keyData, type: .private)

        try self.fileSystem.write(data: data, name: self.defaultName, subdir: identity)
    }

    internal func store(_ key: VirgilPublicKey, identity: String) throws {
        let keyData = try self.crypto.exportPublicKey(key)

        let data = try self.encode(key: keyData, type: .public)

        try self.fileSystem.write(data: data, name: self.defaultName, subdir: identity)
    }

    internal func retrieve(identity: String) throws -> TempKey? {
        let data = try self.fileSystem.read(name: self.defaultName, subdir: identity)

        guard !data.isEmpty else {
            return nil
        }

        return try self.decode(data: data)
    }

    internal func delete(identity: String) throws {
        try self.fileSystem.delete(name: self.defaultName, subdir: identity)
    }

    internal func reset() throws {
        try self.fileSystem.delete()
    }
}
