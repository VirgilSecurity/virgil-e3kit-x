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

import VirgilSDK
import VirgilCrypto

internal class FileUnsafeKeysStorage {
    internal let identity: String

    private let crypto: VirgilCrypto
    private let fileSystem: FileSystem
    private let queue = DispatchQueue(label: "FileUnsafeKeysStorageQueue")

    private let defaultName: String = "default"

    internal struct UnsafeKey: Codable {
        let key: Data
        let type: KeyType
    }

    internal enum KeyType: String, Codable {
        case `private`
        case `public`
    }

    internal init(identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair) throws {
        self.identity = identity
        self.crypto = crypto

        let credentials = FileSystemCredentials(crypto: crypto, keyPair: identityKeyPair)
        self.fileSystem = FileSystem(prefix: "VIRGIL-E3KIT",
                                     userIdentifier: identity,
                                     pathComponents: ["UNSAFE-KEYS"],
                                     credentials: credentials)

    }
}

extension FileUnsafeKeysStorage {
    internal func store(_ key: VirgilPrivateKey, identity: String) throws {
        try self.queue.sync {
            let keyData = try self.crypto.exportPrivateKey(key)
            let unsafeKey = UnsafeKey(key: keyData, type: .private)

            let data = try JSONEncoder().encode(unsafeKey)

            try self.fileSystem.write(data: data, name: self.defaultName, subdir: identity)
        }
    }

    internal func store(_ key: VirgilPublicKey, identity: String) throws {
        try self.queue.sync {
            let keyData = try self.crypto.exportPublicKey(key)
            let unsafeKey = UnsafeKey(key: keyData, type: .public)

            let data = try JSONEncoder().encode(unsafeKey)

            try self.fileSystem.write(data: data, name: self.defaultName, subdir: identity)
        }
    }

    internal func retrieve(identity: String) throws -> UnsafeKey {
        let data = try self.fileSystem.read(name: self.defaultName, subdir: identity)

        return try JSONDecoder().decode(UnsafeKey.self, from: data)
    }

    internal func delete(identity: String) throws {
        try self.queue.sync {
            try self.fileSystem.delete(name: self.defaultName, subdir: identity)
        }
    }

    internal func reset() throws {
        try self.queue.sync {
            try self.fileSystem.delete()
        }
    }
}
