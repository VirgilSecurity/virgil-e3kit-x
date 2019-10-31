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

internal class UnsafeChatManager {
    private let crypto: VirgilCrypto
    private let keychain: SandboxedKeychainStorage
    private let cloudUnsafeStorage: CloudUnsafeStorage
    private let localKeyStorage: LocalKeyStorage
    private let lookupManager: LookupManager

    private let metaIsPrivateKey: String = "isPrivate"

    internal init(crypto: VirgilCrypto,
                  keychain: KeychainStorage,
                  accessTokenProvider: AccessTokenProvider,
                  localKeyStorage: LocalKeyStorage,
                  lookupManager: LookupManager) {
        self.crypto = crypto
        self.localKeyStorage = localKeyStorage
        self.lookupManager = lookupManager

        let identity = localKeyStorage.identity

        self.cloudUnsafeStorage = CloudUnsafeStorage(identity: identity,
                                                     accessTokenProvider: accessTokenProvider,
                                                     crypto: crypto)

        self.keychain = SandboxedKeychainStorage(identity: identity,
                                                 prefix: "TEMP-KEYS",
                                                 keychainStorage: keychain)
    }
}

extension UnsafeChatManager {
    internal func create(with identity: String) throws -> UnsafeChat {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let participantKeyPair = try self.crypto.generateKeyPair()

        try self.cloudUnsafeStorage.store(participantKeyPair.privateKey, for: identity)

        let unsafeChat = UnsafeChat(participant: identity,
                                    participantPublicKey: participantKeyPair.publicKey,
                                    selfPrivateKey: selfKeyPair.privateKey,
                                    crypto: self.crypto)

        let meta = [self.metaIsPrivateKey: "false"]
        let data = try self.crypto.exportPublicKey(participantKeyPair.publicKey)
        _ = try self.keychain.store(data: data, withName: identity, meta: meta)

        return unsafeChat
    }

    internal func join(with card: Card) throws -> UnsafeChat {
        let tempKeyPair = try self.cloudUnsafeStorage.retrieve(from: card.identity)

        let meta = [self.metaIsPrivateKey: "true"]
        let data = try self.crypto.exportPrivateKey(tempKeyPair.privateKey)
        _ = try self.keychain.store(data: data, withName: card.identity, meta: meta)

        return UnsafeChat(participant: card.identity,
                          participantPublicKey: card.publicKey,
                          selfPrivateKey: tempKeyPair.privateKey,
                          crypto: self.crypto)
    }

    internal func get(with identity: String) throws -> UnsafeChat {
        let entry = try self.keychain.retrieveEntry(withName: identity)

        guard let isPrivateStr = entry.meta?[self.metaIsPrivateKey],
            let isPrivate = Bool(isPrivateStr) else {
                throw NSError()
        }

        if isPrivate {
            let keyPair = try self.crypto.importPrivateKey(from: entry.data)
            let participantCard = try self.lookupManager.lookupCachedCard(of: identity)

            return UnsafeChat(participant: identity,
                              participantPublicKey: participantCard.publicKey,
                              selfPrivateKey: keyPair.privateKey,
                              crypto: self.crypto)
        } else {
            let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()
            let participantPublicKey = try self.crypto.importPublicKey(from: entry.data)

            return UnsafeChat(participant: identity,
                              participantPublicKey: participantPublicKey,
                              selfPrivateKey: selfKeyPair.privateKey,
                              crypto: self.crypto)
        }
    }

    internal func delete(with identity: String) throws {
        try self.cloudUnsafeStorage.delete(with: identity)

        try self.keychain.deleteEntry(withName: identity)
    }
}
