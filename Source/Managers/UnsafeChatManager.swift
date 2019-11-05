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
    internal let localUnsafeStorage: FileUnsafeKeysStorage

    private let crypto: VirgilCrypto
    private let cloudUnsafeStorage: CloudUnsafeStorage
    private let localKeyStorage: LocalKeyStorage
    private let lookupManager: LookupManager

    private var identity: String {
        return self.localKeyStorage.identity
    }

    internal init(crypto: VirgilCrypto,
                  accessTokenProvider: AccessTokenProvider,
                  localKeyStorage: LocalKeyStorage,
                  lookupManager: LookupManager,
                  keyPair: VirgilKeyPair) throws {
        self.crypto = crypto
        self.localKeyStorage = localKeyStorage
        self.lookupManager = lookupManager

        let identity = localKeyStorage.identity

        self.cloudUnsafeStorage = CloudUnsafeStorage(identity: identity,
                                                     accessTokenProvider: accessTokenProvider,
                                                     crypto: crypto)

        self.localUnsafeStorage = try FileUnsafeKeysStorage(identity: identity,
                                                            crypto: crypto,
                                                            identityKeyPair: keyPair)
    }
}

extension UnsafeChatManager {
    internal func create(with identity: String) throws -> UnsafeChat {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let tempKeyPair = try self.crypto.generateKeyPair()

        do {
            try self.cloudUnsafeStorage.store(tempKeyPair.privateKey, for: identity)
        } catch let error as ServiceError where error.errorCode == ServiceErrorCodes.invalidPreviousHash.rawValue {
            throw UnsafeChatError.chatAlreadyExists
        }

        let unsafeChat = UnsafeChat(participant: identity,
                                    participantPublicKey: tempKeyPair.publicKey,
                                    selfPrivateKey: selfKeyPair.privateKey,
                                    crypto: self.crypto)

        try self.localUnsafeStorage.store(tempKeyPair.publicKey, identity: identity)

        return unsafeChat
    }

    internal func load(asCreator: Bool, with identity: String) throws -> UnsafeChat {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let publicKey: VirgilPublicKey
        let privateKey: VirgilPrivateKey

        if asCreator {
            let tempKeyPair = try self.cloudUnsafeStorage.retrieve(from: self.identity, path: identity)
            try self.localUnsafeStorage.store(tempKeyPair.publicKey, identity: identity)

            publicKey = tempKeyPair.publicKey
            privateKey = selfKeyPair.privateKey
        } else {
            let card = try self.lookupManager.lookupCard(of: identity)

            let tempKeyPair = try self.cloudUnsafeStorage.retrieve(from: identity, path: self.identity)
            try self.localUnsafeStorage.store(tempKeyPair.privateKey, identity: identity)

            publicKey = card.publicKey
            privateKey = tempKeyPair.privateKey
        }

        return UnsafeChat(participant: identity,
                          participantPublicKey: publicKey,
                          selfPrivateKey: privateKey,
                          crypto: self.crypto)
    }

    internal func get(with identity: String) throws -> UnsafeChat? {
        guard let unsafeKey = try? self.localUnsafeStorage.retrieve(identity: identity) else {
            return nil
        }

        let privateKey: VirgilPrivateKey
        let publicKey: VirgilPublicKey

        switch unsafeKey.type {
        case .private:
            privateKey = try self.crypto.importPrivateKey(from: unsafeKey.key).privateKey
            publicKey = try self.lookupManager.lookupCachedCard(of: identity).publicKey
        case .public:
            privateKey = try self.localKeyStorage.retrieveKeyPair().privateKey
            publicKey = try self.crypto.importPublicKey(from: unsafeKey.key)
        }

        return UnsafeChat(participant: identity,
                          participantPublicKey: publicKey,
                          selfPrivateKey: privateKey,
                          crypto: self.crypto)
    }

    internal func delete(with identity: String) throws {
        try self.cloudUnsafeStorage.delete(with: identity)

        do {
            try self.localUnsafeStorage.delete(identity: identity)
        } catch CocoaError.fileNoSuchFile {
            throw UnsafeChatError.chatNotFound
        }
    }
}
