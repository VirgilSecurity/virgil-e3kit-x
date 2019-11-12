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

internal class TempChannelManager {
    internal let localStorage: FileTempKeysStorage

    private let identity: String
    private let crypto: VirgilCrypto
    private let cloudStorage: CloudTempKeysStorage
    private let keyWrapper: PrivateKeyWrapper
    private let lookupManager: LookupManager

    internal init(identity: String,
                  crypto: VirgilCrypto,
                  accessTokenProvider: AccessTokenProvider,
                  keyWrapper: PrivateKeyWrapper,
                  lookupManager: LookupManager) throws {
        self.identity = identity
        self.crypto = crypto
        self.keyWrapper = keyWrapper
        self.lookupManager = lookupManager

        self.cloudStorage = CloudTempKeysStorage(identity: identity,
                                                 accessTokenProvider: accessTokenProvider,
                                                 crypto: crypto)

        self.localStorage = try FileTempKeysStorage(identity: identity,
                                                    crypto: crypto,
                                                    keyWrapper: keyWrapper)
    }
}

extension TempChannelManager {
    internal func create(with identity: String) throws -> TemporaryChannel {
        let selfPrivateKey = try self.keyWrapper.getPrivateKey()

        let tempKeyPair = try self.crypto.generateKeyPair()

        do {
            try self.cloudStorage.store(tempKeyPair.privateKey, for: identity)
        } catch let error as ServiceError where error.errorCode == ServiceErrorCodes.invalidPreviousHash.rawValue {
            throw TemporaryChannelError.channelAlreadyExists
        }

        let tempChannel = TemporaryChannel(participant: identity,
                                           participantPublicKey: tempKeyPair.publicKey,
                                           selfPrivateKey: selfPrivateKey,
                                           crypto: self.crypto)

        try self.localStorage.store(tempKeyPair.publicKey, identity: identity)

        return tempChannel
    }

    internal func loadFromCloud(asCreator: Bool, with identity: String) throws -> TemporaryChannel {
        let selfPrivateKey = try self.keyWrapper.getPrivateKey()

        let publicKey: VirgilPublicKey
        let privateKey: VirgilPrivateKey

        if asCreator {
            let tempKeyPair = try self.cloudStorage.retrieve(from: self.identity, path: identity)
            try self.localStorage.store(tempKeyPair.publicKey, identity: identity)

            publicKey = tempKeyPair.publicKey
            privateKey = selfPrivateKey
        } else {
            let card = try self.lookupManager.lookupCard(of: identity)

            let tempKeyPair = try self.cloudStorage.retrieve(from: identity, path: self.identity)
            try self.localStorage.store(tempKeyPair.privateKey, identity: identity)

            publicKey = card.publicKey
            privateKey = tempKeyPair.privateKey
        }

        return TemporaryChannel(participant: identity,
                                participantPublicKey: publicKey,
                                selfPrivateKey: privateKey,
                                crypto: self.crypto)
    }

    internal func getLocalChannel(with identity: String) throws -> TemporaryChannel? {
        guard let tempKey = try? self.localStorage.retrieve(identity: identity) else {
            return nil
        }

        let privateKey: VirgilPrivateKey
        let publicKey: VirgilPublicKey

        switch tempKey.type {
        case .private:              // User is participant
            privateKey = try self.crypto.importPrivateKey(from: tempKey.key).privateKey
            publicKey = try self.lookupManager.lookupCachedCard(of: identity).publicKey
        case .public:               // User is creator of channel
            privateKey = try self.keyWrapper.getPrivateKey()
            publicKey = try self.crypto.importPublicKey(from: tempKey.key)
        }

        return TemporaryChannel(participant: identity,
                                participantPublicKey: publicKey,
                                selfPrivateKey: privateKey,
                                crypto: self.crypto)
    }

    internal func delete(with identity: String) throws {
        try self.cloudStorage.delete(with: identity)

        do {
            try self.localStorage.delete(identity: identity)
        } catch CocoaError.fileNoSuchFile { }
    }
}
