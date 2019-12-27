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
import VirgilCryptoRatchet

internal class CloudRatchetStorage {
    private static let root = "ratchet-peer-to-peer"
    private static let defaultKey = "default"

    private let accessTokenProvider: AccessTokenProvider
    private let localKeyStorage: LocalKeyStorage
    private let keyknoxManager: KeyknoxManager

    private var identity: String {
        return self.localKeyStorage.identity
    }

    internal init(accessTokenProvider: AccessTokenProvider, localKeyStorage: LocalKeyStorage, keyknoxServiceUrl: URL) throws {
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage

        let connection = EThree.getConnection()

        let keyknoxClient = KeyknoxClient(accessTokenProvider: self.accessTokenProvider,
                                          serviceUrl: keyknoxServiceUrl,
                                          connection: connection,
                                          retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: keyknoxClient)
    }
}

extension CloudRatchetStorage {
    internal func store(_ ticket: RatchetMessage, sharedWith card: Card, name: String?) throws {
        do {
            let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

            let pushParams = KeyknoxPushParams(identities: [card.identity, self.identity],
                                               root: CloudRatchetStorage.root,
                                               path: card.identity,
                                               key: name ?? CloudRatchetStorage.defaultKey)

            _ = try self.keyknoxManager
                .pushValue(params: pushParams,
                           data: ticket.serialize(),
                           previousHash: nil,
                           publicKeys: [card.publicKey, selfKeyPair.publicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()
        }
        catch let error as ServiceError where error.errorCode == ServiceErrorCodes.invalidPreviousHash.rawValue {
            throw EThreeRatchetError.channelAlreadyExists
        }
    }

    internal func retrieve(from card: Card, name: String?) throws -> RatchetMessage {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let params = KeyknoxPullParams(identity: card.identity,
                                       root: CloudRatchetStorage.root,
                                       path: self.identity,
                                       key: name ?? CloudRatchetStorage.defaultKey)
        let response = try self.keyknoxManager
            .pullValue(params: params,
                       publicKeys: [card.publicKey],
                       privateKey: selfKeyPair.privateKey)
            .startSync()
            .get()

        guard !response.value.isEmpty else {
            throw EThreeRatchetError.noInvite
        }

        return try RatchetMessage.deserialize(input: response.value)
    }

    internal func delete(card: Card, name: String?) throws {
        let params = KeyknoxResetParams(root: CloudRatchetStorage.root,
                                        path: card.identity,
                                        key: name ?? CloudRatchetStorage.defaultKey)

        _ = try self.keyknoxManager.resetValue(params: params).startSync().get()
    }

    internal func reset() throws {
        let params = KeyknoxResetParams(root: CloudRatchetStorage.root)

        _ = try self.keyknoxManager.resetValue(params: params).startSync().get()
    }
}
