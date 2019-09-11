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

internal class KeyknoxCloudStorage {
    internal var root: String {
        return CloudKeyStorage.root
    }

    internal let localKeyStorage: LocalKeyStorage
    internal let keyknoxManager: KeyknoxManager

    internal var identity: String {
        return self.localKeyStorage.identity
    }

    internal init(accessTokenProvider: AccessTokenProvider, localKeyStorage: LocalKeyStorage) throws {
        self.localKeyStorage = localKeyStorage

        let connection = EThree.getConnection()

        let keyknoxClient = KeyknoxClient(accessTokenProvider: accessTokenProvider,
                                          serviceUrl: KeyknoxClient.defaultURL,
                                          connection: connection,
                                          retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: keyknoxClient)
    }
}

extension KeyknoxCloudStorage {
    internal func addRecipients(_ cards: [Card], path: Data) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let path = path.hexEncodedString()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }

        let params = KeyknoxGetKeysParams(identity: self.identity,
                                          root: self.root,
                                          path: path)

        let keys = try self.keyknoxManager.getKeys(params: params)
            .startSync()
            .get()

        for key in keys {
            let pullParams = KeyknoxPullParams(identity: self.identity,
                                               root: self.root,
                                               path: path,
                                               key: key)
            let response = try self.keyknoxManager
                .pullValue(params: pullParams,
                           publicKeys: [selfKeyPair.publicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()

            let pushParams = KeyknoxPushParams(identities: identities,
                                               root: self.root,
                                               path: path,
                                               key: key)

            _ = try self.keyknoxManager.pushValue(params: pushParams,
                                                  data: response.value,
                                                  previousHash: response.keyknoxHash,
                                                  publicKeys: publicKeys + [selfKeyPair.publicKey],
                                                  privateKey: selfKeyPair.privateKey)

                .startSync()
                .get()
        }
    }

    internal func reAddRecipient(_ card: Card, path pathData: Data) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let path = pathData.hexEncodedString()

        let params = KeyknoxGetKeysParams(identity: self.identity,
                                          root: self.root,
                                          path: path)

        let keys = try self.keyknoxManager.getKeys(params: params)
            .startSync()
            .get()

        for key in keys {
            let pullParams = KeyknoxPullParams(identity: self.identity,
                                               root: self.root,
                                               path: path,
                                               key: key)
            let response = try self.keyknoxManager
                .pullValue(params: pullParams,
                           publicKeys: [selfKeyPair.publicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()

            try self.removeRecipient(identity: card.identity, path: pathData, key: key)

            let pushParams = KeyknoxPushParams(identities: [card.identity],
                                               root: self.root,
                                               path: path,
                                               key: key)

            _ = try self.keyknoxManager.pushValue(params: pushParams,
                                                  data: response.value,
                                                  previousHash: response.keyknoxHash,
                                                  publicKeys: [card.publicKey, selfKeyPair.publicKey],
                                                  privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()
        }
    }

    internal func removeRecipient(identity: String, path: Data, key: String? = nil) throws {
        let path = path.hexEncodedString()

        let params = KeyknoxDeleteRecipientParams(identity: identity,
                                                  root: self.root,
                                                  path: path,
                                                  key: key)

        _ = try self.keyknoxManager.deleteRecipient(params: params)
            .startSync()
            .get()
    }

    internal func delete(path: Data) throws {
        let path = path.hexEncodedString()

        let params = KeyknoxResetParams(root: self.root, path: path)

        _ = try self.keyknoxManager.resetValue(params: params)
            .startSync()
            .get()
    }
}
