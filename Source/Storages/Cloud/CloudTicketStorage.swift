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
import VirgilSDKPythia
import VirgilCryptoFoundation

internal class CloudTicketStorage {
    private static let groupSessionsRoot = "group-sessions"

    private let accessTokenProvider: AccessTokenProvider
    private let localKeyStorage: LocalKeyStorage

    internal let keyknoxManager: KeyknoxManager

    private var identity: String {
        return self.localKeyStorage.identity
    }

    internal init(accessTokenProvider: AccessTokenProvider, localKeyStorage: LocalKeyStorage) throws {
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage

        let connection = EThree.getConnection()

        let keyknoxClient = KeyknoxClient(accessTokenProvider: self.accessTokenProvider,
                                          serviceUrl: KeyknoxClient.defaultURL,
                                          connection: connection,
                                          retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: keyknoxClient)
    }
}

extension CloudTicketStorage {
    public func store(_ ticket: Ticket, sharedWith cards: [Card]) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let groupMessage = ticket.groupMessage

        let sessionId = groupMessage.getSessionId().hexEncodedString()
        let epoch = groupMessage.getEpoch()
        let ticketData = groupMessage.serialize()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }
        
        let params = KeyknoxPushParams(identities: identities + [self.identity],
                                       root: CloudTicketStorage.groupSessionsRoot,
                                       path: sessionId,
                                       key: "\(epoch)")

        _ = try self.keyknoxManager
            .pushValue(params: params,
                       data: ticketData,
                       previousHash: nil,
                       publicKeys: publicKeys + [selfKeyPair.publicKey],
                       privateKey: selfKeyPair.privateKey)
            .startSync()
            .get()
    }

    public func retrieve(sessionId: Data,
                         identity: String,
                         identityPublicKey: VirgilPublicKey) throws -> [Ticket] {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let sessionId = sessionId.hexEncodedString()
        
        let params = KeyknoxGetKeysParams(identity: identity,
                                          root: CloudTicketStorage.groupSessionsRoot,
                                          path: sessionId)

        let epochs = try self.keyknoxManager.getKeys(params: params)
            .startSync()
            .get()

        var tickets: [Ticket] = []
        for epoch in epochs {
            let params = KeyknoxPullParams(identity: identity,
                                           root: CloudTicketStorage.groupSessionsRoot,
                                           path: sessionId,
                                           key: epoch)
            let response = try self.keyknoxManager
                .pullValue(params: params,
                           publicKeys: [identityPublicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()

            let groupMessage = try GroupSessionMessage.deserialize(input: response.value)
            let participants = Set(response.identities)
            let ticket = Ticket(groupMessage: groupMessage, participants: participants)

            tickets.append(ticket)
        }

        return tickets
    }

    public func updateRecipients(sessionId: Data, newRecipients cards: [Card]) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()
        
        let sessionId = sessionId.hexEncodedString()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }
        
        let params = KeyknoxGetKeysParams(identity: identity,
                                          root: CloudTicketStorage.groupSessionsRoot,
                                          path: sessionId)

        let epochs = try self.keyknoxManager.getKeys(params: params)
            .startSync()
            .get()

        for epoch in epochs {
            let pullParams = KeyknoxPullParams(identity: identity,
                                               root: CloudTicketStorage.groupSessionsRoot,
                                               path: sessionId,
                                               key: epoch)
            let response = try self.keyknoxManager
                .pullValue(params: pullParams,
                           publicKeys: [selfKeyPair.publicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()
            
            let updateParams = KeyknoxPushParams(identities: identities,
                                                 root: CloudTicketStorage.groupSessionsRoot,
                                                 path: sessionId,
                                                 key: epoch)
            
            _ = try self.keyknoxManager.updateRecipients(params: updateParams,
                                                         value: response.value,
                                                         previousHash: response.keyknoxHash,
                                                         newPublicKeys: publicKeys + [selfKeyPair.publicKey],
                                                         newPrivateKey: selfKeyPair.privateKey)
                .startSync()
                .get()
        }
    }

    public func removeAccess(identity: String, to sessionId: Data) throws {
        let sessionId = sessionId.hexEncodedString()
        
        let params = KeyknoxDeleteRecipientParams(identity: identity,
                                                  root: CloudTicketStorage.groupSessionsRoot,
                                                  path: sessionId)

        _ = try self.keyknoxManager.deleteRecipient(params: params)
            .startSync()
            .get()
    }

    public func delete(sessionId: Data) throws {
        let sessionId = sessionId.hexEncodedString()
        
        let params = KeyknoxResetParams(root: CloudTicketStorage.groupSessionsRoot, path: sessionId)

        _ = try self.keyknoxManager.resetValue(params: params)
            .startSync()
            .get()
    }
}
