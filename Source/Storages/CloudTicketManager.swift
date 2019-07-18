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

internal class CloudTicketManager {
    private static let groupSessionsRoot = "group-sessions"

    private let accessTokenProvider: AccessTokenProvider

    internal let keyknoxClient: KeyknoxClient
    internal let keyknoxManager: KeyknoxManager

    internal init(accessTokenProvider: AccessTokenProvider) throws {
        self.accessTokenProvider = accessTokenProvider

        let connection = EThree.getConnection()

        self.keyknoxClient = KeyknoxClient(accessTokenProvider: self.accessTokenProvider,
                                           serviceUrl: KeyknoxClient.defaultURL,
                                           connection: connection,
                                           retryConfig: ExpBackoffRetry.Config())

        self.keyknoxManager = try KeyknoxManager(keyknoxClient: self.keyknoxClient)
    }
}

extension CloudTicketManager {
    public func store(ticket: Ticket, sharedWith cards: [Card], selfKeyPair: VirgilKeyPair) throws {
        let sessionId = ticket.groupMessage.getSessionId().hexEncodedString()
        let epoch = ticket.groupMessage.getEpoch()
        let ticketData = try ticket.serialize()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }

        // FIXME: previous hash
        _ = try self.keyknoxManager
            .pushValue(identities: identities,
                       root1: CloudTicketManager.groupSessionsRoot,
                       root2: sessionId,
                       key: "\(epoch)",
                data: ticketData,
                previousHash: nil,
                overwrite: true,
                publicKeys: publicKeys + [selfKeyPair.publicKey],
                privateKey: selfKeyPair.privateKey)
            .startSync()
            .get()
    }

    public func retrieveTickets(sessionId: Data,
                                identity: String,
                                identityPublicKey: VirgilPublicKey,
                                selfKeyPair: VirgilKeyPair) throws -> [Ticket] {
        let sessionId = sessionId.hexEncodedString()

        let epochs = try self.keyknoxClient.getKeys(identity: identity,
                                                    root1: CloudTicketManager.groupSessionsRoot,
                                                    root2: sessionId)

        var tickets: [Ticket] = []
        for epoch in epochs {
            let response = try self.keyknoxManager
                .pullValue(identity: identity,
                           root1: CloudTicketManager.groupSessionsRoot,
                           root2: sessionId,
                           key: epoch,
                           publicKeys: [identityPublicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()

            let ticket = try Ticket.deserialize(response.value)
            tickets.append(ticket)
        }

        return tickets
    }

    public func updateRecipients(sessionId: Data, newRecipients cards: [Card], selfKeyPair: VirgilKeyPair) throws {
        let sessionId = sessionId.hexEncodedString()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }

        let epochs = try self.keyknoxClient.getKeys(identity: nil,
                                                    root1: CloudTicketManager.groupSessionsRoot,
                                                    root2: sessionId)

        // TODO: save hash
        for epoch in epochs {
            _ = try self.keyknoxManager
                .updateRecipients(identities: identities,
                                  root1: CloudTicketManager.groupSessionsRoot,
                                  root2: sessionId,
                                  key: epoch,
                                  oldPublicKeys: [selfKeyPair.publicKey],
                                  oldPrivateKey: selfKeyPair.privateKey,
                                  overwrite: false,
                                  newPublicKeys: publicKeys + [selfKeyPair.publicKey],
                                  newPrivateKey: selfKeyPair.privateKey)
                .startSync()
                .get()
        }
    }

    public func deleteTickets(sessionId: Data) throws {
        let sessionId = sessionId.hexEncodedString()

        _ = try self.keyknoxClient.resetValue(identities: [],
                                              root1: CloudTicketManager.groupSessionsRoot,
                                              root2: sessionId,
                                              key: nil)
    }
}
