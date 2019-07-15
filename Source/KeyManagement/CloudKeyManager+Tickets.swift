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

extension CloudKeyManager {
    private static let groupSessionsRoot = "group-sessions"

    public func store(ticket: Ticket, sharedWith cards: [Card], overwrite: Bool) throws {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        let sessionId = ticket.groupMessage.getSessionId().hexEncodedString()
        let epoch = ticket.groupMessage.getEpoch()
        let ticketData = try ticket.serialize()

        let identities = cards.map { $0.identity }
        let publicKeys = cards.map { $0.publicKey }

        // FIXME: previous hash
        _ = try self.keyknoxManager
            .pushValue(identities: identities,
                       root1: CloudKeyManager.groupSessionsRoot,
                       root2: sessionId,
                       key: "\(epoch)",
                       data: ticketData,
                       previousHash: nil,
                       overwrite: overwrite,
                       publicKeys: publicKeys + [selfKeyPair.publicKey],
                       privateKey: selfKeyPair.privateKey)
            .startSync()
            .get()
    }

    public func retrieveTickets(sessionId: Data, identity: String) throws -> [Ticket] {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        let sessionId = sessionId.hexEncodedString()

        let epochs = try self.keyknoxClient.getKeys(identity: identity,
                                                    root1: CloudKeyManager.groupSessionsRoot,
                                                    root2: sessionId)

        var tickets: [Ticket] = []
        for epoch in epochs {
            let response = try self.keyknoxManager
                .pullValue(identity: identity,
                           root1: CloudKeyManager.groupSessionsRoot,
                           root2: sessionId,
                           key: epoch,
                           publicKeys: [selfKeyPair.publicKey],
                           privateKey: selfKeyPair.privateKey)
                .startSync()
                .get()

            let ticket = try Ticket.deserialize(response.value)
            tickets.append(ticket)
        }

        return tickets
    }
}
