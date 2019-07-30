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

internal class GroupManager {
    internal let identity: String
    internal let localStorage: FileGroupStorage
    internal let cloudStorage: CloudTicketStorage

    internal let maxTicketsInGroup: Int = 50

    internal init(localStorage: FileGroupStorage,
                  cloudStorage: CloudTicketStorage) {
        self.identity = localStorage.identity
        self.localStorage = localStorage
        self.cloudStorage = cloudStorage
    }

    internal func store(_ ticket: Ticket, sharedWith cards: [Card]) throws {
        let group = RawGroup(info: GroupInfo(initiator: self.identity), tickets: [ticket])

        try self.cloudStorage.store(ticket, sharedWith: cards)

        try self.localStorage.store(group)
    }

    internal func pull(sessionId: Data, from card: Card) throws {
        let tickets = try self.cloudStorage.retrieve(sessionId: sessionId,
                                                     identity: card.identity,
                                                     identityPublicKey: card.publicKey)

        guard !tickets.isEmpty else {
            try self.localStorage.delete(sessionId: sessionId)
            throw EThreeError.groupWasNotFound
        }

        let group = RawGroup(info: GroupInfo(initiator: card.identity), tickets: tickets)

        try self.localStorage.store(group)
    }

    internal func updateRecipients(sessionId: Data, newRecipients: [Card]) throws {
        try self.cloudStorage.updateRecipients(sessionId: sessionId, newRecipients: newRecipients)
    }

    internal func retrieve(sessionId: Data, epoch: UInt32? = nil) -> RawGroup? {
        if let epoch = epoch {
            return self.localStorage.retrieve(sessionId: sessionId, epoch: epoch)
        } else {
            return self.localStorage.retrieve(sessionId: sessionId, lastTicketsCount: self.maxTicketsInGroup)
        }
    }

    internal func delete(sessionId: Data) throws {
        try self.cloudStorage.delete(sessionId: sessionId)

        try self.localStorage.delete(sessionId: sessionId)
    }
}
