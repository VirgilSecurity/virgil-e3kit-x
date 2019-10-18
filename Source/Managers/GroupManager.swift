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

internal class GroupManager {
    internal let identity: String
    internal let localGroupStorage: FileGroupStorage
    internal let cloudTicketStorage: CloudTicketStorage

    private let localKeyStorage: LocalKeyStorage
    private let lookupManager: LookupManager
    private let crypto: VirgilCrypto

    internal static let maxTicketsInGroup: Int = 50

    internal init(localGroupStorage: FileGroupStorage,
                  cloudTicketStorage: CloudTicketStorage,
                  localKeyStorage: LocalKeyStorage,
                  lookupManager: LookupManager,
                  crypto: VirgilCrypto) {
        self.identity = localGroupStorage.identity
        self.localGroupStorage = localGroupStorage
        self.cloudTicketStorage = cloudTicketStorage
        self.localKeyStorage = localKeyStorage
        self.lookupManager = lookupManager
        self.crypto = crypto
    }

    private func parse(_ rawGroup: RawGroup) throws -> Group {
        return try Group(rawGroup: rawGroup,
                         crypto: self.crypto,
                         localKeyStorage: self.localKeyStorage,
                         groupManager: self,
                         lookupManager: self.lookupManager)
    }

    internal func store(_ ticket: Ticket, sharedWith cards: [Card]) throws -> Group {
        let rawGroup = try RawGroup(info: GroupInfo(initiator: self.identity), tickets: [ticket])

        try self.cloudTicketStorage.store(ticket, sharedWith: cards)

        try self.localGroupStorage.store(rawGroup)

        return try self.parse(rawGroup)
    }

    internal func pull(sessionId: Data, from card: Card) throws -> Group {
        let cloudEpochs = try self.cloudTicketStorage.getEpochs(sessionId: sessionId, identity: card.identity)
        let localEpochs = try self.localGroupStorage.getEpochs(sessionId: sessionId)

        guard let lastEpoch = cloudEpochs.sorted().last else {
            try self.localGroupStorage.delete(sessionId: sessionId)
            throw GroupError.groupWasNotFound
        }

        var epochs: Set<String> = cloudEpochs.subtracting(localEpochs)
        epochs.insert(lastEpoch)

        let tickets = try self.cloudTicketStorage.retrieve(sessionId: sessionId,
                                                           identity: card.identity,
                                                           identityPublicKey: card.publicKey,
                                                           epochs: epochs)
        let rawGroup: RawGroup

        if localEpochs.isEmpty {
            let info = GroupInfo(initiator: card.identity)
            rawGroup = try RawGroup(info: info, tickets: tickets)

            try self.localGroupStorage.store(rawGroup)
        } else {
            try self.localGroupStorage.add(tickets: tickets)

            guard let localGroup = try? self.localGroupStorage.retrieve(sessionId: sessionId,
                                                                        lastTicketsCount: GroupManager.maxTicketsInGroup) else {
                throw GroupError.groupWasNotFound
            }

            rawGroup = localGroup
        }

        return try self.parse(rawGroup)
    }

    internal func addAccess(to cards: [Card], sessionId: Data) throws {
        try self.cloudTicketStorage.addRecipients(cards, sessionId: sessionId)
    }

    internal func reAddAccess(to card: Card, sessionId: Data) throws {
        try self.cloudTicketStorage.reAddRecipient(card, sessionId: sessionId)
    }

    internal func retrieve(sessionId: Data) -> Group? {
        guard let rawGroup = try? self.localGroupStorage.retrieve(sessionId: sessionId,
                                                                  lastTicketsCount: GroupManager.maxTicketsInGroup) else {
            return nil
        }

        return try? self.parse(rawGroup)
    }

    internal func retrieve(sessionId: Data, epoch: UInt32) -> Group? {
        guard let rawGroup = try? self.localGroupStorage.retrieve(sessionId: sessionId, epoch: epoch) else {
            return nil
        }

        return try? self.parse(rawGroup)
    }

    internal func removeAccess(identities: Set<String>, to sessionId: Data) throws {
        try identities.forEach {
            try self.cloudTicketStorage.removeRecipient(identity: $0, sessionId: sessionId)
        }
    }

    internal func delete(sessionId: Data) throws {
        try self.cloudTicketStorage.delete(sessionId: sessionId)

        try self.localGroupStorage.delete(sessionId: sessionId)
    }
}
