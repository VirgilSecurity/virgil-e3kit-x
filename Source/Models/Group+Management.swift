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

import VirgilCryptoFoundation
import VirgilSDK

extension Group {
    public func update() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.getSessionId()

                let card = try self.lookupManager.lookupCard(of: self.initiator)

                let group = try self.groupManager.pull(sessionId: sessionId, from: card)

                self.session = group.session
                self.participants = group.participants

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func add(participants lookup: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                guard self.selfIdentity == self.initiator else {
                    throw EThreeError.groupPermissionDenied
                }

                let oldSet = self.participants
                let newSet = oldSet.union(lookup.keys)

                try Group.validateParticipantsCount(newSet.count)

                guard newSet != oldSet else {
                    throw EThreeError.invalidChangeParticipants
                }

                let addSet = newSet.subtracting(oldSet)

                let addedCards: [Card] = try addSet.map {
                    guard let card = lookup[$0] else {
                        throw EThreeError.inconsistentState
                    }

                    return card
                }

                try self.shareTickets(for: addedCards)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func remove(participants lookup: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                guard self.selfIdentity == self.initiator else {
                    throw EThreeError.groupPermissionDenied
                }

                let oldSet = self.participants
                let newSet = oldSet.subtracting(lookup.keys)

                try Group.validateParticipantsCount(newSet.count)

                guard newSet != oldSet else {
                    throw EThreeError.invalidChangeParticipants
                }

                let newSetLookup = try self.lookupManager.lookupCards(of: Array(newSet))

                try self.addNewTicket(for: newSetLookup)

                let removedSet = oldSet.subtracting(newSet)

                try self.groupManager.removeAccess(identities: removedSet, to: self.session.getSessionId())

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func add(participant card: Card) -> GenericOperation<Void> {
        return self.add(participants: [card.identity: card])
    }

    public func remove(participant card: Card) -> GenericOperation<Void> {
        return self.remove(participants: [card.identity: card])
    }
}

extension Group {
    private func shareTickets(for cards: [Card]) throws {
        let sessionId = self.session.getSessionId()

        try self.groupManager.updateRecipients(sessionId: sessionId, newRecipients: cards)

        let newParticipants = cards.map { $0.identity }
        self.participants = self.participants.union(newParticipants)
    }

    private func addNewTicket(for lookup: LookupResult) throws {
        let newSet = Set(lookup.keys)

        let ticketMessage = try self.session.createGroupTicket().getTicketMessage()
        let ticket = Ticket(groupMessage: ticketMessage, participants: newSet)

        _ = try self.groupManager.store(ticket, sharedWith: Array(lookup.values))

        try self.session.addEpoch(message: ticket.groupMessage)

        self.participants = newSet.union([self.initiator])
    }
}
