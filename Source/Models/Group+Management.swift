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

                try self.groupManager.pull(sessionId: sessionId, from: card)

                guard let group = self.groupManager.retrieve(sessionId: sessionId) else {
                    throw NSError()
                }

                guard let lastTicket = group.tickets.last else {
                    throw NSError()
                }

                self.session = try self.generateSession(from: group.tickets)
                self.participants = lastTicket.participants

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func add(participants lookup: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let oldSet = self.participants
                let newSet = oldSet.union(lookup.keys)

                guard newSet != oldSet else {
                    throw NSError()
                }

                let addSet = newSet.subtracting(oldSet)

                let addedCards: [Card] = try addSet.map {
                    guard let card = lookup[$0] else {
                        throw NSError()
                    }

                    return card
                }

                let sessionId = self.session.getSessionId()

                try self.groupManager.updateRecipients(sessionId: sessionId, newRecipients: addedCards)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func remove(participants lookup: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let oldSet = self.participants
                let newSet = oldSet.subtracting(lookup.keys)

                guard newSet != oldSet else {
                    throw NSError()
                }

                let ticketMessage = try self.session.createGroupTicket().getTicketMessage()
                let ticket = Ticket(groupMessage: ticketMessage, participants: newSet)

                try self.groupManager.store(ticket, sharedWith: Array(lookup.values))

                try self.session.addEpoch(message: ticket.groupMessage)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func changeParticipants(to lookup: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.getSessionId()

                let oldSet = Set(self.participants)
                let newSet = Set(lookup.keys)

                let deleteSet = oldSet.subtracting(newSet)
                let addSet = newSet.subtracting(oldSet)

                if deleteSet.isEmpty && addSet.isEmpty {
                    throw NSError()
                }

                if !addSet.isEmpty {
                    let addedCards = Array(addSet).map { lookup[$0]! }

                    try self.groupManager.updateRecipients(sessionId: sessionId, newRecipients: addedCards)
                }

                if !deleteSet.isEmpty {
                    let ticketMessage = try self.session.createGroupTicket().getTicketMessage()
                    let ticket = Ticket(groupMessage: ticketMessage, participants: newSet)

                    try self.groupManager.store(ticket, sharedWith: Array(lookup.values))

                    try self.session.addEpoch(message: ticket.groupMessage)
                }

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func delete() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.getSessionId()

                try self.groupManager.delete(sessionId: sessionId)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
