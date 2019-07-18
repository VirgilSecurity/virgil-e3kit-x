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
    // FIXME: Remove initiator ?
    public func update(initiator: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.getSessionId()

                let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

                let tickets = try self.cloudTicketManager.retrieveTickets(sessionId: sessionId,
                                                                          identity: initiator,
                                                                          selfKeyPair: selfKeyPair)

                try self.localTicketsManager.store(tickets: tickets)

                // FIXME
                let session = GroupSession()
                session.setRng(rng: self.crypto.rng)

                guard !tickets.isEmpty else {
                    completion((), nil)
                    return
                }

                try tickets.forEach {
                    try session.addEpoch(message: $0.groupMessage)
                }

                guard let currentTicket = tickets.first(where: { $0.groupMessage.getEpoch() == session.getCurrentEpoch() }) else {
                    throw NSError()
                }

                self.session = session
                self.participants = currentTicket.participants

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func changeMembers(to newMembers: EThree.LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                // self.update(initiator: ) ?

                let sessionId = self.session.getSessionId()

                let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

                let oldParticipants = self.participants
                let newParticipants = Array(newMembers.keys)

                let oldSet: Set<String> = Set(oldParticipants)
                let newSet: Set<String> = Set(newParticipants)

                let deleteSet = oldSet.subtracting(newSet)
                let addSet = newSet.subtracting(oldSet)

                if deleteSet.isEmpty && addSet.isEmpty {
                    throw NSError()
                }

                if !addSet.isEmpty {
                    let addedCards = Array(addSet).map { newMembers[$0]! }

                    try self.cloudTicketManager.updateRecipients(sessionId: sessionId,
                                                                 newRecipients: addedCards,
                                                                 selfKeyPair: selfKeyPair)
                }

                if !deleteSet.isEmpty {
                    let ticketMessage = try self.session.createGroupTicket().getTicketMessage()
                    let ticket = Ticket(groupMessage: ticketMessage, participants: newParticipants)

                    try self.cloudTicketManager.store(ticket: ticket,
                                                      sharedWith: Array(newMembers.values),
                                                      overwrite: true,
                                                      selfKeyPair: selfKeyPair)

                    try self.localTicketsManager.store(tickets: [ticket])

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

                try self.cloudTicketManager.deleteTickets(sessionId: sessionId)

                try self.localTicketsManager.deleteTickets(sessionId: sessionId)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
