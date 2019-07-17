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
import VirgilCryptoFoundation
import VirgilSDK

extension EThree {    
    public func createGroup(id identifier: Data, participants: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                let ticket = try Ticket(crypto: self.crypto, sessionId: sessionId, participants: Array(participants.keys))

                try self.cloudKeyManager.store(ticket: ticket,
                                               sharedWith: Array(participants.values),
                                               overwrite: true)

                try self.getTicketStorage().store(tickets: [ticket])

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func retrieveGroup(id identifier: Data) throws -> Group? {
        let sessionId = self.computeSessionId(from: identifier)

        let tickets = try self.getTicketStorage().retrieveTickets(sessionId: sessionId)

        guard !tickets.isEmpty else {
            return nil
        }

        return try Group(crypto: self.crypto, tickets: tickets, localKeyManager: self.localKeyManager)
    }

    public func updateGroup(id identifier: Data, initiator: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                let tickets = try self.cloudKeyManager.retrieveTickets(sessionId: sessionId, identity: initiator)

                try self.getTicketStorage().store(tickets: tickets)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func updateGroup(group: Group, initiator: String) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = group.session.getSessionId()

                let tickets = try self.cloudKeyManager.retrieveTickets(sessionId: sessionId, identity: initiator)

                try self.getTicketStorage().store(tickets: tickets)

                let group = try Group(crypto: self.crypto, tickets: tickets, localKeyManager: self.localKeyManager)

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func deleteGroup(id identifier: Data) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                try self.cloudKeyManager.deleteTickets(sessionId: sessionId)

                try self.getTicketStorage().deleteTickets(sessionId: sessionId)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func changeMembers(group: Group, newMembers: LookupResult) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = group.session.getSessionId()

                let oldParticipants = group.participants
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

                    try self.cloudKeyManager.updateRecipients(sessionId: sessionId, newRecipients: addedCards)
                }

                if !deleteSet.isEmpty {
                    let ticketMessage = try group.session.createGroupTicket().getTicketMessage()
                    let ticket = Ticket(groupMessage: ticketMessage, participants: newParticipants)

                    try self.cloudKeyManager.store(ticket: ticket,
                                                   sharedWith: Array(newMembers.values),
                                                   overwrite: true)

                    try self.getTicketStorage().store(tickets: [ticket])
                }

                guard let group = try self.retrieveGroup(id: sessionId) else {
                    throw NSError()
                }

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
