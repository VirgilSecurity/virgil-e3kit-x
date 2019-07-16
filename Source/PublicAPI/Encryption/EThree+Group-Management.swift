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
    public func createGroup(withId identifier: Data, participants: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                let ticket = try Ticket(crypto: self.crypto, sessionId: sessionId, participants: Array(participants.keys))

                try self.cloudKeyManager.store(ticket: ticket,
                                               sharedWith: Array(participants.values),
                                               overwrite: true)

                try self.getTicketStorage().store(tickets: [ticket])
            } catch {
                completion(nil, error)
            }
        }
    }

    public func hasGroup(withId identifier: Data) throws -> Bool {
        let sessionId = self.computeSessionId(from: identifier)

        return try !self.getTicketStorage().retrieveTickets(sessionId: sessionId).isEmpty
    }

    // TODO: Remove initiator = store sessionId - initiators in Keyknox?
    public func updateGroup(withId identifier: Data, initiator: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                let tickets = try self.cloudKeyManager.retrieveTickets(sessionId: sessionId, identity: initiator)

                try self.getTicketStorage().store(tickets: tickets)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func deleteGroup(withId identifier: Data) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                try self.cloudKeyManager.deleteTickets(sessionId: sessionId)

                try self.getTicketStorage().deleteTickets(sessionId: sessionId)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func changeMembersInGroup(withId identifier: Data, newMembers: LookupResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.computeSessionId(from: identifier)

                let session = try self.getSession(withId: sessionId)

                let currentEpoch = session.getCurrentEpoch()

                guard let ticket = try self.getTicketStorage().retrieveTicket(sessionId: sessionId, epoch: currentEpoch) else {
                    throw NSError()
                }

                let oldParticipants = ticket.participants
                let newParticipants = Array(newMembers.keys)

                let oldSet: Set<String> = Set(oldParticipants)
                let newSet: Set<String> = Set(newParticipants)

                let deleteSet = oldSet.subtracting(newSet)
                let addSet = newSet.subtracting(oldSet)

                if !deleteSet.isEmpty {
                    let ticket = try Ticket(crypto: self.crypto, sessionId: sessionId, participants: newParticipants)

                    try self.cloudKeyManager.store(ticket: ticket,
                                                   sharedWith: Array(newMembers.values),
                                                   overwrite: true)

                    try self.getTicketStorage().store(tickets: [ticket])
                } else if !addSet.isEmpty {
                    try self.cloudKeyManager.store(ticket: ticket,
                                                   sharedWith: Array(newMembers.values),
                                                   overwrite: false)
                } else {
                    throw NSError()
                }

            } catch {
                completion(nil, error)
            }
        }
    }

    internal func getSession(withId identifier: Data) throws -> GroupSession {
        // Retrieve tickets from storage with identifier
        let sessionId = self.computeSessionId(from: identifier)

        let tickets = try self.getTicketStorage().retrieveTickets(sessionId: sessionId)

        guard !tickets.isEmpty else {
            throw NSError()
        }

        // Use ticket/tickets to generate session
        let session = GroupSession()
        session.setRng(rng: self.crypto.rng)

        try tickets.forEach {
            try session.addEpoch(message: $0.groupMessage)
        }

        return session
    }
}
