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

extension RatchetGroup {
    public func add(participants: FindUsersResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.checkPermissions()

                let oldSet = self.participants
                let newSet = oldSet.union(participants.keys)

                try Group.validateParticipantsCount(newSet.count)

                guard newSet != oldSet else {
                    throw GroupError.invalidChangeParticipants
                }

                let addSet = newSet.subtracting(oldSet)

                let addedCards: [Card] = try addSet.map {
                    guard let card = participants[$0] else {
                        throw GroupError.inconsistentState
                    }

                    return card
                }

                let groupMessage = try self.session.createChangeParticipantsTicket()
                let ticket = RatchetTicket(groupMessage: groupMessage, participants: newSet)

                let newSetLookup = try self.lookupManager.lookupCards(of: Array(newSet))
                try self.groupManager.share(ticket: ticket, with: Array(newSetLookup.values))

                try self.session.updateParticipants(ticket: groupMessage, addCards: addedCards, removeCardIds: [])

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func remove(participants: FindUsersResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.checkPermissions()

                let oldSet = self.participants
                let newSet = oldSet.subtracting(participants.keys)

                try Group.validateParticipantsCount(newSet.count)

                guard newSet != oldSet else {
                    throw GroupError.invalidChangeParticipants
                }

                let groupMessage = try self.session.createChangeParticipantsTicket()
                let ticket = RatchetTicket(groupMessage: groupMessage, participants: newSet)

                try self.groupManager.share(ticket: ticket, with: Array(participants.values))

                let removeCardIds = participants.values.map { $0.identifier }
                try self.session.updateParticipants(ticket: groupMessage, addCards: [], removeCardIds: removeCardIds)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func added(users: FindUsersResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.identifier

                let card = try self.lookupManager.lookupCard(of: self.initiator)

                guard let ticket = self.groupManager.retrieveTicket(sessionId: sessionId, epoch: 0, from: card) else {
                    throw NSError()
                }

                try self.session.updateParticipants(ticket: ticket.groupMessage,
                                                    addCards: Array(users.values),
                                                    removeCardIds: [])

                self.participants = self.participants.union(users.keys)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func removed(users: FindUsersResult) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.identifier

                let card = try self.lookupManager.lookupCard(of: self.initiator)

                guard let ticket = self.groupManager.retrieveTicket(sessionId: sessionId, epoch: 0, from: card) else {
                    throw NSError()
                }

                try self.session.updateParticipants(ticket: ticket.groupMessage,
                                                    addCards: [],
                                                    removeCardIds: users.values.map { $0.identifier })

                self.participants = self.participants.union(users.keys)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
