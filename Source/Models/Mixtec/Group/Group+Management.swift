//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

import Foundation
import VirgilCryptoFoundation
import VirgilSDK

// MARK: - Extension with group management operations
extension Group {
    /// Updates group
    ///
    /// - Returns: CallbackOperation<Void>
    open func update() -> GenericOperation<Void> {
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

    /// Adds new participants to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameter participants: Cards of users to add. Result of findUsers call
    /// - Returns: CallbackOperation<Void>
    open func add(participants: FindUsersResult) -> GenericOperation<Void> {
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

                try self.shareTickets(for: addedCards, newSet: newSet)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Share group access and history on new Card of existing participant
    ///
    /// - Parameter participant: participant Card
    /// - Returns: CallbackOperation<Void>
    open func reAdd(participant: Card) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.checkPermissions()

                try self.groupManager.reAddAccess(to: participant,
                                                  sessionId: self.session.getSessionId())

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Removes participants from group
    ///
    /// - Note: Removed participant will not be able to decrypt previous history again after group update
    /// - Parameter participants: Cards of users to remove. Result of findUsers call
    /// - Returns: CallbackOperation<Void>
    open func remove(participants: FindUsersResult) -> GenericOperation<Void> {
        return self.remove(participants: Array(participants.keys))
    }

    /// Adds new participant to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameter card: Card of user to add
    /// - Returns: CallbackOperation<Void>
    open func add(participant card: Card) -> GenericOperation<Void> {
        return self.add(participants: [card.identity: card])
    }

    /// Removes participant from group
    ///
    /// - Parameter card: Card of user to remove
    /// - Returns: CallbackOperation<Void>
    open func remove(participant card: Card) -> GenericOperation<Void> {
        return self.remove(participants: [card.identity: card])
    }
}

extension Group {
    private func shareTickets(for cards: [Card], newSet: Set<String>) throws {
        let sessionId = self.session.getSessionId()

        try self.groupManager.addAccess(to: cards, newSet: newSet, sessionId: sessionId)

        self.participants = newSet
    }

    private func addNewTicket(for participants: FindUsersResult) throws {
        let newSet = Set(participants.keys)

        let ticketMessage = try self.session.createGroupTicket().getTicketMessage()
        let ticket = Ticket(groupMessage: ticketMessage, participants: newSet)

        _ = try self.groupManager.store(ticket, sharedWith: Array(participants.values))

        try self.session.addEpoch(message: ticket.groupMessage)

        self.participants = newSet.union([self.initiator])
    }
}

// MARK: - Extension with group management operations with string participants parameter
extension Group {
    /// Adds new participants to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameter participants: Identities of users to add
    /// - Returns: CallbackOperation<Void>
    open func add(participants: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let result = try self.lookupManager.lookupCards(of: participants,
                                                                forceReload: false,
                                                                checkResult: true)

                self.add(participants: result).start(completion: completion)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Adds new participant to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameter card: User to add
    /// - Returns: CallbackOperation<Void>
    open func add(participant: String) -> GenericOperation<Void> {
        return self.add(participants: [participant])
    }

    /// Share group access and history on new Card of existing participant
    ///
    /// - Parameter participant: participant to re add
    /// - Returns: CallbackOperation<Void>
    open func reAdd(participant: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.lookupManager.lookupCard(of: participant)

                self.reAdd(participant: card).start(completion: completion)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Removes participants from group
    ///
    /// - Note: Removed participant will not be able to decrypt previous history again after group update
    /// - Parameter participants: Users to remove
    /// - Returns: CallbackOperation<Void>
    open func remove(participants: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.checkPermissions()

                let oldSet = self.participants
                let newSet = oldSet.subtracting(participants)

                try Group.validateParticipantsCount(newSet.count)

                guard newSet != oldSet else {
                    throw GroupError.invalidChangeParticipants
                }

                let newSetLookup = try self.lookupManager.lookupCards(of: Array(newSet),
                                                                      forceReload: false,
                                                                      checkResult: true)

                try self.addNewTicket(for: newSetLookup)

                let removedSet = oldSet.subtracting(newSet)

                try self.groupManager.removeAccess(identities: removedSet, to: self.session.getSessionId())

                completion((), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Removes participant from group
    ///
    /// - Parameter participant: User to remove
    /// - Returns: CallbackOperation<Void>
    open func remove(participant: String) -> GenericOperation<Void> {
        return self.remove(participants: [participant])
    }
}
