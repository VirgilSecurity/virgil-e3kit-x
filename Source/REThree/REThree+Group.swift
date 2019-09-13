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
import VirgilSDKRatchet
import VirgilCryptoRatchet

extension REThree {
    public func createGroup(id identifier: Data, with users: FindUsersResult) -> GenericOperation<RatchetGroup> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let participants = Set(users.keys + [self.identity])
                try RatchetGroup.validateParticipantsCount(participants.count)

                let cards = Array(users.values)

                let secureChat = try self.getSecureChat()
                let manager = try self.getGroupManager()

                // Generate session
                let ratchetMessage = try secureChat.startNewGroupSession(sessionId: sessionId)
                let ticket = RatchetTicket(groupMessage: ratchetMessage, participants: participants)

                let session = try secureChat.startGroupSession(with: cards,
                                                               sessionId: sessionId,
                                                               using: ticket.groupMessage)

                // Store and share session
                try manager.share(ticket: ticket, with: cards)

                let group = try manager.store(session: session,
                                              participants: participants)

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func getGroup(id identifier: Data) throws -> RatchetGroup? {
        let sessionId = try self.computeSessionId(from: identifier)

        return try self.getGroupManager().retrieve(sessionId: sessionId)
    }

    public func joinGroup(id identifier: Data, with users: FindUsersResult, initiator card: Card) -> GenericOperation<RatchetGroup> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let manager = try self.getGroupManager()

                guard let ticket = manager.retrieveTicket(sessionId: sessionId, epoch: 0, from: card) else {
                    throw NSError()
                }

                let session = try self.getSecureChat().startGroupSession(with: Array(users.values),
                                                                         sessionId: sessionId,
                                                                         using: ticket.groupMessage)

                let group = try manager.store(session: session, participants: ticket.participants)

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func deleteGroup(id identifier: Data) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let groupManager = try self.getGroupManager()

                // TODO: Hide in group manager?
                guard let group = groupManager.retrieve(sessionId: sessionId) else {
                    throw NSError()
                }

                try group.checkPermissions()

                try groupManager.delete(sessionId: sessionId)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
