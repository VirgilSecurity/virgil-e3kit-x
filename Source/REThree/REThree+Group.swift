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
//                let sessionId = try self.computeSessionId(from: identifier)
//
//                let participants = Set(users.keys + [self.identity])
//
//                try Group.validateParticipantsCount(participants.count)
//
//                let secureChat = try self.getSecureChat()
//
//                let ratchetMessage = try secureChat.startNewGroupSession(sessionId: sessionId)
//
//                // Do we even need this class ?
//                let ticket = RatchetTicket(groupMessage: ratchetMessage, participants: participants)
//
//                let session = try secureChat.startGroupSession(with: Array(users.values),
//                                                               sessionId: sessionId,
//                                                               using: ticket.groupMessage)

                

//                let group = try self.getGroupManager().store(ticket, sharedWith: Array(users.values))
//
//                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
