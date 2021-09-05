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

import VirgilCryptoFoundation
import VirgilCrypto

internal class Ticket: Codable {
    internal let groupMessage: GroupSessionMessage
    internal let participants: Set<String>

    private enum CodingKeys: String, CodingKey {
        case groupMessage = "group_message"
        case participants = "participants"
    }

    internal func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        let groupMessageData = self.groupMessage.serialize()

        try container.encode(groupMessageData, forKey: .groupMessage)
        try container.encode(participants, forKey: .participants)
    }

    internal required convenience init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let groupMessageData = try container.decode(Data.self, forKey: .groupMessage)

        let groupMessage = try GroupSessionMessage.deserialize(input: groupMessageData)

        let participants = try container.decode(Set<String>.self, forKey: .participants)

        self.init(groupMessage: groupMessage, participants: participants)
    }

    internal static func deserialize(_ data: Data) throws -> Ticket {
        return try JSONDecoder().decode(Ticket.self, from: data)
    }

    internal func serialize() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    internal init(groupMessage: GroupSessionMessage, participants: Set<String>) {
        self.groupMessage = groupMessage
        self.participants = participants
    }

    internal convenience init(crypto: VirgilCrypto, sessionId: Data, participants: Set<String>) throws {
        let ticket = GroupSessionTicket()
        ticket.setRng(rng: crypto.rng)

        try ticket.setupTicketAsNew(sessionId: sessionId)

        let ticketMessage = ticket.getTicketMessage()

        self.init(groupMessage: ticketMessage, participants: participants)
    }
}
