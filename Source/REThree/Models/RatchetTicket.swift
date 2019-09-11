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

import VirgilCryptoRatchet

// TODO: Generic class with Ticket?
internal class RatchetTicket: Codable {
    internal let groupMessage: RatchetGroupMessage
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

        let groupMessage = try RatchetGroupMessage.deserialize(input: groupMessageData)

        let participants = try container.decode(Set<String>.self, forKey: .participants)

        self.init(groupMessage: groupMessage, participants: participants)
    }

    internal static func deserialize(_ data: Data) throws -> RatchetTicket {
        return try JSONDecoder().decode(RatchetTicket.self, from: data)
    }

    internal func serialize() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    internal init(groupMessage: RatchetGroupMessage, participants: Set<String>) {
        self.groupMessage = groupMessage
        self.participants = participants
    }
}
