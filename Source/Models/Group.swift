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
import VirgilCrypto

public class Group {
    public static let ValidParticipatnsCountRange = 2...100

    public let initiator: String
    public internal(set) var participants: Set<String>

    internal let selfIdentity: String
    internal let crypto: VirgilCrypto
    internal let localKeyStorage: LocalKeyStorage
    internal let groupManager: GroupManager
    internal let lookupManager: LookupManager

    internal var session: GroupSession

    internal init(rawGroup: RawGroup,
                  crypto: VirgilCrypto,
                  localKeyStorage: LocalKeyStorage,
                  groupManager: GroupManager,
                  lookupManager: LookupManager) throws {
        let tickets = rawGroup.tickets.sorted { $0.groupMessage.getEpoch() < $1.groupMessage.getEpoch() }

        guard let lastTicket = tickets.last else {
            throw EThreeError.invalidGroup
        }

        try Group.validateParticipantsCount(lastTicket.participants.count)

        self.initiator = rawGroup.info.initiator
        self.selfIdentity = localKeyStorage.identity
        self.participants = lastTicket.participants
        self.crypto = crypto
        self.session = try Group.generateSession(from: tickets, crypto: crypto)
        self.localKeyStorage = localKeyStorage
        self.groupManager = groupManager
        self.lookupManager = lookupManager
    }

    internal static func validateParticipantsCount(_ count: Int) throws {
        guard Group.ValidParticipatnsCountRange ~= count else {
            throw EThreeError.invalidParticipantsCount
        }
    }

    private static func generateSession(from tickets: [Ticket], crypto: VirgilCrypto) throws -> GroupSession {
        let session = GroupSession()
        session.setRng(rng: crypto.rng)

        try tickets.forEach {
            try session.addEpoch(message: $0.groupMessage)
        }

        return session
    }

    internal func checkPermissions() throws {
        guard self.selfIdentity == self.initiator else {
            throw EThreeError.groupPermissionDenied
        }
    }

    internal func generateSession(from tickets: [Ticket]) throws -> GroupSession {
        return try Group.generateSession(from: tickets, crypto: self.crypto)
    }
}

