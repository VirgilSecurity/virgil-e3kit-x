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
    internal let crypto: VirgilCrypto

    internal let localKeyManager: LocalKeyManager
    internal let ticketManager: TicketManager
    internal let lookupManager: LookupManager

    internal var session: GroupSession
    public internal(set) var participants: [String]

    internal init(crypto: VirgilCrypto,
                  tickets: [Ticket],
                  localKeyManager: LocalKeyManager,
                  ticketManager: TicketManager,
                  lookupManager: LookupManager) throws {
        let tickets = tickets.sorted { $0.groupMessage.getEpoch() < $1.groupMessage.getEpoch() }

        guard let lastTicket = tickets.last else {
            throw NSError()
        }

        self.crypto = crypto
        self.participants = lastTicket.participants
        self.session = try Group.generateSession(from: tickets, crypto: crypto)
        self.localKeyManager = localKeyManager
        self.ticketManager = ticketManager
        self.lookupManager = lookupManager
    }

    private static func generateSession(from tickets: [Ticket], crypto: VirgilCrypto) throws -> GroupSession {
        let session = GroupSession()
        session.setRng(rng: crypto.rng)

        try tickets.forEach {
            try session.addEpoch(message: $0.groupMessage)
        }

        return session
    }

    internal func generateSession(from tickets: [Ticket]) throws -> GroupSession {
        return try Group.generateSession(from: tickets, crypto: self.crypto)
    }

    public func encrypt(data: Data) throws -> Data {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        let encrypted = try self.session.encrypt(plainText: data, privateKey: selfKeyPair.privateKey.key)

        return encrypted.serialize()
    }

    public func decrypt(data: Data, from senderCard: Card) throws -> Data {
        let encrypted = try GroupSessionMessage.deserialize(input: data)


        do {
            return try self.session.decrypt(message: encrypted, publicKey: senderCard.publicKey.key)
        } catch {
            let sessionId = encrypted.getSessionId()
            let messageEpoch = encrypted.getEpoch()

            guard let ticket = self.ticketManager.retrieve(sessionId: sessionId, epoch: messageEpoch) else {
                throw NSError()
            }

            let tempSession = try self.generateSession(from: [ticket])

            return try tempSession.decrypt(message: encrypted, publicKey: senderCard.publicKey.key)
        }
    }

    public func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    public func decrypt(text: String, from senderCard: Card) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: senderCard)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }
}

