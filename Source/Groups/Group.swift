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
    internal let session: GroupSession
    public let participants: [String]

    private let localKeyManager: LocalKeyManager

    internal init(crypto: VirgilCrypto, tickets: [Ticket], localKeyManager: LocalKeyManager) throws {
        let session = GroupSession()
        session.setRng(rng: crypto.rng)

        guard !tickets.isEmpty else {
            throw NSError()
        }

        try tickets.forEach {
            try session.addEpoch(message: $0.groupMessage)
        }

        guard let currentTicket = tickets.first(where: { $0.groupMessage.getEpoch() == session.getCurrentEpoch() }) else {
            throw NSError()
        }

        self.session = session
        self.participants = currentTicket.participants
        self.localKeyManager = localKeyManager
    }

    public func encrypt(data: Data) throws -> Data {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        let encrypted = try session.encrypt(plainText: data, privateKey: selfKeyPair.privateKey.key)

        return encrypted.serialize()
    }

    public func decrypt(data: Data) throws -> Data {
        let encrypted = try GroupSessionMessage.deserialize(input: data)

        guard encrypted.getEpoch() == session.getCurrentEpoch() else {
            throw NSError()
        }

        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        return try session.decrypt(message: encrypted, publicKey: selfKeyPair.publicKey.key)
    }

    public func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    public func decrypt(text: String) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }
}

