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
import VirgilCryptoFoundation

extension EThree {
    public func encryptForGroup(withId identifier: Data, message: Data) throws -> Data {
        let session = try self.getSession(withId: identifier)

        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        // FIXME
        let selfCardId = "FIXME"

        guard let myId = Data(hexEncodedString: selfCardId) else {
            throw NSError()
        }

        let encrypted = try session.encrypt(plainText: message, privateKey: selfKeyPair.privateKey.key, senderId: myId)

        return encrypted.serialize()
    }

    public func decryptFromGroup(withId identifier: Data, data: Data, author senderCard: Card) throws -> Data {
        let session = try self.getSession(withId: identifier)

        let encrypted = try GroupSessionMessage.deserialize(input: data)

        guard encrypted.getEpoch() == session.getCurrentEpoch() else {
            throw NSError()
        }

        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        guard let senderId = Data(hexEncodedString: senderCard.identifier) else {
            throw NSError()
        }

        return try session.decrypt(message: encrypted, publicKey: selfKeyPair.publicKey.key, senderId: senderId)
    }

    public func encryptForGroup(withId identifier: Data, text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encryptForGroup(withId: identifier, message: data).base64EncodedString()
    }

    public func decryptFromGroup(withId identifier: Data, text: String, author senderCard: Card) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decryptFromGroup(withId: identifier, data: data, author: senderCard)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }
}
