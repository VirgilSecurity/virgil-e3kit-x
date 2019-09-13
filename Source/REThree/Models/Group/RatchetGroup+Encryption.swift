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

import VirgilSDKRatchet
import VirgilSDK
import VirgilCryptoRatchet

extension RatchetGroup {
    @objc public func encrypt(data: Data) throws -> Data {
        let encrypted = try self.session.encrypt(data: data)

        return encrypted.serialize()
    }

    @objc public func decrypt(data: Data, from senderCard: Card, date: Date? = nil) throws -> Data {
        let encrypted = try RatchetGroupMessage.deserialize(input: data)

        var card = senderCard
        if let date = date {
            while let previousCard = card.previousCard {
                guard card.createdAt > date else {
                    break
                }

                card = previousCard
            }
        }

        guard self.session.identifier == encrypted.getSessionId() else {
            throw GroupError.messageNotFromThisGroup
        }

        let messageEpoch = encrypted.getEpoch()
        let currentEpoch = self.session.currentEpoch

        guard messageEpoch >= currentEpoch else {
            // Old message can't be decrypted
            throw NSError()
        }

        guard currentEpoch <= messageEpoch else {
            throw GroupError.groupIsOutdated
        }

        // TODO: add verification failed error
        return try self.session.decryptData(from: encrypted, senderCardId: senderCard.identifier)
    }

    @objc public func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    @objc public func decrypt(text: String, from senderCard: Card, date: Date? = nil) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: senderCard, date: date)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }
}

