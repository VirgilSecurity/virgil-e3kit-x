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

// MARK: - Extension with group encrypt and decrypt operations
extension Group {
    /// Signs and encrypts data for group
    ///
    /// - Parameter data: data to encrypt
    /// - Returns: encrypted data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func encrypt(data: Data) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let encrypted = try self.session.encrypt(plainText: data, privateKey: selfKeyPair.privateKey.key)

        return encrypted.serialize()
    }

    /// Decrypts and verifies data from group participant
    ///
    /// - Parameters:
    ///   - data: encrypted data
    ///   - senderCard: sender Card to verify with
    ///   - date: date of message. Use it to prevent verifying new messages with old card
    /// - Returns: decrypted data
    /// - Throws: corresponding error
    @objc public func decrypt(data: Data, from senderCard: Card, date: Date? = nil) throws -> Data {
        let encrypted = try GroupSessionMessage.deserialize(input: data)

        var card = senderCard
        if let date = date {
            while let previousCard = card.previousCard {
                guard card.createdAt > date else {
                    break
                }

                card = previousCard
            }
        }

        guard self.session.getSessionId() == encrypted.getSessionId() else {
            throw GroupError.messageNotFromThisGroup
        }

        let messageEpoch = encrypted.getEpoch()
        let currentEpoch = self.session.getCurrentEpoch()

        guard currentEpoch >= messageEpoch else {
            throw GroupError.groupIsOutdated
        }

        do {
            if currentEpoch - messageEpoch < GroupManager.MaxTicketsInGroup {
                return try self.session.decrypt(message: encrypted, publicKey: card.publicKey.key)
            } else {
                let sessionId = encrypted.getSessionId()
                let messageEpoch = encrypted.getEpoch()

                guard let tempGroup = self.groupManager.retrieve(sessionId: sessionId, epoch: messageEpoch) else {
                    throw GroupError.missingCachedGroup
                }

                return try tempGroup.decrypt(data: data, from: senderCard)
            }
        } catch FoundationError.errorInvalidSignature {
            throw EThreeError.verificationFailed
        }
    }

    /// Signs then encrypts string for group
    ///
    /// - Parameter text: String to encrypt
    /// - Returns: encrypted base64String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    /// Decrypts and verifies base64 string from group participant
    ///
    /// - Parameters:
    ///   - text: encryted String
    ///   - senderCard: sender Card to verify with
    ///   - date: date of message. Use it to prevent verifying new messages with old card
    /// - Returns: decrypted String
    /// - Throws: corresponding error
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
