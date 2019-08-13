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
import VirgilCrypto

// MARK: - Extension with pear-to-pear encrypt and decrypt operations
extension EThree {
    /// Signs then encrypts data for group of users
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - recipientKeys: result of lookupCards call recipient PublicKeys to sign and encrypt with.
    ///                    Use nil to sign and encrypt for self
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc public func encrypt(data: Data, for recipientCards: LookupResult? = nil) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var publicKeys = [selfKeyPair.publicKey]

        if let recipientCards = recipientCards {
            guard !recipientCards.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            let recipientKeys = recipientCards.values.map { $0.publicKey }

            publicKeys += recipientKeys
        }

        let encryptedData = try self.crypto.signAndEncrypt(data, with: selfKeyPair.privateKey, for: publicKeys)

        return encryptedData
    }

    /// Decrypts and verifies data from users
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - senderPublicKey: sender PublicKey to verify with. Use nil to decrypt and verify from self
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func decrypt(data: Data, from senderCard: Card? = nil, date: Date? = nil) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var card = try senderCard ?? self.lookupManager.lookupCachedCard(of: self.identity)

        if let date = date {
            while let previousCard = card.previousCard {
                guard card.createdAt > date else {
                    break
                }

                card = previousCard
            }
        }

        do {
            return try self.crypto.decryptAndVerify(data,
                                                    with: selfKeyPair.privateKey,
                                                    using: card.publicKey)
        } catch VirgilCryptoError.signatureNotVerified {
            throw EThreeError.verificationFailed
        }
    }

    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    ///                    Use nil to sign and encrypt for self
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc public func encrypt(_ stream: InputStream,
                              to outputStream: OutputStream,
                              for recipientCards: LookupResult? = nil) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var publicKeys = [selfKeyPair.publicKey]

        if let recipientCards = recipientCards {
            guard !recipientCards.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            let recipientKeys = recipientCards.values.map { $0.publicKey }

            publicKeys += recipientKeys
        }

        try self.crypto.encrypt(stream, to: outputStream, for: publicKeys)
    }

    /// Decrypts data stream
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func decrypt(_ stream: InputStream, to outputStream: OutputStream) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        try self.crypto.decrypt(stream, to: outputStream, with: selfKeyPair.privateKey)
    }

    /// Signs then encrypts string for group of users
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    ///                    Use nil to sign and encrypt for self
    /// - Returns: encrypted base64String
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc public func encrypt(text: String, for recipientCards: LookupResult? = nil) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data, for: recipientCards).base64EncodedString()
    }

    /// Decrypts and verifies base64 string from users
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - senderPublicKey: sender PublicKey to verify with. Use nil to decrypt and verify from self.
    /// - Returns: decrypted String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func decrypt(text: String, from senderCard: Card? = nil, date: Date? = nil) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: senderCard, date: date)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Signs and encrypts data for user
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - recipientCard: user Card to encrypt for
    /// - Returns: encrypted data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    public func encrypt(data: Data, for recipientCard: Card) throws -> Data {
        return try self.encrypt(data: data, for: [recipientCard.identity: recipientCard])
    }

    /// Signs and encrypts string for user
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - recipientCard: user Card to encrypt for
    /// - Returns: encrypted String
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    public func encrypt(text: String, for recipientCard: Card) throws -> String {
        return try self.encrypt(text: text, for: [recipientCard.identity: recipientCard])
    }

    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - recipientCard: user Card to encrypt for
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    public func encrypt(_ stream: InputStream, to outputStream: OutputStream, for recipientCard: Card) throws {
        try self.encrypt(stream, to: outputStream, for: [recipientCard.identity: recipientCard])
    }
}