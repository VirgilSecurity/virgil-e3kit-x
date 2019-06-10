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

// MARK: - Extension with encrypt-decrypt operations
extension EThree {
    /// Typealias for the valid result of lookupPublicKeys call
    public typealias LookupResult = [String: VirgilPublicKey]

    /// Signs then encrypts data for group of users
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    ///                    Use nil to sign and encrypt for self
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc public func encrypt(data: Data, for recipientKeys: LookupResult? = nil) throws -> Data {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        var publicKeys = [selfKeyPair.publicKey]

        if let recipientKeys = recipientKeys {
            guard !recipientKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            publicKeys += recipientKeys.values
        }

        let encryptedData = try self.crypto.signThenEncrypt(data, with: selfKeyPair.privateKey, for: publicKeys)

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
    @objc public func decrypt(data: Data, from senderPublicKey: VirgilPublicKey? = nil) throws -> Data {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        let senderPublicKey = senderPublicKey ?? selfKeyPair.publicKey

        let decryptedData = try self.crypto.decryptThenVerify(data,
                                                              with: selfKeyPair.privateKey,
                                                              using: senderPublicKey)

        return decryptedData
    }

    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    ///                    Use nil to sign and encrypt for self
    /// - Throws: corresponding error
    @objc public func encrypt(_ stream: InputStream, to outputStream: OutputStream,
                              for recipientKeys: LookupResult? = nil) throws {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

        var publicKeys = [selfKeyPair.publicKey]

        if let recipientKeys = recipientKeys {
            guard !recipientKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            publicKeys += recipientKeys.values
        }

        try self.crypto.encrypt(stream, to: outputStream, for: publicKeys)
    }

    /// Decrypts data stream
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    /// - Throws: corresponding error
    @objc public func decrypt(_ stream: InputStream, to outputStream: OutputStream) throws {
        let selfKeyPair = try self.localKeyManager.retrieveKeyPair()

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
    @objc public func encrypt(text: String, for recipientKeys: LookupResult? = nil) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data, for: recipientKeys).base64EncodedString()
    }

    /// Decrypts and verifies base64 string from users
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - senderPublicKey: sender PublicKey to verify with. Use nil to decrypt and verify from self.
    /// - Returns: decrypted String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc public func decrypt(text: String, from senderPublicKey: VirgilPublicKey? = nil) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: senderPublicKey)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Retrieves user public keys from the cloud for encryption/verification.
    ///
    /// - Parameter identities: array of identities to search for
    /// - Returns: CallbackOperation<Void>
    public func lookupPublicKeys(of identities: [String]) -> GenericOperation<LookupResult> {
        return CallbackOperation { _, completion in
            do {
                guard !identities.isEmpty else {
                    throw EThreeError.missingIdentities
                }

                let cards = try self.cardManager.searchCards(identities: identities).startSync().getResult()

                var result: LookupResult = [:]

                for card in cards {
                    guard let virgilPublicKey = card.publicKey as? VirgilPublicKey else {
                        throw EThreeError.keyIsNotVirgil
                    }

                    guard result[card.identity] == nil else {
                        throw EThreeError.duplicateCards
                    }

                    result[card.identity] = virgilPublicKey
                }

                completion(result, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
