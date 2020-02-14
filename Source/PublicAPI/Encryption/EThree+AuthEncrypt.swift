//
// Copyright (C) 2015-2020 Virgil Security Inc.
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

// MARK: - Extension with peer-to-pear encrypt and decrypt operations
extension EThree {
    /// Signs then encrypts data (and signature) for user
    ///
    /// - Important: Deprecated decrypt method is unable to decrypt result of this method
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - user: user Card to encrypt for
    /// - Returns: encrypted data
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(authEncryptData:forUser:error:)
    open func authEncrypt(data: Data, for user: Card) throws -> Data {
        return try self.authEncrypt(data: data, for: [user.identity: user])
    }

    /// Signs then encrypts string (and signature) for user
    ///
    /// - Important: Deprecated decrypt method is unable to decrypt result of this method
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - user: user Card to encrypt for
    /// - Returns: encrypted String
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(authEncryptText:forUser:error:)
    open func authEncrypt(text: String, for user: Card) throws -> String {
        return try self.authEncrypt(text: text, for: [user.identity: user])
    }

    /// Decrypts data and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - user: sender Card with Public Key to verify with. Use nil to decrypt and verify from self
    /// - Returns: decrypted Data
    /// - Important: Requires private key in local storage
    @objc(authDecryptData:fromUsers:error:)
    open func authDecrypt(data: Data, from user: Card? = nil) throws -> Data {
        return try self.decryptInternal(data: data, from: user?.publicKey)
    }

    /// Decrypts data and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - user: sender Card with Public Key to verify with
    ///   - date: date of encryption to use proper card version
    /// - Returns: decrypted Data
    /// - Important: Requires private key in local storage
    @objc(authDecryptData:fromUsers:date:error:)
    open func authDecrypt(data: Data, from user: Card, date: Date) throws -> Data {
        var card = user

        while let previousCard = card.previousCard {
            guard card.createdAt > date else {
                break
            }

            card = previousCard
        }

        return try self.decryptInternal(data: data, from: card.publicKey)
    }

    /// Decrypts base64 string and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - user: sender Card with Public Key to verify with. Use nil to decrypt and verify from self.
    /// - Returns: decrypted String
    /// - Important: Requires private key in local storage
    @objc(authDecryptText:fromUser:error:)
    open func authDecrypt(text: String, from user: Card? = nil) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.authDecrypt(data: data, from: user)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Decrypts base64 string and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - user: sender Card with Public Key to verify with
    ///   - date: date of encryption to use proper card version
    /// - Returns: decrypted String
    /// - Important: Requires private key in local storage
    @objc(authDecryptText:fromUser:date:error:)
    open func authDecrypt(text: String, from user: Card, date: Date) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.authDecrypt(data: data, from: user, date: date)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Signs then encrypts string (and signature) for group of users
    ///
    /// - Important: Deprecated decrypt method is unable to decrypt result of this method
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - users: result of findUsers call recipient Cards with Public Keys to sign and encrypt with.
    ///            Use nil to sign and encrypt for self
    /// - Returns: encrypted base64String
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc(authEncryptText:forUsers:error:)
    open func authEncrypt(text: String, for users: FindUsersResult? = nil) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.authEncrypt(data: data, for: users).base64EncodedString()
    }

    /// Signs then encrypts string (and signature) for group of users
    ///
    /// - Important: Deprecated decrypt method is unable to decrypt result of this method
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - users: result of findUsers call recipient Cards with Public Keys to sign and encrypt with.
    ///            Use nil to sign and encrypt for self
    /// - Returns: decrypted Data
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc(authEncryptData:forUsers:error:)
    open func authEncrypt(data: Data, for users: FindUsersResult? = nil) throws -> Data {
        return try self.encryptInternal(data: data, for: users?.map { $1.publicKey })
    }
}

extension EThree {
    internal func encryptInternal(data: Data, for publicKeys: [VirgilPublicKey]?) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var pubKeys = [selfKeyPair.publicKey]

        if let publicKeys = publicKeys {
            guard !publicKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            pubKeys += publicKeys
        }

        let encryptedData = try self.crypto.authEncrypt(data, with: selfKeyPair.privateKey, for: pubKeys)

        return encryptedData
    }

    internal func decryptInternal(data: Data, from publicKey: VirgilPublicKey?) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let publicKey = publicKey ?? selfKeyPair.publicKey

        do {
            return try self.crypto.authDecrypt(data,
                                               with: selfKeyPair.privateKey,
                                               usingOneOf: [publicKey])
        } catch VirgilCryptoError.signatureNotVerified {
            throw EThreeError.verificationFailed
        }
    }
}
