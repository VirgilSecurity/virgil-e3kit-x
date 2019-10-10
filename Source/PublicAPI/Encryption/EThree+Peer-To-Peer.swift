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

// MARK: - Extension with peer-to-pear encrypt and decrypt operations
public extension EThree {
    /// Signs and encrypts data for user
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - user: user Card to encrypt for
    /// - Returns: encrypted data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(encryptData:forUser:error:)
    func encrypt(data: Data, for user: Card) throws -> Data {
        return try self.encrypt(data: data, for: [user.identity: user])
    }

    /// Signs and encrypts string for user
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - user: user Card to encrypt for
    /// - Returns: encrypted String
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(encryptText:forUser:error:)
    func encrypt(text: String, for user: Card) throws -> String {
        return try self.encrypt(text: text, for: [user.identity: user])
    }

    /// Decrypts and verifies data from users
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - user: sender Card with Public Key to verify with. Use nil to decrypt and verify from self
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc(decryptData:fromUsers:error:)
    func decrypt(data: Data, from user: Card? = nil) throws -> Data {
        return try self.decryptInternal(data: data, from: user?.publicKey)
    }

    /// Decrypts and verifies data from users
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - user: sender Card with Public Key to verify with
    ///   - date: date of encryption to use proper card version
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc(decryptData:fromUsers:date:error:)
    func decrypt(data: Data, from user: Card, date: Date) throws -> Data {
        var card = user

        while let previousCard = card.previousCard {
            guard card.createdAt > date else {
                break
            }

            card = previousCard
        }

        return try self.decryptInternal(data: data, from: card.publicKey)
    }

    /// Decrypts and verifies base64 string from users
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - user: sender Card with Public Key to verify with. Use nil to decrypt and verify from self.
    /// - Returns: decrypted String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc(decryptText:fromUser:error:)
    func decrypt(text: String, from user: Card? = nil) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: user)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Decrypts and verifies base64 string from users
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - user: sender Card with Public Key to verify with
    ///   - date: date of encryption to use proper card version
    /// - Returns: decrypted String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc(decryptText:fromUser:date:error:)
    func decrypt(text: String, from user: Card, date: Date) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decrypt(data: data, from: user, date: date)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    /// Signs then encrypts string for group of users
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - users: result of findUsers call recipient Cards with Public Keys to sign and encrypt with.
    ///            Use nil to sign and encrypt for self
    /// - Returns: encrypted base64String
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc(encryptText:forUsers:error:)
    func encrypt(text: String, for users: FindUsersResult? = nil) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data, for: users).base64EncodedString()
    }

    /// Signs then encrypts data for group of users
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - user: result of findUsers call recipient Cards with Public Keys to sign and encrypt with.
    ///           Use nil to sign and encrypt for self
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc(encryptData:forUsers:error:)
    func encrypt(data: Data, for users: FindUsersResult? = nil) throws -> Data {
        return try self.encryptInternal(data: data, for: users?.map { $1.publicKey })
    }
}

// MARK: - Extension with streams peer-to-pear encrypt and decrypt operations
public extension EThree {
    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - user: user Card to encrypt for
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(encryptStream:toStream:forUser:error:)
    func encrypt(_ stream: InputStream, to outputStream: OutputStream, for user: Card) throws {
        try self.encrypt(stream, to: outputStream, for: [user.identity: user])
    }

    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - users: result of findUsers call recipient Cards with Public Keys to sign and encrypt with.
    ///            Use nil to sign and encrypt for self
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @objc(encryptStream:toStream:forUsers:error:)
    func encrypt(_ stream: InputStream,
                        to outputStream: OutputStream,
                        for users: FindUsersResult? = nil) throws {
        try self.encryptInternal(stream, to: outputStream, for: users?.map { $1.publicKey })
    }

    /// Decrypts data stream
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc func decrypt(_ stream: InputStream, to outputStream: OutputStream) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        try self.crypto.decrypt(stream, to: outputStream, with: selfKeyPair.privateKey)
    }
}

internal extension EThree {
    func lookupResultToPublicKeys(_ lookupResult: LookupResult?) -> [VirgilPublicKey]? {
        guard let lookupResult = lookupResult else {
            return nil
        }

        return [VirgilPublicKey](lookupResult.values)
    }

    func encryptInternal(_ stream: InputStream,
                         to outputStream: OutputStream,
                         for publicKeys: [VirgilPublicKey]?) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var pubKeys = [selfKeyPair.publicKey]

        if let publicKeys = publicKeys {
            guard !publicKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            pubKeys += publicKeys
        }

        try self.crypto.encrypt(stream, to: outputStream, for: pubKeys)
    }

    func encryptInternal(data: Data, for publicKeys: [VirgilPublicKey]?) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var pubKeys = [selfKeyPair.publicKey]

        if let publicKeys = publicKeys {
            guard !publicKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            pubKeys += publicKeys
        }

        let encryptedData = try self.crypto.signAndEncrypt(data, with: selfKeyPair.privateKey, for: pubKeys)

        return encryptedData
    }

    func decryptInternal(data: Data, from publicKey: VirgilPublicKey?) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let publicKey = publicKey ?? selfKeyPair.publicKey

        do {
            return try self.crypto.decryptAndVerify(data,
                                                    with: selfKeyPair.privateKey,
                                                    using: publicKey)
        } catch VirgilCryptoError.signatureNotVerified {
            throw EThreeError.verificationFailed
        }
    }
}