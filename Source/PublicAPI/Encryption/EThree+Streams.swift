//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

import Foundation
import VirgilCrypto
import VirgilSDK

// MARK: - Extension with streams encrypt and decrypt operations
extension EThree {
    /// Signs then encrypts stream and signature for user
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - user: user Card to encrypt for
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    @objc(authEncryptStream:withSize:toStream:forUser:error:)
    public func authEncrypt(
        _ stream: InputStream,
        streamSize: Int,
        to outputStream: OutputStream,
        for user: Card
    ) throws {
        try self.authEncrypt(
            stream, streamSize: streamSize, to: outputStream, for: [user.identity: user])
    }

    /// Signs then encrypts stream and signature for users
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
    @objc(authEncryptStream:withSize:toStream:forUsers:error:)
    public func authEncrypt(
        _ stream: InputStream,
        streamSize: Int,
        to outputStream: OutputStream,
        for users: FindUsersResult? = nil
    ) throws {
        try self.encryptInternal(
            stream, streamSize: streamSize, to: outputStream, for: users?.map { $1.publicKey })
    }

    /// Decrypts stream and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    ///   - user: sender Card with Public Key to verify with. Use nil to decrypt and verify from self.
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc open func authDecrypt(
        _ stream: InputStream, to outputStream: OutputStream, from user: Card? = nil
    ) throws {
        try self.decryptInternal(stream, to: outputStream, from: user?.publicKey)
    }

    /// Decrypts stream and signature and verifies signature of sender
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    ///   - user: sender Card with Public Key to verify with
    ///   - date: date of encryption to use proper card version
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @objc open func authDecrypt(
        _ stream: InputStream,
        to outputStream: OutputStream,
        from user: Card,
        date: Date
    ) throws {
        var card = user

        while let previousCard = card.previousCard {
            guard card.createdAt > date else {
                break
            }

            card = previousCard
        }

        try self.decryptInternal(stream, to: outputStream, from: card.publicKey)
    }
}

extension EThree {
    internal func encryptInternal(
        _ stream: InputStream,
        streamSize: Int,
        to outputStream: OutputStream,
        for publicKeys: [VirgilPublicKey]?
    ) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        var pubKeys = [selfKeyPair.publicKey]

        if let publicKeys = publicKeys {
            guard !publicKeys.isEmpty else {
                throw EThreeError.missingPublicKey
            }

            pubKeys += publicKeys
        }

        try self.crypto.authEncrypt(
            stream,
            streamSize: streamSize,
            to: outputStream,
            with: selfKeyPair.privateKey,
            for: pubKeys)
    }

    internal func decryptInternal(
        _ stream: InputStream,
        to outputStream: OutputStream,
        from publicKey: VirgilPublicKey?
    ) throws {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let publicKey = publicKey ?? selfKeyPair.publicKey

        try self.crypto.authDecrypt(
            stream,
            to: outputStream,
            with: selfKeyPair.privateKey,
            usingOneOf: [publicKey])
    }
}
