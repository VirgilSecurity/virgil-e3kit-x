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


// MARK: - Extension with encrypt/decrypt file stream operations
extension EThree {
    /// Encrypts file stream with a new private key.
    ///
    /// File is signed with a private key from the local storage.
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - streamSize: total stream size in bytes
    ///   - outputStream: stream with encrypted data
    /// - Returns:
    ///    - serialized private key
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage to sign stream
    @objc(encryptSharedStream:withSize:toStream:error:)
    open func encryptShared(_ stream: InputStream,
                          streamSize: Int,
                          to outputStream: OutputStream) throws -> Data {

        let sharedKeyPair = try self.crypto.generateKeyPair()
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        try self.crypto.authEncrypt(stream,
                    streamSize: streamSize,
                    to: outputStream,
                    with: selfKeyPair.privateKey,
                    for: [sharedKeyPair.publicKey])

        return try self.crypto.exportPrivateKey(sharedKeyPair.privateKey)
    }

    /// Decrypts file stream.
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    ///   - privateKeyData: serialized private key to decrypt file stream
    ///   - senderCard: sender Card with Public Key to verify with
    /// - Throws: corresponding error
    @objc(decryptSharedStream:toStream:with:verifyWithSenderCard:error:)
    open func decryptShared(_ stream: InputStream,
                                to outputStream: OutputStream,
                                with privateKeyData: Data,
                                verifyWith senderCard: Card) throws {

        return try self.decryptShared(stream, to: outputStream, with: privateKeyData, verifyWith: senderCard.publicKey)
    }

    /// Decrypts file stream.
    ///
    /// - Parameters:
    ///   - stream: stream with encrypted data
    ///   - outputStream: stream with decrypted data
    ///   - privateKeyData: serialized private key to decrypt file stream
    ///   - senderPublicKey: sender Public Key to verify with, if nill then self public key is used
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage, if senderPublicKey is not given
    @objc(decryptSharedStream:toStream:with:verifyWithSenderPublicKey:error:)
    open func decryptShared(_ stream: InputStream,
                                to outputStream: OutputStream,
                                with privateKeyData: Data,
                                verifyWith senderPublicKey: VirgilPublicKey? = nil) throws {

        let keyPair = try self.crypto.importPrivateKey(from: privateKeyData)
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let publicKey = senderPublicKey ?? selfKeyPair.publicKey

        try self.crypto.authDecrypt(stream, to: outputStream, with: keyPair.privateKey, usingOneOf: [publicKey])
    }
}
