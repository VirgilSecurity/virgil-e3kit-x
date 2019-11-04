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

import Foundation
import VirgilCrypto

/// Class representing Unsafe Chat
@objc(VTEUnsafeChat) public class UnsafeChat: NSObject {
    /// Identity of participant
    @objc public let participant: String

    internal let crypto: VirgilCrypto
    internal let participantPublicKey: VirgilPublicKey
    internal let selfPrivateKey: VirgilPrivateKey

    internal init(participant: String,
                  participantPublicKey: VirgilPublicKey,
                  selfPrivateKey: VirgilPrivateKey,
                  crypto: VirgilCrypto) {
        self.participant = participant
        self.participantPublicKey = participantPublicKey
        self.selfPrivateKey = selfPrivateKey
        self.crypto = crypto

        super.init()
    }
}

extension UnsafeChat {
    /// Encrypts data
    /// - Parameter data: Data to encrypt
    @objc open func encrypt(data: Data) throws -> Data {
        try self.crypto.authEncrypt(data, with: self.selfPrivateKey, for: [self.participantPublicKey])
    }

    /// Decrypts data
    /// - Parameter data: encrypted Data
    @objc open func decrypt(data: Data) throws -> Data {
        try self.crypto.authDecrypt(data, with: self.selfPrivateKey, usingOneOf: [self.participantPublicKey])
    }

    /// Encrypts string
    /// - Parameter text: String to encrypt
    @objc open func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    /// Decrypts string
    /// - Parameter text: encrypted String
    @objc open func decrypt(text: String) throws -> String {
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
