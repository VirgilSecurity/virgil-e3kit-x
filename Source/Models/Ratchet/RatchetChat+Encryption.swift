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
import VirgilCryptoRatchet

extension RatchetChat {
    /// Encrypts data
    ///
    /// - Parameters:
    ///   - data: Data to encrypt
    /// - Returns: encrypted Data
    /// - Throws: corresponding error
    @objc open func encrypt(data: Data) throws -> Data {
        let ratchetMessage = try session.encrypt(data: data)

        try self.sessionStorage.storeSession(self.session)

        return ratchetMessage.serialize()
    }

    /// Decrypts data
    ///
    /// - Parameters:
    ///   - data: encrypted Data
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    @objc open func decrypt(data: Data) throws -> Data {
        let message = try RatchetMessage.deserialize(input: data)

        // TODO: Add check on proper session id (local and message one) - should add getter to crypto

        let decrypted = try session.decryptData(from: message)

        try self.sessionStorage.storeSession(self.session)

        return decrypted
    }

    /// Encrypts string for user
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    /// - Returns: encrypted String
    /// - Throws: corresponding error
    @objc open func encrypt(text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encrypt(data: data).base64EncodedString()
    }

    /// Decrypts string
    ///
    /// - Parameters:
    ///   - text: encrypted String
    /// - Returns: decrypted String
    /// - Throws: corresponding error
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

extension RatchetChat {
    @objc open func encryptMultiple(data: [Data]) throws -> [Data] {
        guard !data.isEmpty else {
            throw NSError()
        }

        var result: [Data] = []

        for item in data {
            let ratchetMessage = try session.encrypt(data: item)
            let encrypted = ratchetMessage.serialize()

            result.append(encrypted)
        }

        try self.sessionStorage.storeSession(self.session)

        return result
    }

    /// Decrypts multiple Data
    ///
    /// - Important: data should be in strict order by encryption time
    ///
    /// - Parameters:
    ///   - data: array with Data to decrypt
    /// - Returns: array with decrypted Data
    /// - Throws: corresponding error
    @objc open func decryptMultiple(data: [Data]) throws -> [Data] {
        guard !data.isEmpty else {
            throw EThreeRatchetError.decryptEmptyArray
        }

        var result: [Data] = []

        for encrypted in data {
            let message = try RatchetMessage.deserialize(input: encrypted)

            let decrypted = try session.decryptData(from: message)

            result.append(decrypted)
        }

        try self.sessionStorage.storeSession(self.session)

        return result
    }

    @objc open func encryptMultiple(text: [String]) throws -> [String] {
        let data = try self.stringToData(text)

        let encryptedData = try self.encryptMultiple(data: data)

        return try self.dataToString(encryptedData)
    }

    /// Decrypts multiple text
    ///
    /// - Important: text should be in strict order by encryption time
    ///
    /// - Parameters:
    ///   - text: array with String to decrypt
    /// - Returns: array with decrypted String
    /// - Throws: corresponding error
    @objc open func decryptMultiple(text: [String]) throws -> [String] {
        let data = try self.stringToData(text)

        let decryptedData = try self.decryptMultiple(data: data)

        return try self.dataToString(decryptedData)
    }

    private func dataToString(_ data: [Data]) throws -> [String] {
        return try data.map { (item: Data) throws -> String in
            guard let text = String(data: item, encoding: .utf8) else {
                throw EThreeError.strFromDataFailed
            }

            return text
        }
    }

    private func stringToData(_ text: [String]) throws -> [Data] {
        return try text.map { (item: String) throws -> Data in
            guard let data = Data(base64Encoded: item) else {
                throw EThreeError.strToDataFailed
            }

            return data
        }
    }
}
