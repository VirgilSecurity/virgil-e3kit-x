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
import XCTest

@testable import VirgilE3Kit

class VTE011_EncryptSharedFileTests: XCTestCase {
    let utils = TestUtils()

    func test01__encrypt_shared__then_decrypt_with_implicit_self_verify__should_be_equal() {
        let ethree = try! self.utils.setupDevice()

        // Encrypt.
        let plaintext = UUID().uuidString
        let plaintextData = plaintext.data(using: .utf8)!
        let plaintextInputStream = InputStream(data: plaintextData)
        let ciphertextOutputStream = OutputStream.toMemory()

        let fileKeyData = try! ethree.encryptShared(
            plaintextInputStream,
            streamSize: plaintextData.count,
            to: ciphertextOutputStream
        )
        let ciphertextData = ciphertextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // Decrypt.
        let ciphertextInputStream = InputStream(data: ciphertextData)
        let plaintextOutputStream = OutputStream.toMemory()

        try! ethree.decryptShared(ciphertextInputStream, to: plaintextOutputStream, with: fileKeyData)
        let decryptedPlaintextData = plaintextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let decryptedPlaintext = String(bytes: decryptedPlaintextData, encoding: .utf8)!

        // Check.
        XCTAssertEqual(plaintext, decryptedPlaintext)
    }

    func test02__encrypt_shared__then_decrypt_with_explicit_self_verify__should_be_equal() {
        let ethree = try! self.utils.setupDevice()

        // Encrypt.
        let plaintext = UUID().uuidString
        let plaintextData = plaintext.data(using: .utf8)!
        let plaintextInputStream = InputStream(data: plaintextData)
        let ciphertextOutputStream = OutputStream.toMemory()

        let fileKeyData = try! ethree.encryptShared(
            plaintextInputStream,
            streamSize: plaintextData.count,
            to: ciphertextOutputStream
        )
        let ciphertextData = ciphertextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // Decrypt.
        let ciphertextInputStream = InputStream(data: ciphertextData)
        let plaintextOutputStream = OutputStream.toMemory()
        let selfKeyPair = try! ethree.localKeyStorage.retrieveKeyPair()

        try! ethree.decryptShared(
            ciphertextInputStream,
            to: plaintextOutputStream,
            with: fileKeyData,
            verifyWith: selfKeyPair.publicKey
        )
        let decryptedPlaintextData = plaintextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let decryptedPlaintext = String(bytes: decryptedPlaintextData, encoding: .utf8)!

        // Check.
        XCTAssertEqual(plaintext, decryptedPlaintext)
    }

    func test03__encrypt_shared__then_decrypt_with_card_verify__should_be_equal() {
        let ethree = try! self.utils.setupDevice()
        let cards = try! ethree.cardManager.searchCards(identities: [ethree.identity]).startSync().get()

        // Encrypt.
        let plaintext = UUID().uuidString
        let plaintextData = plaintext.data(using: .utf8)!
        let plaintextInputStream = InputStream(data: plaintextData)
        let ciphertextOutputStream = OutputStream.toMemory()

        let fileKeyData = try! ethree.encryptShared(
            plaintextInputStream,
            streamSize: plaintextData.count,
            to: ciphertextOutputStream
        )
        let ciphertextData = ciphertextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // Decrypt.
        let ciphertextInputStream = InputStream(data: ciphertextData)
        let plaintextOutputStream = OutputStream.toMemory()

        try! ethree.decryptShared(
            ciphertextInputStream,
            to: plaintextOutputStream,
            with: fileKeyData,
            verifyWith: cards.first!
        )
        let decryptedPlaintextData = plaintextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let decryptedPlaintext = String(bytes: decryptedPlaintextData, encoding: .utf8)!

        // Check.
        XCTAssertEqual(plaintext, decryptedPlaintext)
    }

    func test04__decrypt_shared__compatibility__succeed() {
        let ethree = try! self.utils.setupDevice()

        // Get compatibility data.
        let compatibilityData = self.utils.encryptSharedCompatibilityDict
        let originData = compatibilityData["originData"]!
        let encryptedData = Data(base64Encoded: compatibilityData["encryptedData"]!)!
        let fileKeyData = Data(base64Encoded: compatibilityData["fileKey"]!)!
        let senderPublicKeyData = Data(base64Encoded: compatibilityData["senderPublicKey"]!)!
        let senderPublicKey = try! ethree.crypto.importPublicKey(from: senderPublicKeyData)

        // Decrypt.
        let ciphertextInputStream = InputStream(data: encryptedData)
        let plaintextOutputStream = OutputStream.toMemory()

        try! ethree.decryptShared(
            ciphertextInputStream,
            to: plaintextOutputStream,
            with: fileKeyData,
            verifyWith: senderPublicKey
        )
        let decryptedData = plaintextOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let decryptedPlaintext = String(bytes: decryptedData, encoding: .utf8)!

        // Check.
        XCTAssertEqual(originData, decryptedPlaintext)
    }
}
