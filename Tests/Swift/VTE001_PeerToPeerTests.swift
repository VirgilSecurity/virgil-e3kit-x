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
import XCTest

@testable import VirgilE3Kit

class VTE001_PeerToPeerTests: XCTestCase {
    let utils = TestUtils()

    func test001_STE_3__encrypt_decrypt__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()

            let plainText = UUID().uuidString
            let encrypted = try ethree1.authEncrypt(text: plainText, for: card2)

            let otherCard = self.utils.publishCard()
            XCTAssertThrowsError(try ethree2.authDecrypt(text: encrypted, from: otherCard))

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let decrypted = try ethree2.authDecrypt(text: encrypted, from: card1)
            XCTAssertEqual(decrypted, plainText)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test002_STE_4__encrypt_for_empty_users__should_fail() {
        do {
            let ethree = try self.utils.setupDevice()

            do {
                _ = try ethree.authEncrypt(text: "plaintext", for: [:] as FindUsersResult)
                XCTFail()
            } catch EThreeError.missingPublicKey {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test003_STE_5__decrypt_unsigned_ciphertext__should_fail() {
        do {
            let ethree = try self.utils.setupDevice()

            let selfCard = try ethree.findUser(with: ethree.identity).startSync().get()
            let plainData = Data(UUID().uuidString.utf8)

            let encryptedData = try self.utils.crypto.encrypt(plainData, for: [selfCard.publicKey], enablePadding: false)
            let encryptedString = encryptedData.base64EncodedString()

            let otherCard = self.utils.publishCard()
            XCTAssertThrowsError(try ethree.authDecrypt(text: encryptedString, from: otherCard))
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test004_STE_6__missing_private_key__encrypt_decrypt_should_fail() {
        do {
            let storageParams = try KeychainStorageParams.makeKeychainStorageParams()
            let keychainStorage = KeychainStorage(storageParams: storageParams)
            defer { try? keychainStorage.deleteAllEntries() }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            try? keychainStorage.deleteEntry(withName: ethree.identity)

            let card = self.utils.publishCard()

            do {
                _ = try ethree.authEncrypt(text: "plainText", for: [ethree.identity: card])
                XCTFail()
            } catch EThreeError.missingPrivateKey {}

            do {
                _ = try ethree.authDecrypt(text: "", from: card)
                XCTFail()
            } catch EThreeError.missingPrivateKey {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test005_STE_22__stream_encrypt_decrypt_self__should_succeed() {
        do {
            let ethree = try self.utils.setupDevice()

            let data = Data((0..<100).map { UInt8($0 % 256) })

            let inputStream1 = InputStream(data: data)
            let outputStream1 = OutputStream(toMemory: ())

            try ethree.authEncrypt(inputStream1, streamSize: data.count, to: outputStream1, for: nil as FindUsersResult?)

            let encryptedData = outputStream1.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

            let inputStream2 = InputStream(data: encryptedData)
            let outputStream2 = OutputStream(toMemory: ())

            try ethree.authDecrypt(inputStream2, to: outputStream2, from: nil as Card?)

            let decryptedData = outputStream2.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
            XCTAssertEqual(data, decryptedData)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test006_STE_40__decrypt_with_old_card_using_date__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()

            let date1 = Date()
            Thread.sleep(forTimeInterval: 1)

            let plainText1 = UUID().uuidString
            let encrypted1 = try ethree1.authEncrypt(text: plainText1, for: [card2.identity: card2])

            try ethree1.cleanUp()
            try ethree1.rotatePrivateKey().startSync().get()

            let date2 = Date()

            let plainText2 = UUID().uuidString
            let encrypted2 = try ethree1.authEncrypt(text: plainText2, for: [card2.identity: card2])

            let updatedCard1 = try ethree2.findUser(with: ethree1.identity, forceReload: true).startSync().get()

            XCTAssertThrowsError(try ethree2.authDecrypt(text: encrypted1, from: updatedCard1))
            XCTAssertThrowsError(try ethree2.authDecrypt(text: encrypted1, from: updatedCard1, date: date2))

            let decrypted1 = try ethree2.authDecrypt(text: encrypted1, from: updatedCard1, date: date1)
            XCTAssertEqual(decrypted1, plainText1)

            XCTAssertThrowsError(try ethree2.authDecrypt(text: encrypted2, from: updatedCard1, date: date1))

            let decrypted2 = try ethree2.authDecrypt(text: encrypted2, from: updatedCard1, date: date2)
            XCTAssertEqual(decrypted2, plainText2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test007_STE_41__deprecated_lookup_encrypt_decrypt__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            let lookup = try ethree1.lookupPublicKeys(of: [ethree2.identity]).startSync().get()
            XCTAssert(!lookup.isEmpty)

            let plainText = UUID().uuidString
            // swiftlint:disable:next deprecated_not_recommended
            let encrypted = try ethree1.encrypt(text: plainText, for: lookup)

            let lookup2 = try ethree2.lookupPublicKeys(of: [ethree1.identity]).startSync().get()
            XCTAssert(!lookup2.isEmpty)
            // swiftlint:disable:next deprecated_not_recommended
            let decrypted = try ethree2.decrypt(text: encrypted, from: lookup2[ethree1.identity]!)
            XCTAssertEqual(decrypted, plainText)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test008_STE_71__deprecated_encrypt_decrypt_with_card__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()
            let plainText = UUID().uuidString
            // swiftlint:disable:next deprecated_not_recommended
            let encrypted = try ethree1.encrypt(text: plainText, for: card2)

            let otherCard = self.utils.publishCard()
            // swiftlint:disable:next deprecated_not_recommended
            XCTAssertThrowsError(try ethree2.decrypt(text: encrypted, from: otherCard))

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            // swiftlint:disable:next deprecated_not_recommended
            let decrypted = try ethree2.decrypt(text: encrypted, from: card1)
            XCTAssertEqual(decrypted, plainText)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test009_STE_88__data_encrypt_stream_decrypt__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            let card1 = try ethree1.findUser(with: ethree1.identity).startSync().get()
            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()

            let data = try self.utils.crypto.generateRandomData(ofSize: 10)
            let encrypted = try ethree1.authEncrypt(data: data, for: card2)

            let inputStream = InputStream(data: encrypted)
            let outputStream = OutputStream(toMemory: ())

            try ethree2.authDecrypt(inputStream, to: outputStream, from: card1)

            let decryptedData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
            XCTAssertEqual(data, decryptedData)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test010_STE_89__streams_compatibility() {
        do {
            let dict = self.utils.streamsCompatibilityDict
            guard
                let privateKeyString = dict["private_key"],
                let encryptedString = dict["encrypted_data"],
                let originString = dict["origin_data"],
                let privateKeyData = Data(base64Encoded: privateKeyString),
                let encryptedData = Data(base64Encoded: encryptedString),
                let originData = Data(base64Encoded: originString)
            else {
                XCTFail("Missing streams compatibility data in compatibility_data.json")
                return
            }

            let keyPair = try self.utils.crypto.importPrivateKey(from: privateKeyData)
            let ethree = try self.utils.setupDevice(identity: nil, keyPair: keyPair, keyPairType: .ed25519, register: false)

            let inputStream = InputStream(data: encryptedData)
            let outputStream = OutputStream(toMemory: ())

            try ethree.authDecrypt(inputStream, to: outputStream, from: nil as Card?)

            let decryptedData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
            XCTAssertEqual(originData, decryptedData)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
