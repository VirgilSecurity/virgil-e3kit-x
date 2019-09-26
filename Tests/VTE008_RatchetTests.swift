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

import XCTest
@testable import VirgilE3Kit
import VirgilCrypto
import VirgilSDK
import VirgilSDKRatchet
import VirgilCryptoRatchet

class EThreeRatchetTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice(keyRotationInterval: TimeInterval = 3_600) throws -> (EThreeRatchet, Card) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let rethree = try EThreeRatchet.initialize(tokenCallback: tokenCallback,
                                                   keyRotationInterval: keyRotationInterval)
            .startSync()
            .get()

        try rethree.register().startSync().get()

        let card = try rethree.findUser(with: identity).startSync().get()

        return (rethree, card)
    }

    func encryptDecrypt100Times(senderSession: (EThreeRatchet, Card), receiverSession: (EThreeRatchet, Card)) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: (EThreeRatchet, Card)
                let receiver: (EThreeRatchet, Card)

                if Bool.random() {
                    sender = senderSession
                    receiver = receiverSession
                }
                else {
                    sender = receiverSession
                    receiver = senderSession
                }

                let plainText = UUID().uuidString

                let message = try sender.0.encrypt(text: plainText, for: receiver.1)

                let decryptedMessage = try receiver.0.decrypt(text: message, from: sender.1)

                XCTAssert(decryptedMessage == plainText)
            }
        }
    }

    func test_001__encrypt_decrypt() {
        do {
            let (rethree1, card1) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            try rethree1.startChat(with: card2).startSync().get()

            let message = UUID().uuidString
            let encrypted = try rethree1.encrypt(text: message, for: card2)
            let decrypted = try rethree2.decrypt(text: encrypted, from: card1)

            XCTAssert(message == decrypted)

            try self.encryptDecrypt100Times(senderSession: (rethree1, card1), receiverSession: (rethree2, card2))
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_002__isChatStarted() {
        do {
            let (rethree1, card1) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            XCTAssert(try !rethree1.isChatStarted(with: card2))
            try rethree1.startChat(with: card2).startSync().get()
            XCTAssert(try rethree1.isChatStarted(with: card2))

            let message = UUID().uuidString
            let encrypted = try rethree1.encrypt(text: message, for: card2)

            XCTAssert(try !rethree2.isChatStarted(with: card1))
            let decrypted = try rethree2.decrypt(text: encrypted, from: card1)
            XCTAssert(try rethree2.isChatStarted(with: card1))

            XCTAssert(message == decrypted)

            try rethree1.deleteChat(with: card2)
            XCTAssert(try !rethree1.isChatStarted(with: card2))
            XCTAssert(try rethree2.isChatStarted(with: card1))

            try rethree2.deleteChat(with: card1)
            XCTAssert(try !rethree2.isChatStarted(with: card1))
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_003__duplicateChats__should_throw_error() {
        do {
            let (rethree1, _) = try self.setUpDevice()
            let (_, card2) = try self.setUpDevice()

            try rethree1.startChat(with: card2).startSync().get()

            do {
                try rethree1.startChat(with: card2).startSync().get()
            }
            catch EThreeRatchetError.chatAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_004__delete_nonexistent_chat__should_throw_error() {
        do {
            let (rethree1, _) = try self.setUpDevice()
            let (_, card2) = try self.setUpDevice()

            do {
                try rethree1.deleteChat(with: card2)
            }
            catch EThreeRatchetError.missingChat {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_005__startChat_again__should_succeed() {
        do {
            let (rethree1, card1) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            try rethree1.startChat(with: card2).startSync().get()

            let message1 = UUID().uuidString
            let encrypted1 = try rethree1.encrypt(text: message1, for: card2)
            _ = try rethree2.decrypt(text: encrypted1, from: card1)

            try rethree1.deleteChat(with: card2)

            try rethree1.startChat(with: card2).startSync().get()

            let message2 = UUID().uuidString
            let encrypted2 = try rethree1.encrypt(text: message2, for: card2)

            // TODO: Add proper error
            do {
                _ = try rethree2.decrypt(text: encrypted2, from: card1)
            } catch {}

            try rethree2.deleteChat(with: card1)

            let decrypted2 = try rethree2.decrypt(text: encrypted2, from: card1)

            XCTAssert(message2 == decrypted2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_006__encrypt_without_chat__should_throw_error() {
        do {
            let (rethree1, _) = try self.setUpDevice()
            let (_, card2) = try self.setUpDevice()

            let message = UUID().uuidString

            do {
                _ = try rethree1.encrypt(text: message, for: card2)
            } catch EThreeRatchetError.missingChat {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_007__startChat_with_self__should_throw_error() {
        do {
            let (rethree, card) = try self.setUpDevice()

            do {
                try rethree.startChat(with: card).startSync().get()
            } catch EThreeRatchetError.selfChatIsForbidden {}

        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_008__multipleDecrypt() {
        do {
            let (rethree1, card1) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            try rethree1.startChat(with: card2).startSync().get()

            var messages: [String] = []
            for _ in 0..<100 {
                messages.append(UUID().uuidString)
            }

            var encryptedArray: [String] = []
            for message in messages {
                let encrypted = try rethree1.encrypt(text: message, for: card2)
                encryptedArray.append(encrypted)
            }

            for i in 0..<encryptedArray.count {
                let decrypted = try rethree2.decrypt(text: encryptedArray[i], from: card1)

                XCTAssert(decrypted == messages[i])
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_009_decrypt_messages_after_rotate_identity_key() {
        do {
            let (rethree1, _) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            try rethree1.startChat(with: card2).startSync().get()

            let date = Date()
            let message = UUID().uuidString
            let encrypted = try rethree1.encrypt(text: message, for: card2)

            sleep(1)

            try rethree1.cleanUp()
            try rethree1.rotatePrivateKey().startSync().get()

            XCTAssert(try !rethree1.isChatStarted(with: card2))

            let newCard1 = try rethree2.findUser(with: rethree1.identity, forceReload: true).startSync().get()

            do {
                _ = try rethree2.decrypt(text: encrypted, from: newCard1)
                XCTFail()
            } catch EThreeRatchetError.wrongSenderCard {} catch {
                print(error.localizedDescription)
                XCTFail()
            }

            let decrypted = try rethree2.decrypt(text: encrypted, from: newCard1, date: date)

            XCTAssert(message == decrypted)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_010_auto_keys_rotation() {
        do {
            let (rethree2, card2) = try self.setUpDevice()
            let (rethree1, card1) = try self.setUpDevice(keyRotationInterval: 5)

            try rethree2.startChat(with: card1).startSync().get()
            let message = UUID().uuidString
            let encrypted = try rethree2.encrypt(text: message, for: card1)

            let secureChat1 = try rethree1.getSecureChat()

            try secureChat1.oneTimeKeysStorage.startInteraction()
            let keys1 = try secureChat1.oneTimeKeysStorage.retrieveAllKeys()
            try secureChat1.oneTimeKeysStorage.stopInteraction()

            _ = try rethree1.decrypt(text: encrypted, from: card2)

            sleep(5)

            try secureChat1.oneTimeKeysStorage.startInteraction()
            let keys2 = try secureChat1.oneTimeKeysStorage.retrieveAllKeys()
            try secureChat1.oneTimeKeysStorage.stopInteraction()

            var keysRotated = false

            for key1 in keys1 {
                if !keys2.contains { $0.identifier == key1.identifier } {
                    keysRotated = true
                    break
                }
            }

            XCTAssert(keysRotated)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

