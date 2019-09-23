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
import VirgilE3Kit
import VirgilCrypto
import VirgilSDK
import VirgilSDKRatchet

class EThreeRatchetTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice() throws -> (EThreeRatchet, Card) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let rethree = try EThreeRatchet.initialize(identity: identity, tokenCallback: tokenCallback)
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

    func test_01__encrypt_decrypt() {
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

    func test_02__isChatStarted() {
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

    func test_03__duplicateChats__should_throw_error() {
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

    func test_04__delete_nonexistent_chat__should_throw_error() {
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

    func test_05__startChat_again__should_succeed() {
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

    func test_06__encrypt_without_chat__should_throw_error() {
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
}

