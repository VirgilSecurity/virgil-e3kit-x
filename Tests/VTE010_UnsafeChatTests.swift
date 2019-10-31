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
import VirgilSDK

class VTE010_UnsafeChatTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice(identity: String? = nil) throws -> (EThree, Card) {
        let identity = identity ?? UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree(identity: identity, tokenCallback: tokenCallback)

        try ethree.register().startSync().get()

        let card = try ethree.findUser(with: identity).startSync().get()

        return (ethree, card)
    }

    func encryptDecrypt100Times(chat1: UnsafeChat, chat2: UnsafeChat) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: UnsafeChat
                let receiver: UnsafeChat

                if Bool.random() {
                    sender = chat1
                    receiver = chat2
                }
                else {
                    sender = chat2
                    receiver = chat1
                }

                let plainText = UUID().uuidString

                let encrypted = try sender.encrypt(text: plainText)
                let decrypted = try receiver.decrypt(text: encrypted)

                XCTAssert(decrypted == plainText)
            }
        }
    }

    func test01__encrypt_decrypt__should_succeed() {
        do {
            let (ethree1, card1) = try self.setUpDevice()

            let identity2 = UUID().uuidString
            let chat1 = try ethree1.createUnsafeChat(with: identity2).startSync().get()

            let message = UUID().uuidString
            let encrypted = try chat1.encrypt(text: message)

            let (ethree2, _) = try self.setUpDevice(identity: identity2)
            let chat2 = try ethree2.joinUnsafeChat(with: card1).startSync().get()
            let decrypted = try chat2.decrypt(text: encrypted)

            XCTAssert(decrypted == message)

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)

            let newChat1 = try ethree1.getUnsafeChat(with: identity2)
            let newChat2 = try ethree2.getUnsafeChat(with: card1.identity)

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
