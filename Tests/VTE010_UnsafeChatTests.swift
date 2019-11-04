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
            let chat2 = try ethree2.loadUnsafeChat(asCreator: false, with: card1.identity).startSync().get()
            let decrypted = try chat2.decrypt(text: encrypted)

            XCTAssert(decrypted == message)

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)

            let newChat1 = try ethree1.getUnsafeChat(with: identity2)!
            let newChat2 = try ethree2.getUnsafeChat(with: card1.identity)!

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02__create__existent_chat__should_throw_error() {
        do {
            let (ethree, _) = try self.setUpDevice()

            let identity = UUID().uuidString
            _ = try ethree.createUnsafeChat(with: identity).startSync().get()

            do {
                _ = try ethree.createUnsafeChat(with: identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.chatAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03__create__with_self__should_throw_error() {
        do {
            let (ethree, _) = try self.setUpDevice()

            do {
                _ = try ethree.createUnsafeChat(with: ethree.identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.selfChatIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04__create__with_registered__should_throw_error() {
        do {
            let (ethree1, _) = try self.setUpDevice()
            let (ethree2, _) = try self.setUpDevice()

            do {
                _ = try ethree1.createUnsafeChat(with: ethree2.identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.userIsRegistered {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05__get__should_suceed() {
        do {
            let (ethree1, _) = try self.setUpDevice()

            let identity2 = UUID().uuidString
            XCTAssert(try ethree1.getUnsafeChat(with: identity2) == nil)

            _ = try ethree1.createUnsafeChat(with: identity2).startSync().get()
            XCTAssert(try ethree1.getUnsafeChat(with: identity2) != nil)

            let (ethree2, _) = try self.setUpDevice(identity: identity2)
            XCTAssert(try ethree2.getUnsafeChat(with: ethree1.identity) == nil)

            _ = try ethree2.loadUnsafeChat(asCreator: false, with: ethree1.identity).startSync().get()
            XCTAssert(try ethree2.getUnsafeChat(with: ethree1.identity) != nil)

            try ethree1.deleteUnsafeChat(with: identity2).startSync().get()
            XCTAssert(try ethree1.getUnsafeChat(with: identity2) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test06__load__with_self__should_throw_error() {
        do {
            let (ethree, _) = try self.setUpDevice()

            do {
                _ = try ethree.loadUnsafeChat(asCreator: true, with: ethree.identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.selfChatIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test07__load__unexistent_chat__should_throw_error() {
        do {
            let (ethree, _) = try self.setUpDevice()

            let identity = UUID().uuidString
            do {
                _ = try ethree.loadUnsafeChat(asCreator: true, with: identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.chatNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test08__join__after_delete__should_throw_error() {
        do {
            let (ethree1, _) = try self.setUpDevice()

            let identity2 = UUID().uuidString

            _ = try ethree1.createUnsafeChat(with: identity2).startSync().get()
            try ethree1.deleteUnsafeChat(with: identity2).startSync().get()

            do {
                _ = try ethree1.loadUnsafeChat(asCreator: true, with: identity2).startSync().get()
            } catch UnsafeChatError.chatNotFound {}

            let (ethree2, _) = try self.setUpDevice(identity: identity2)

            do {
                _ = try ethree2.loadUnsafeChat(asCreator: false, with: ethree1.identity).startSync().get()
                XCTFail()
            } catch UnsafeChatError.chatNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test09__delete__unexistent_chat__should_throw_error() {
        do {
            let (ethree, _) = try self.setUpDevice()

            let fakeIdentity = UUID().uuidString

            do {
                try ethree.deleteUnsafeChat(with: fakeIdentity).startSync().get()
            } catch UnsafeChatError.chatNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
