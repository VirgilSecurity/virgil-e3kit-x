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
import VirgilSDK
import VirgilCrypto

class VTE010_UnsafeChannelTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice(identity: String? = nil, keyPair: VirgilKeyPair? = nil) throws -> EThree {
        let identity = identity ?? UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree(identity: identity, tokenCallback: tokenCallback)

        try ethree.register(with: keyPair).startSync().get()

        return ethree
    }

    func encryptDecrypt100Times(chat1: UnsafeChannel, chat2: UnsafeChannel) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: UnsafeChannel
                let receiver: UnsafeChannel

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

    func test01_STE_74__encrypt_decrypt__should_succeed() {
        do {
            let ethree1 = try self.setUpDevice()

            let identity2 = UUID().uuidString
            let chat1 = try ethree1.createUnsafeChannel(with: identity2).startSync().get()

            let message = UUID().uuidString
            let encrypted = try chat1.encrypt(text: message)

            let ethree2 = try self.setUpDevice(identity: identity2)
            let chat2 = try ethree2.loadUnsafeChannel(asCreator: false, with: ethree1.identity).startSync().get()
            let decrypted = try chat2.decrypt(text: encrypted)

            XCTAssert(decrypted == message)

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)

            let newChat1 = try ethree1.loadUnsafeChannel(asCreator: true, with: identity2).startSync().get()
            let newChat2 = try ethree2.getUnsafeChannel(with: ethree1.identity)!

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02_STE_75__create__existent_chat__should_throw_error() {
        do {
            let ethree = try self.setUpDevice()

            let identity = UUID().uuidString
            _ = try ethree.createUnsafeChannel(with: identity).startSync().get()

            do {
                _ = try ethree.createUnsafeChannel(with: identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.channelAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03_STE_76__create__with_self__should_throw_error() {
        do {
            let ethree = try self.setUpDevice()

            do {
                _ = try ethree.createUnsafeChannel(with: ethree.identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04_STE_77__create__with_registered__should_throw_error() {
        do {
            let ethree1 = try self.setUpDevice()
            let ethree2 = try self.setUpDevice()

            do {
                _ = try ethree1.createUnsafeChannel(with: ethree2.identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.userIsRegistered {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05_STE_78__get__should_suceed() {
        do {
            let ethree1 = try self.setUpDevice()

            let identity2 = UUID().uuidString
            XCTAssert(try ethree1.getUnsafeChannel(with: identity2) == nil)

            _ = try ethree1.createUnsafeChannel(with: identity2).startSync().get()
            XCTAssert(try ethree1.getUnsafeChannel(with: identity2) != nil)

            let ethree2 = try self.setUpDevice(identity: identity2)
            XCTAssert(try ethree2.getUnsafeChannel(with: ethree1.identity) == nil)

            _ = try ethree2.loadUnsafeChannel(asCreator: false, with: ethree1.identity).startSync().get()
            XCTAssert(try ethree2.getUnsafeChannel(with: ethree1.identity) != nil)

            try ethree1.deleteUnsafeChannel(with: identity2).startSync().get()
            XCTAssert(try ethree1.getUnsafeChannel(with: identity2) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test06_STE_79__load__with_self__should_throw_error() {
        do {
            let ethree = try self.setUpDevice()

            do {
                _ = try ethree.loadUnsafeChannel(asCreator: true, with: ethree.identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test07_STE_80__load__unexistent_chat__should_throw_error() {
        do {
            let ethree = try self.setUpDevice()

            let identity = UUID().uuidString
            do {
                _ = try ethree.loadUnsafeChannel(asCreator: true, with: identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.channelNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test08_STE_81__load__after_delete__should_throw_error() {
        do {
            let ethree1 = try self.setUpDevice()

            let identity2 = UUID().uuidString

            _ = try ethree1.createUnsafeChannel(with: identity2).startSync().get()
            try ethree1.deleteUnsafeChannel(with: identity2).startSync().get()

            do {
                _ = try ethree1.loadUnsafeChannel(asCreator: true, with: identity2).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.channelNotFound {}

            let ethree2 = try self.setUpDevice(identity: identity2)

            do {
                _ = try ethree2.loadUnsafeChannel(asCreator: false, with: ethree1.identity).startSync().get()
                XCTFail()
            } catch UnsafeChannelError.channelNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test09_STE_82__delete__unexistent_chat__should_succeed() {
        do {
            let ethree = try self.setUpDevice()

            let fakeIdentity = UUID().uuidString

            try ethree.deleteUnsafeChannel(with: fakeIdentity).startSync().get()
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test10_STE_83__compatibility() {
        do {
            let config = self.utils.config.UnsafeChannel

            let identity = config.Identity

            let tokenCallback: EThree.RenewJwtCallback = { completion in
                let token = self.utils.getTokenString(identity: identity)

                completion(token, nil)
            }

            let ethree = try EThree(identity: identity, tokenCallback: tokenCallback)

            if try !ethree.hasLocalPrivateKey() {
                let privateKeyData = Data(base64Encoded: config.PrivateKey)!
                try ethree.localKeyStorage.store(data: privateKeyData)
                try ethree.privateKeyChanged()
            }

            let chat = try ethree.loadUnsafeChannel(asCreator: false, with: config.Initiator).startSync().get()

            let decrypted = try chat.decrypt(text: config.EncryptedText)

            XCTAssert(decrypted == config.OriginText)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test11_STE_84__cleanup__should_reset_local_storage() {
        do {
            let keyPair = try self.utils.crypto.generateKeyPair()
            let ethree = try self.setUpDevice(keyPair: keyPair)

            let localUnsafeStorage = try FileUnsafeKeysStorage(identity: ethree.identity,
                                                               crypto: self.utils.crypto,
                                                               identityKeyPair: keyPair)

            let identity = UUID().uuidString

            XCTAssert(try localUnsafeStorage.retrieve(identity: identity) == nil)

            _ = try ethree.createUnsafeChannel(with: identity).startSync().get()

            XCTAssert(try localUnsafeStorage.retrieve(identity: identity) != nil)

            try ethree.cleanUp()

            XCTAssert(try localUnsafeStorage.retrieve(identity: identity) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
