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
import VirgilSDK
import XCTest

@testable import VirgilE3Kit

class VTE009_RatchetTests: XCTestCase {
    let utils = TestUtils()

    func encryptDecrypt100Times(chat1: RatchetChannel, chat2: RatchetChannel) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: RatchetChannel
                let receiver: RatchetChannel

                if Bool.random() {
                    sender = chat1
                    receiver = chat2
                } else {
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

    func test001_STE_51__encrypt_decrypt__should_succeed() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            let chat1 = try ethree1.createRatchetChannel(with: card2).startSync().get()
            let chat2 = try ethree2.joinRatchetChannel(with: card1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test002_STE_52__create__with_self__should_throw_error() {
        do {
            let (ethree, card) = try self.utils.setupRatchetDevice()

            do {
                _ = try ethree.createRatchetChannel(with: card).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test003_STE_53__create__with_disabled_ratchet_user__should_throw_error() {
        do {
            let ethree1 = try self.utils.setupDevice(keyPairType: .ed25519)
            let (ethree2, _) = try self.utils.setupRatchetDevice()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            do {
                _ = try ethree2.createRatchetChannel(with: card1).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.userIsNotUsingRatchet {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test004_STE_54__create__which_exists__should_throw_error() {
        do {
            let (ethree1, _) = try self.utils.setupRatchetDevice()
            let (_, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()

            do {
                _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
            } catch EThreeRatchetError.channelAlreadyExists {}

            let secureChat1 = try ethree1.getSecureChat()
            try secureChat1.deleteSession(withParticipantIdentity: card2.identity)

            do {
                _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.channelAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test005_STE_55__create__after_delete__should_succeed() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
            _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()

            try ethree1.deleteRatchetChannel(with: card2).startSync().get()
            try ethree2.deleteRatchetChannel(with: card1).startSync().get()

            let newChat1 = try ethree1.createRatchetChannel(with: card2).startSync().get()
            let newChat2 = try ethree2.joinRatchetChannel(with: card1).startSync().get()

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test006_STE_56__join__with_self__should_throw_error() {
        do {
            let (ethree, card) = try self.utils.setupRatchetDevice()

            do {
                _ = try ethree.joinRatchetChannel(with: card).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test007_STE_57__join__which_exists__should_throw_error() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
            _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()

            do {
                _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.channelAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test008_STE_58__join__without_invitation__should_throw_error() {
        do {
            let (_, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, _) = try self.utils.setupRatchetDevice()

            do {
                _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.noInvite {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test009_STE_59__join__after_delete__should_throw_error() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()

            try ethree1.deleteRatchetChannel(with: card2).startSync().get()

            do {
                _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.noInvite {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test010_STE_60__join__after_rotate__should_throw_error() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()

            try ethree1.cleanUp()
            try ethree1.rotatePrivateKey().startSync().get()

            do {
                _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.noInvite {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test011_STE_61__join__after_unregister__should_succeed() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            let chat1 = try ethree1.createRatchetChannel(with: card2).startSync().get()

            let message = UUID().uuidString
            let encrypted = try chat1.encrypt(text: message)

            try ethree1.unregister().startSync().get()

            let chat2 = try ethree2.joinRatchetChannel(with: card1).startSync().get()
            let decrypted = try chat2.decrypt(text: encrypted)

            XCTAssert(decrypted == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test012_STE_62__getRatchetChannel__should_succeed() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            XCTAssert(try ethree1.getRatchetChannel(with: card2) == nil)
            XCTAssert(try ethree2.getRatchetChannel(with: card1) == nil)

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
            XCTAssert(try ethree1.getRatchetChannel(with: card2) != nil)

            _ = try ethree2.joinRatchetChannel(with: card1).startSync().get()
            XCTAssert(try ethree2.getRatchetChannel(with: card1) != nil)

            try ethree1.deleteRatchetChannel(with: card2).startSync().get()
            XCTAssert(try ethree1.getRatchetChannel(with: card2) == nil)

            try ethree2.deleteRatchetChannel(with: card1).startSync().get()
            XCTAssert(try ethree2.getRatchetChannel(with: card1) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test013_STE_63__delete__nonexistent_chat__should_succeed() {
        do {
            let (ethree1, _) = try self.utils.setupRatchetDevice()
            let (_, card2) = try self.utils.setupRatchetDevice()

            try ethree1.deleteRatchetChannel(with: card2).startSync().get()
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test014_STE_64__enableRatchet() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let (_, card2) = try self.utils.setupRatchetDevice()

            do {
                _ = try ethree1.createRatchetChannel(with: card2).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.ratchetIsDisabled {}

            do {
                _ = try ethree1.joinRatchetChannel(with: card2).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.ratchetIsDisabled {}

            do {
                _ = try ethree1.getRatchetChannel(with: card2)
                XCTFail()
            } catch EThreeRatchetError.ratchetIsDisabled {}

            do {
                _ = try ethree1.deleteRatchetChannel(with: card2).startSync().get()
                XCTFail()
            } catch EThreeRatchetError.ratchetIsDisabled {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test015_STE_65__auto_keys_rotation() {
        do {
            let (ethree2, card2) = try self.utils.setupRatchetDevice()
            let (ethree1, card1) = try self.utils.setupRatchetDevice(keyRotationInterval: 5)

            _ = try ethree2.createRatchetChannel(with: card1).startSync().get()

            let secureChat1 = try ethree1.getSecureChat()

            let keys1 = try secureChat1.oneTimeKeysStorage.retrieveAllKeys()

            _ = try ethree1.joinRatchetChannel(with: card2).startSync().get()

            sleep(5)

            let keys2 = try secureChat1.oneTimeKeysStorage.retrieveAllKeys()

            var keysRotated = false

            for key1 in keys1 {
                if !keys2.contains(where: { $0.identifier == key1.identifier }) {
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

    func test016_STE_66__multiple_encrypt_decrypt__should_succeed() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            let chat1 = try ethree1.createRatchetChannel(with: card2).startSync().get()

            var messages: [String] = []
            for _ in 0..<100 {
                messages.append(UUID().uuidString)
            }

            let encrypted = try chat1.encryptMultiple(text: messages)

            let chat2 = try ethree2.joinRatchetChannel(with: card1).startSync().get()

            let decrypted = try chat2.decryptMultiple(text: encrypted)

            for i in 0..<messages.count {
                XCTAssert(decrypted[i] == messages[i])
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test017_STE_67__decrypt_messages__after_rotate_identity_key__should_succeed() {
        do {
            let (ethree1, _) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            _ = try ethree1.createRatchetChannel(with: card2).startSync().get()

            try ethree1.cleanUp()
            try ethree1.rotatePrivateKey().startSync().get()

            let newCard1 = try ethree2.findUser(with: ethree1.identity, forceReload: true)
                .startSync()
                .get()

            let chat1 = try ethree1.createRatchetChannel(with: card2).startSync().get()
            let chat2 = try ethree2.joinRatchetChannel(with: newCard1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test018_STE_68__chats__with_different_names() {
        do {
            let (ethree1, card1) = try self.utils.setupRatchetDevice()
            let (ethree2, card2) = try self.utils.setupRatchetDevice()

            let name1 = UUID().uuidString
            let chat11 = try ethree1.createRatchetChannel(with: card2, name: name1).startSync()
                .get()

            let name2 = UUID().uuidString
            let chat22 = try ethree2.createRatchetChannel(with: card1, name: name2).startSync()
                .get()

            let chat12 = try ethree1.joinRatchetChannel(with: card2, name: name2).startSync().get()
            let chat21 = try ethree2.joinRatchetChannel(with: card1, name: name1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat11, chat2: chat21)
            try self.encryptDecrypt100Times(chat1: chat12, chat2: chat22)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
