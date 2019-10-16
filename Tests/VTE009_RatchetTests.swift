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

class VTE009_RatchetTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice(enableRatchet: Bool = true,
                             keyRotationInterval: TimeInterval = Defaults.keyRotationInterval) throws -> (EThree, Card) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree(identity: identity,
                                tokenCallback: tokenCallback,
                                enableRatchet: enableRatchet,
                                keyRotationInterval: keyRotationInterval)

        try ethree.register().startSync().get()

        let card = try ethree.findUser(with: identity).startSync().get()

        return (ethree, card)
    }

    func encryptDecrypt100Times(chat1: RatchetChat, chat2: RatchetChat) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: RatchetChat
                let receiver: RatchetChat

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


    func test_001__encrypt_decrypt__should_succeed() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            let chat1 = try ethree1.createRatchetChat(with: card2).startSync().get()
            let chat2 = try ethree2.joinRatchetChat(with: card1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_002__createChat__with_self__should_throw_error() {
        do {
            let (ethree, card) = try self.setUpDevice()

            do {
                _ = try ethree.createRatchetChat(with: card).startSync().get()
            } catch EThreeRatchetError.selfChatIsForbidden {}

        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_003__createСhat__with_disabled_ratchet_user__should_throw_error() {
        do {
            let (_, card1) = try self.setUpDevice(enableRatchet: false)
            let (ethree2, _) = try self.setUpDevice()

            do {
                _ = try ethree2.createRatchetChat(with: card1).startSync().get()
            } catch EThreeRatchetError.unregisteredUser {} catch {
                XCTFail()
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_004__createChat__which_exists__should_throw_error() {
        do {
            let (ethree1, _) = try self.setUpDevice()
            let (_, card2) = try self.setUpDevice()

            _ = try ethree1.createRatchetChat(with: card2).startSync().get()

            do {
                _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            }
            catch EThreeRatchetError.chatAlreadyExists {}

            let secureChat1 = try ethree1.getSecureChat()
            try secureChat1.deleteSession(withParticipantIdentity: card2.identity)

            do {
                _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            }
            catch EThreeRatchetError.chatAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_005__createChat__after_delete__should_succeed() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            _ = try ethree2.joinRatchetChat(with: card1).startSync().get()

            try ethree1.deleteRatchetChat(with: card2).startSync().get()
            try ethree2.deleteRatchetChat(with: card1).startSync().get()

            let newChat1 = try ethree1.createRatchetChat(with: card2).startSync().get()
            let newChat2 = try ethree2.joinRatchetChat(with: card1).startSync().get()

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_006__joinChat__with_self__should_throw_error() {
        do {
            let (ethree, card) = try self.setUpDevice()

            do {
                _ = try ethree.joinRatchetChat(with: card).startSync().get()
            } catch EThreeRatchetError.selfChatIsForbidden {}

        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_007__joinChat__which_exists__should_throw_error() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            _ = try ethree2.joinRatchetChat(with: card1).startSync().get()

            do {
                _ = try ethree2.joinRatchetChat(with: card1).startSync().get()
            } catch EThreeRatchetError.chatAlreadyExists {}

        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_008__joinChat__without_invitation__should_throw_error() {
        do {
            let (_, card1) = try self.setUpDevice()
            let (ethree2, _) = try self.setUpDevice()

            do {
                _ = try ethree2.joinRatchetChat(with: card1).startSync().get()
            } catch EThreeRatchetError.noInvite {} catch {
                XCTFail()
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_009__getRatchetChat__should_succeed() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            XCTAssert(try ethree1.getRatchetChat(with: card2) == nil)
            XCTAssert(try ethree2.getRatchetChat(with: card1) == nil)

            _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            XCTAssert(try ethree1.getRatchetChat(with: card2) != nil)

            _ = try ethree2.joinRatchetChat(with: card1).startSync().get()
            XCTAssert(try ethree2.getRatchetChat(with: card1) != nil)

            try ethree1.deleteRatchetChat(with: card2).startSync().get()
            XCTAssert(try ethree1.getRatchetChat(with: card2) == nil)

            try ethree2.deleteRatchetChat(with: card1).startSync().get()
            XCTAssert(try ethree2.getRatchetChat(with: card1) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_010__delete_nonexistent_chat__should_throw_error() {
        do {
            let (ethree1, _) = try self.setUpDevice()
            let (_, card2) = try self.setUpDevice()

            do {
                try ethree1.deleteRatchetChat(with: card2).startSync().get()
            }
            catch EThreeRatchetError.missingLocalChat {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_011__enable_ratchet() {
        do {
            let (ethree1, _) = try self.setUpDevice(enableRatchet: false)
            let (_, card2) = try self.setUpDevice()

            do {
                _ = try ethree1.createRatchetChat(with: card2).startSync().get()
            } catch EThreeRatchetError.ratchetIsDisabled {} catch {
                XCTFail()
            }

            do {
                _ = try ethree1.joinRatchetChat(with: card2).startSync().get()
            } catch EThreeRatchetError.ratchetIsDisabled {} catch {
                XCTFail()
            }

            do {
                _ = try ethree1.getRatchetChat(with: card2)
            } catch EThreeRatchetError.ratchetIsDisabled {} catch {
                XCTFail()
            }

            do {
                _ = try ethree1.deleteRatchetChat(with: card2).startSync().get()
            } catch EThreeRatchetError.ratchetIsDisabled {} catch {
                XCTFail()
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_012__auto_keys_rotation() {
        do {
            let (ethree2, card2) = try self.setUpDevice()
            let (ethree1, card1) = try self.setUpDevice(keyRotationInterval: 5)

            _ = try ethree2.createRatchetChat(with: card1).startSync().get()

            let secureChat1 = try ethree1.getSecureChat()

            try secureChat1.oneTimeKeysStorage.startInteraction()
            let keys1 = try secureChat1.oneTimeKeysStorage.retrieveAllKeys()
            try secureChat1.oneTimeKeysStorage.stopInteraction()

            _ = try ethree1.joinRatchetChat(with: card2).startSync().get()

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

    func test_013__multipleDecrypt__should_succeed() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            let chat1 = try ethree1.createRatchetChat(with: card2).startSync().get()

            var messages: [String] = []
            for _ in 0..<100 {
                messages.append(UUID().uuidString)
            }

            var encryptedArray: [String] = []
            for message in messages {
                let encrypted = try chat1.encrypt(text: message)
                encryptedArray.append(encrypted)
            }

            let chat2 = try ethree2.joinRatchetChat(with: card1).startSync().get()

            for i in 0..<encryptedArray.count {
                let decrypted = try chat2.decrypt(text: encryptedArray[i])

                XCTAssert(decrypted == messages[i])
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_014__decrypt_messages_after_rotate_identity_key__should_succeed() {
        do {
            let (ethree1, _) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            _ = try ethree1.createRatchetChat(with: card2).startSync().get()

            try ethree1.cleanUp()
            try ethree1.rotatePrivateKey().startSync().get()

            let newCard1 = try ethree2.findUser(with: ethree1.identity, forceReload: true).startSync().get()

            let chat1 = try ethree1.createRatchetChat(with: card2).startSync().get()
            let chat2 = try ethree2.joinRatchetChat(with: newCard1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_015__chats__with_different_names() {
        do {
            let (ethree1, card1) = try self.setUpDevice()
            let (ethree2, card2) = try self.setUpDevice()

            let name1 = UUID().uuidString
            let chat11 = try ethree1.createRatchetChat(with: card2, name: name1).startSync().get()

            let name2 = UUID().uuidString
            let chat22 = try ethree2.createRatchetChat(with: card1, name: name2).startSync().get()

            let chat12 = try ethree1.joinRatchetChat(with: card2, name: name2).startSync().get()
            let chat21 = try ethree2.joinRatchetChat(with: card1, name: name1).startSync().get()

            try self.encryptDecrypt100Times(chat1: chat11, chat2: chat21)
            try self.encryptDecrypt100Times(chat1: chat12, chat2: chat22)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

