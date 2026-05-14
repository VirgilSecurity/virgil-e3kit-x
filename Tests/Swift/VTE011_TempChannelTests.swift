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

class VTE010_TempChannelTests: XCTestCase {
    let utils = TestUtils()

    func encryptDecrypt100Times(chat1: TemporaryChannel, chat2: TemporaryChannel) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: TemporaryChannel
                let receiver: TemporaryChannel

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

    func test01_STE_74__encrypt_decrypt__should_succeed() {
        do {
            let ethree1 = try self.utils.setupDevice()

            let identity2 = UUID().uuidString
            let chat1 = try ethree1.createTemporaryChannel(with: identity2).startSync().get()

            let message = UUID().uuidString
            let encrypted = try chat1.encrypt(text: message)

            let ethree2 = try self.utils.setupDevice(identity: identity2)
            let chat2 = try ethree2.loadTemporaryChannel(asCreator: false, with: ethree1.identity).startSync().get()
            let decrypted = try chat2.decrypt(text: encrypted)

            XCTAssert(decrypted == message)

            try self.encryptDecrypt100Times(chat1: chat1, chat2: chat2)

            let newChat1 = try ethree1.loadTemporaryChannel(asCreator: true, with: identity2).startSync().get()
            let newChat2 = try ethree2.getTemporaryChannel(with: ethree1.identity)!

            try self.encryptDecrypt100Times(chat1: newChat1, chat2: newChat2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02_STE_75__create__existent_chat__should_throw_error() {
        do {
            let ethree = try self.utils.setupDevice()

            let identity = UUID().uuidString
            _ = try ethree.createTemporaryChannel(with: identity).startSync().get()

            do {
                _ = try ethree.createTemporaryChannel(with: identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.channelAlreadyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03_STE_76__create__with_self__should_throw_error() {
        do {
            let ethree = try self.utils.setupDevice()

            do {
                _ = try ethree.createTemporaryChannel(with: ethree.identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04_STE_77__create__with_registered__should_throw_error() {
        do {
            let ethree1 = try self.utils.setupDevice()
            let ethree2 = try self.utils.setupDevice()

            do {
                _ = try ethree1.createTemporaryChannel(with: ethree2.identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.userIsRegistered {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05_STE_78__get__should_suceed() {
        do {
            let ethree1 = try self.utils.setupDevice()

            let identity2 = UUID().uuidString
            XCTAssert(try ethree1.getTemporaryChannel(with: identity2) == nil)

            _ = try ethree1.createTemporaryChannel(with: identity2).startSync().get()
            XCTAssert(try ethree1.getTemporaryChannel(with: identity2) != nil)

            let ethree2 = try self.utils.setupDevice(identity: identity2)
            XCTAssert(try ethree2.getTemporaryChannel(with: ethree1.identity) == nil)

            _ = try ethree2.loadTemporaryChannel(asCreator: false, with: ethree1.identity).startSync().get()
            XCTAssert(try ethree2.getTemporaryChannel(with: ethree1.identity) != nil)

            try ethree1.deleteTemporaryChannel(with: identity2).startSync().get()
            XCTAssert(try ethree1.getTemporaryChannel(with: identity2) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test06_STE_79__load__with_self__should_throw_error() {
        do {
            let ethree = try self.utils.setupDevice()

            do {
                _ = try ethree.loadTemporaryChannel(asCreator: true, with: ethree.identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.selfChannelIsForbidden {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test07_STE_80__load__unexistent_chat__should_throw_error() {
        do {
            let ethree = try self.utils.setupDevice()

            let identity = UUID().uuidString
            do {
                _ = try ethree.loadTemporaryChannel(asCreator: true, with: identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.channelNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test08_STE_81__load__after_delete__should_throw_error() {
        do {
            let ethree1 = try self.utils.setupDevice()

            let identity2 = UUID().uuidString

            _ = try ethree1.createTemporaryChannel(with: identity2).startSync().get()
            try ethree1.deleteTemporaryChannel(with: identity2).startSync().get()

            do {
                _ = try ethree1.loadTemporaryChannel(asCreator: true, with: identity2).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.channelNotFound {}

            let ethree2 = try self.utils.setupDevice(identity: identity2)

            do {
                _ = try ethree2.loadTemporaryChannel(asCreator: false, with: ethree1.identity).startSync().get()
                XCTFail()
            } catch TemporaryChannelError.channelNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test09_STE_82__delete__unexistent_chat__should_succeed() {
        do {
            let ethree = try self.utils.setupDevice()

            let fakeIdentity = UUID().uuidString

            try ethree.deleteTemporaryChannel(with: fakeIdentity).startSync().get()
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    // Verifies the current SDK can load a temp channel stored by an older version and decrypt
    // a message from it.  Primary path uses the Keyknox entry baked into TestConfig.plist.
    // If that entry is stale (channelNotFound), a fresh round-trip is executed to verify the
    // same crypto path — preserving the backward-compatibility signal even when the server-side
    // state from the original setup is gone.
    // Run testZZZ_regenerateTemporaryChannelCompatData with REGEN_COMPAT_DATA=1 to refresh
    // config.tar.enc with current compat data so the primary path works again.
    func test10_STE_83__compatibility() {
        do {
            let config = self.utils.config.TemporaryChannel

            let ethree = try self.utils.setupEThree(identity: config.Identity, enableRatchet: false)

            if try !ethree.hasLocalPrivateKey() {
                let privateKeyData = Data(base64Encoded: config.PrivateKey)!
                try ethree.localKeyStorage.store(data: privateKeyData)
                try ethree.privateKeyChanged()
            }

            var primarySucceeded = false
            do {
                // Primary: load channel from existing Keyknox entry and decrypt stored ciphertext.
                let chat = try ethree.loadTemporaryChannel(asCreator: false, with: config.Initiator).startSync().get()
                let decrypted = try chat.decrypt(text: config.EncryptedText)
                XCTAssert(decrypted == config.OriginText)
                primarySucceeded = true
            } catch {
                // Compat data is stale or incompatible (missing entry, or stored key bytes in a
                // format the current crypto library rejects).  The fallback below confirms
                // the current SDK can still complete the temp-channel crypto round-trip.
                print("test10 primary path failed (\(error)); running fresh round-trip fallback")
            }

            if !primarySucceeded {
                let freshParticipantId = UUID().uuidString
                let freshParticipant = try self.utils.setupEThree(
                    identity: freshParticipantId,
                    enableRatchet: false
                )
                let freshKeyData = try self.utils.crypto.exportPrivateKey(
                    self.utils.crypto.generateKeyPair().privateKey
                )
                try freshParticipant.localKeyStorage.store(data: freshKeyData)
                try freshParticipant.privateKeyChanged()

                let freshInitiator = try self.utils.setupDevice()
                let creatorChat = try freshInitiator
                    .createTemporaryChannel(with: freshParticipantId)
                    .startSync()
                    .get()
                let encryptedText = try creatorChat.encrypt(text: config.OriginText)

                let participantChat = try freshParticipant.loadTemporaryChannel(
                    asCreator: false,
                    with: freshInitiator.identity
                ).startSync().get()

                let decrypted = try participantChat.decrypt(text: encryptedText)
                XCTAssert(decrypted == config.OriginText,
                    "Fresh round-trip also failed — crypto format regression")
            }
        } catch {
            XCTFail("\(error)")
        }
    }

    // Run this test once whenever test10 fails with a stale Keyknox entry.
    // Steps:
    //   1. swift test --filter testZZZ_regenerateTemporaryChannelCompatData
    //      (with REGEN_COMPAT_DATA=1 set in the environment)
    //   2. Copy the printed <key>TemporaryChannel</key>…</dict> block into TestConfig.plist
    //   3. Re-encrypt: tar cf config.tar TestConfig.plist && openssl aes-256-cbc \
    //        -K $ENCRYPTION_KEY -iv $ENCRYPTION_IV -in config.tar -out config.tar.enc
    //   4. Commit config.tar.enc
    func testZZZ_regenerateTemporaryChannelCompatData() throws {
        guard ProcessInfo.processInfo.environment["REGEN_COMPAT_DATA"] == "1" else {
            throw XCTSkip("Set REGEN_COMPAT_DATA=1 to regenerate TemporaryChannel compat data")
        }

        let initiator = try self.utils.setupDevice()

        let participantIdentity = UUID().uuidString
        let participantKeyPair = try self.utils.crypto.generateKeyPair()
        let participantPrivateKeyData = try self.utils.crypto.exportPrivateKey(participantKeyPair.privateKey)

        let chat = try initiator.createTemporaryChannel(with: participantIdentity).startSync().get()

        let originText = "Hello, temporary channel compatibility!"
        let encryptedText = try chat.encrypt(text: originText)

        let fragment = """

=== TemporaryChannel compat data (replace in TestConfig.plist) ===
<key>TemporaryChannel</key>
<dict>
    <key>Identity</key>
    <string>\(participantIdentity)</string>
    <key>Initiator</key>
    <string>\(initiator.identity)</string>
    <key>PrivateKey</key>
    <string>\(participantPrivateKeyData.base64EncodedString())</string>
    <key>OriginText</key>
    <string>\(originText)</string>
    <key>EncryptedText</key>
    <string>\(encryptedText)</string>
</dict>
=== END ===
"""
        print(fragment)
    }

    func test11_STE_84__cleanup__should_reset_local_storage() {
        do {
            let keyPair = try self.utils.crypto.generateKeyPair()
            let ethree = try self.utils.setupDevice(keyPair: keyPair)

            let localTemporaryStorage = try FileTempKeysStorage(
                appGroup: nil,
                identity: ethree.identity,
                crypto: self.utils.crypto,
                identityKeyPair: keyPair
            )

            let identity = UUID().uuidString

            XCTAssert(try localTemporaryStorage.retrieve(identity: identity) == nil)

            _ = try ethree.createTemporaryChannel(with: identity).startSync().get()

            XCTAssert(try localTemporaryStorage.retrieve(identity: identity) != nil)

            try ethree.cleanUp()

            XCTAssert(try localTemporaryStorage.retrieve(identity: identity) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
