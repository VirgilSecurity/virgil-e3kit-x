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

class VTE011_FlowTests: XCTestCase {
    let utils = TestUtils()
    let password = UUID().uuidString

    var crypto: VirgilCrypto {
       return self.utils.crypto
    }

    var ethree: EThree!

    override func setUp() {
        super.setUp()

        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        self.ethree = try! EThree(identity: identity, tokenCallback: tokenCallback)
    }

    internal func initUser(password: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                do {
                    try self.ethree.bootstrap(password: password).startSync().get()
                }
                catch EThreeError.wrongPassword {
                    // Ask password again, some UI
                    throw EThreeError.wrongPassword
                }
                catch EThreeError.unfinishedBootstrapOnOriginDevice {
                    sleep(2)

                    try self.rotateFlow(password: password)
                }
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func initUser() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                do {
                    try self.ethree.bootstrap().startSync().get()
                }
                catch EThreeError.needPassword {
                    try self.askPassword { password in
                        try self.initUser(password: password).startSync().get()
                    }
                }
                catch EThreeError.unfinishedBootstrapOnOriginDevice {
                    try self.askPassword { password in
                        try self.rotateFlow(password: password)
                    }
                }
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func rotateFlow(password: String) throws {
        try self.askToFinishBootstrapOnOriginDevice { deviceLost in
            if deviceLost {
                try self.ethree.rotateBootstrap(password: password).startSync().get()

                try self.notifyContactsAboutRotation()
            } else {
                // Some UI cancel flow
            }
        }
    }

    internal func askPassword(completion: @escaping (String) throws -> Void) throws {
        // Ask user password
        let password = self.password

        let backupPassword = try EThree.derivePasswords(from: password).backupPassword

        try completion(backupPassword)
    }

    internal func askToFinishBootstrapOnOriginDevice(completion: @escaping (Bool) throws -> Void) throws {
        print("Should rotate key")
        try completion(true)
    }

    internal func notifyContactsAboutRotation() throws {}


//----------------------------------------------------------------------------------------------------------------


    func test001__regular_sign_in__should_decrypt() {
        do {
            try self.initUser().startSync().get()

            let message = UUID().uuidString
            let encrypted = try self.ethree.authEncrypt(text: message)

            try self.initUser().startSync().get()

            let decrypted = try ethree.authDecrypt(text: encrypted)
            XCTAssert(decrypted == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test002__no_local__no_backup__should_rotate() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.resetPrivateKeyBackup().startSync().get()

            let selfCard = try ethree.findUser(with: self.ethree.identity).startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let newSelfCard = try ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

            XCTAssert(newSelfCard.previousCardId == selfCard.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test003__wrong_password__should_throw_error() {
        do {
            try self.initUser().startSync().get()

            sleep(2)

            let fakePassword = UUID().uuidString

            do {
                try self.initUser(password: fakePassword).startSync().get()
                XCTFail()
            } catch EThreeError.wrongPassword { }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test004__local__wrong_backup__should_update_backup() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.rotatePrivateKey().startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let selfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

            try self.ethree.cleanUp()

            let backupPassword = try EThree.derivePasswords(from: self.password).backupPassword
            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            let keyPair = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair.identifier == selfCard.publicKey.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test005__local__no_backup__should_update_backup() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.resetPrivateKeyBackup().startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let selfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

            try self.ethree.cleanUp()

            let backupPassword = try EThree.derivePasswords(from: self.password).backupPassword
            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            let keyPair = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair.identifier == selfCard.publicKey.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test006__register__with_existent_backup__should_backup_latest() {
        do {
            try self.initUser().startSync().get()

            let keyPair1 = try self.ethree.localKeyStorage.retrieveKeyPair()

            try self.ethree.unregister().startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            try self.ethree.cleanUp()

            sleep(2)

            let backupPassword = try EThree.derivePasswords(from: self.password).backupPassword
            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            let keyPair2 = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair2.identifier != keyPair1.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test007__register__with_existent_local__should_succeed() {
        do {
            let keyPair1 = try self.crypto.generateKeyPair()
            let data = try self.crypto.exportPrivateKey(keyPair1.privateKey)
            try self.ethree.localKeyStorage.store(data: data)

            try self.initUser().startSync().get()

            let keyPair2 = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair2.identifier != keyPair1.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test008__initUser__from_new_device__should_succeed() {
        do {
            try self.initUser().startSync().get()

            let keyPair1 = try self.ethree.localKeyStorage.retrieveKeyPair()

            try self.ethree.cleanUp()

            sleep(2)

            try self.initUser().startSync().get()

            let keyPair2 = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair1.identifier == keyPair2.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test009__wrong_local_key__with_backup__should_be_updated() {
        do {
            try self.initUser().startSync().get()

            let keyPair1 = try self.ethree.localKeyStorage.retrieveKeyPair()

            try self.ethree.cleanUp()

            let fakeKeyPair = try self.crypto.generateKeyPair()
            let data = try self.crypto.exportPrivateKey(fakeKeyPair.privateKey)
            try self.ethree.localKeyStorage.store(data: data)

            sleep(2)

            try self.initUser().startSync().get()

            let keyPair2 = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(keyPair1.identifier == keyPair2.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test010__wrong_local_key__no_backup__should_rotate_key() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.resetPrivateKeyBackup().startSync().get()

            let fakeKeyPair = try self.crypto.generateKeyPair()
            let data = try self.crypto.exportPrivateKey(fakeKeyPair.privateKey)
            try self.ethree.localKeyStorage.store(data: data)

            let card = try self.ethree.findUser(with: self.ethree.identity).startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let newCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()
            let keyPair = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(newCard.previousCardId == card.identifier)
            XCTAssert(keyPair.identifier == newCard.publicKey.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test011__no_local_key__wrong_backup__should_rotate_key() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.rotatePrivateKey().startSync().get()
            try self.ethree.cleanUp()

            let card = try self.ethree.findUser(with: self.ethree.identity).startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let newCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()
            let keyPair = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(newCard.previousCardId == card.identifier)
            XCTAssert(keyPair.identifier == newCard.publicKey.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test012__wrong_local_key__wrong_backup__should_rotate_key() {
        do {
            try self.initUser().startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.rotatePrivateKey().startSync().get()
            try self.ethree.cleanUp()

            let fakeKeyPair = try self.crypto.generateKeyPair()
            let data = try self.crypto.exportPrivateKey(fakeKeyPair.privateKey)
            try self.ethree.localKeyStorage.store(data: data)

            let card = try self.ethree.findUser(with: self.ethree.identity).startSync().get()

            sleep(2)

            try self.initUser().startSync().get()

            let newCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()
            let keyPair = try self.ethree.localKeyStorage.retrieveKeyPair()

            XCTAssert(newCard.previousCardId == card.identifier)
            XCTAssert(keyPair.identifier == newCard.publicKey.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

