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

    var crypto: VirgilCrypto {
       return self.utils.crypto
    }

    var ethree: EThree!

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

    func test01__regular_sign_in__should_decrypt() {
        do {
            let ethree = try self.setUpDevice()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            let message = UUID().uuidString
            let encrypted = try ethree.authEncrypt(text: message)

            try ethree.backupPrivateKey(password: backupPassword).startSync().get()

            sleep(2)

            try ethree.bootstrap().startSync().get()

            let decrypted = try ethree.authDecrypt(text: encrypted)
            XCTAssert(decrypted == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    internal func signIn(password: String) throws {
        do {
            try self.ethree.bootstrap(password: password).startSync().get()
        }
        catch EThreeError.wrongPassword {
            // Ask password again, some ui
        }
        catch EThreeError.unfinishedBootstrapOnOriginDevice {
            try self.rotateFlow(password: password)
        }
    }

    internal func signIn() throws {
        do {
            try self.ethree.bootstrap().startSync().get()
        }
        catch EThreeError.needPassword {
            // TODO: Ask password
            let password = UUID().uuidString

            try self.signIn(password: password)
        }
        catch EThreeError.unfinishedBootstrapOnOriginDevice {
            // TODO: Ask password
            let password = UUID().uuidString

            try self.rotateFlow(password: password)
        }
    }

    internal func rotateFlow(password: String) throws {
        // TODO: ask user to confirm he lost device
        let confirmed: Bool = true

        if confirmed {
            try self.ethree.rotateBootstrap(password: password).startSync().get()

            // Notify other users to update cached user card
        }
        else {
            // Some ui cancel flow
        }
    }

    func test02__no_backup__should_rotate() {
        do {
            self.ethree = try self.setUpDevice()

//            let selfCard = try ethree.findUser(with: ethree.identity).startSync().get()

            try ethree.cleanUp()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            do {
                try ethree.bootstrap().startSync().get()
            }
            catch EThreeError.needPassword {
                try ethree.bootstrap(password: backupPassword).startSync().get()
            }
            catch EThreeError.unfinishedBootstrapOnOriginDevice {
                print("yep")
            }

//            let newSelfCard = try ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

//            XCTAssert(newSelfCard.previousCardId == selfCard.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

//    func test03__wrong_password__should_throw_error() {
//        do {
//            self.ethree = try self.setUpDevice()
//
//            let password = UUID().uuidString
//            // Derive separate passwords for login and backup from single one
//            let backupPassword = try EThree.derivePasswords(from: password).backupPassword
//
//            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
//
//            sleep(2)
//
//            let fakePassword = UUID().uuidString
//
//            do {
//                try self.initUser(backupPassword: fakePassword).startSync().get()
//                XCTFail()
//            } catch EThreeError.wrongPassword { }
//        } catch {
//            print(error.localizedDescription)
//            XCTFail()
//        }
//    }
//
//    func test04__initUser__with_wrong_backup__should_rotate() {
//        do {
//            self.ethree = try self.setUpDevice()
//
//            let password = UUID().uuidString
//            // Derive separate passwords for login and backup from single one
//            let backupPassword = try EThree.derivePasswords(from: password).backupPassword
//
//            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
//
//            try self.ethree.cleanUp()
//            try self.ethree.rotatePrivateKey().startSync().get()
//
//            let selfCard = try self.ethree.findUser(with: self.ethree.identity).startSync().get()
//
//            sleep(2)
//
//            try self.initUser(backupPassword: backupPassword).startSync().get()
//
//            let newSelfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()
//
//            XCTAssert(newSelfCard.previousCardId == selfCard.identifier)
//        } catch {
//            print(error.localizedDescription)
//            XCTFail()
//        }
//    }
//
//    func test05__register__with_existent_backup__should_backup_latest() {
//        do {
//            self.ethree = try self.setUpDevice()
//
//            let password = UUID().uuidString
//            // Derive separate passwords for login and backup from single one
//            let backupPassword = try EThree.derivePasswords(from: password).backupPassword
//
//            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
//
//            let params = try KeychainStorageParams.makeKeychainStorageParams()
//            let keychain = KeychainStorage(storageParams: params)
//
//            let entry1 = try keychain.retrieveEntry(withName: self.ethree.identity)
//            let keyPair1 = try self.crypto.importPrivateKey(from: entry1.data)
//
//            try self.ethree.unregister().startSync().get()
//
//            sleep(2)
//
//            try self.initUser(backupPassword: backupPassword).startSync().get()
//
//            try self.ethree.cleanUp()
//
//            sleep(2)
//
//            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()
//
//            let entry2 = try keychain.retrieveEntry(withName: self.ethree.identity)
//            let keyPair2 = try self.crypto.importPrivateKey(from: entry2.data)
//
//            XCTAssert(keyPair2.identifier != keyPair1.identifier)
//        } catch {
//            print(error.localizedDescription)
//            XCTFail()
//        }
//    }
}

