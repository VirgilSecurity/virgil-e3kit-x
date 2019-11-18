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
    var ethree: EThree!

    var crypto: VirgilCrypto {
       return self.utils.crypto
    }

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

    /// Initializes user on current device
    /// - Parameters:
    ///   - identity: identity of user
    ///   - password: user password
    open func initUser(backupPassword: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                // Clean up local Private Key if exists
                if try self.ethree.hasLocalPrivateKey() {
                   try self.ethree.cleanUp()
                }

                do {
                   let selfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true)
                       .startSync()
                       .get()

                   // Self Card found, current user exists on Virgil Cloud
                   try self.restoreUser(backupPassword: backupPassword, selfCard: selfCard)
                }
                catch FindUsersError.cardWasNotFound {
                   // Self Card was not found, user is not registered on VirgilCloud
                   try self.createUser(backupPassword: backupPassword)
                }

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Registeres user on Virgil Cloud and backs up Private Key
    /// - Parameter password: backup password
    open func createUser(backupPassword: String) throws {
        do {
            try self.ethree.register().startSync().get()

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
        }
        catch CloudKeyStorageError.entryAlreadyExists {
            // For some reason Private Key backup already exists.
            // We should reset it and back up new one
            try self.ethree.resetPrivateKeyBackup().startSync().get()

            // This sleep prevents throttling on Virgil Pythia service
            sleep(2)

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
        }
    }

    /// Restores user Private Key
    /// - Parameters:
    ///   - password: backup password
    ///   - selfCard: Self Card
    open func restoreUser(backupPassword: String, selfCard: Card) throws {
        do {
            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            // Checking if restored Private Key matches active Self Card
            if try !self.isKeyValid(card: selfCard) {
               // Reset not valid backup
               try self.ethree.resetPrivateKeyBackup().startSync().get()

               // This sleep prevents throttling on Virgil Pythia service
               sleep(2)

               try self.rotateKey(backupPassword: backupPassword)
            }
        }
        catch CloudKeyStorageError.entryNotFound {
            // This sleep prevents throttling on Virgil Pythia service
            sleep(2)

            try self.rotateKey(backupPassword: backupPassword)
        }
    }

    /// Checks if restored Private Key matches active Self Card
    /// - Parameter card: Self Card to check
    open func isKeyValid(card: Card) throws -> Bool {
        // Retrieve local Private Key
        let params = try KeychainStorageParams.makeKeychainStorageParams()
        let keychain = KeychainStorage(storageParams: params)
        let entry = try keychain.retrieveEntry(withName: self.ethree.identity)
        let keyPair = try self.crypto.importPrivateKey(from: entry.data)

        // Check that id of Self Card Public Key matches local Private Key one
        return card.publicKey.identifier == keyPair.identifier
    }

    /// Performs rotate operation
    /// - Parameter password: backup password
    open func rotateKey(backupPassword: String) throws {
        // Clean up local Private Key if exists
        if try self.ethree.hasLocalPrivateKey() {
           try self.ethree.cleanUp()
        }

        try self.ethree.rotatePrivateKey().startSync().get()
        try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

        // You need to notify other contacts that they need to find this user
        // with forceReload=true to update cached card of this user
        try self.notifyContactsAboutRotate()
    }

    open func notifyContactsAboutRotate() throws {
        print("key was rotated")
        // TODO: Fill me
    }

//----------------------------------------------------------------------------------------------------------------

    func test01__regular_sign_in__should_decrypt() {
        do {
            self.ethree = try self.setUpDevice()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            let message = UUID().uuidString
            let encrypted = try self.ethree.authEncrypt(text: message)

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

            sleep(2)

            try self.initUser(backupPassword: backupPassword).startSync().get()

            let decrypted = try self.ethree.authDecrypt(text: encrypted)
            XCTAssert(decrypted == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02__no_backup__should_rotate() {
        do {
            self.ethree = try self.setUpDevice()

            let selfCard = try self.ethree.findUser(with: self.ethree.identity).startSync().get()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            try self.initUser(backupPassword: backupPassword).startSync().get()

            let newSelfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

            XCTAssert(newSelfCard.previousCardId == selfCard.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03__wrong_password__should_throw_error() {
        do {
            self.ethree = try self.setUpDevice()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

            sleep(2)

            let fakePassword = UUID().uuidString

            do {
                try self.initUser(backupPassword: fakePassword).startSync().get()
                XCTFail()
            } catch EThreeError.wrongPassword { }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04__initUser__with_wrong_backup__should_rotate() {
        do {
            self.ethree = try self.setUpDevice()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

            try self.ethree.cleanUp()
            try self.ethree.rotatePrivateKey().startSync().get()

            let selfCard = try self.ethree.findUser(with: self.ethree.identity).startSync().get()

            sleep(2)

            try self.initUser(backupPassword: backupPassword).startSync().get()

            let newSelfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true).startSync().get()

            XCTAssert(newSelfCard.previousCardId == selfCard.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05__register__with_existent_backup__should_backup_latest() {
        do {
            self.ethree = try self.setUpDevice()

            let password = UUID().uuidString
            // Derive separate passwords for login and backup from single one
            let backupPassword = try EThree.derivePasswords(from: password).backupPassword

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

            let params = try KeychainStorageParams.makeKeychainStorageParams()
            let keychain = KeychainStorage(storageParams: params)

            let entry1 = try keychain.retrieveEntry(withName: self.ethree.identity)
            let keyPair1 = try self.crypto.importPrivateKey(from: entry1.data)

            try self.ethree.unregister().startSync().get()

            sleep(2)

            try self.initUser(backupPassword: backupPassword).startSync().get()

            try self.ethree.cleanUp()

            sleep(2)

            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            let entry2 = try keychain.retrieveEntry(withName: self.ethree.identity)
            let keyPair2 = try self.crypto.importPrivateKey(from: entry2.data)

            XCTAssert(keyPair2.identifier != keyPair1.identifier)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
