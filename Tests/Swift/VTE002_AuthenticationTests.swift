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

class VTE002_AuthenticationTests: XCTestCase {
    let utils = TestUtils()

    private func makeStorageParams() throws -> KeychainStorageParams {
        return try KeychainStorageParams.makeKeychainStorageParams()
    }

    func test01_STE_8__cleanUp__should_delete_local_key() {
        do {
            let storageParams = try self.makeStorageParams()
            let keychainStorage = KeychainStorage(storageParams: storageParams)
            defer { try? keychainStorage.deleteAllEntries() }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            let keyPair = try self.utils.crypto.generateKeyPair()
            let data = try self.utils.crypto.exportPrivateKey(keyPair.privateKey)
            _ = try keychainStorage.store(data: data, withName: ethree.identity, meta: nil)

            try ethree.cleanUp()

            let retrievedEntry = try? keychainStorage.retrieveEntry(withName: ethree.identity)
            XCTAssertNil(retrievedEntry)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02_STE_9__register__should_create_key_and_publish_card() {
        do {
            let ethree = try self.utils.setupDevice()

            XCTAssert(try ethree.hasLocalPrivateKey())

            let cards = try ethree.cardManager.searchCards(identities: [ethree.identity]).startSync().get()
            XCTAssertNotNil(cards.first)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03_STE_10__register__card_exists__should_fail() {
        do {
            let storageParams = try self.makeStorageParams()
            defer {
                let keychainStorage = KeychainStorage(storageParams: storageParams)
                try? keychainStorage.deleteAllEntries()
            }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            _ = self.utils.publishCard(identity: ethree.identity)

            do {
                try ethree.register().startSync().get()
                XCTFail()
            } catch EThreeError.userIsAlreadyRegistered {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04_STE_11__register__local_key_exists__should_fail() {
        do {
            let storageParams = try self.makeStorageParams()
            let keychainStorage = KeychainStorage(storageParams: storageParams)
            defer { try? keychainStorage.deleteAllEntries() }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            let keyPair = try self.utils.crypto.generateKeyPair()
            let data = try self.utils.crypto.exportPrivateKey(keyPair.privateKey)
            _ = try keychainStorage.store(data: data, withName: ethree.identity, meta: nil)

            do {
                try ethree.register().startSync().get()
                XCTFail()
            } catch EThreeError.privateKeyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05_STE_12__rotatePrivateKey__not_registered__should_fail() {
        do {
            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            do {
                try ethree.rotatePrivateKey().startSync().get()
                XCTFail()
            } catch EThreeError.userIsNotRegistered {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test06_STE_13__rotatePrivateKey__local_key_exists__should_fail() {
        do {
            let ethree = try self.utils.setupDevice()

            do {
                try ethree.rotatePrivateKey().startSync().get()
                XCTFail()
            } catch EThreeError.privateKeyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test07_STE_14__rotatePrivateKey__card_exists_no_local_key__should_succeed() {
        do {
            let storageParams = try self.makeStorageParams()
            let keychainStorage = KeychainStorage(storageParams: storageParams)
            defer { try? keychainStorage.deleteAllEntries() }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            let oldCard = self.utils.publishCard(identity: ethree.identity)

            try ethree.rotatePrivateKey().startSync().get()

            let cards = try ethree.cardManager.searchCards(identities: [ethree.identity]).startSync().get()
            XCTAssertNotNil(cards.first)
            XCTAssertEqual(cards.first?.previousCardId, oldCard.identifier)
            XCTAssertNotEqual(cards.first?.identifier, oldCard.identifier)

            let newEntry = try keychainStorage.retrieveEntry(withName: ethree.identity)
            let newKeyPair = try self.utils.crypto.importPrivateKey(from: newEntry.data)
            let oldPubKeyData = try self.utils.crypto.exportPublicKey(oldCard.publicKey)
            let newPubKeyData = try self.utils.crypto.exportPublicKey(newKeyPair.publicKey)
            XCTAssertNotEqual(oldPubKeyData, newPubKeyData)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test08_STE_20__unregister__should_revoke_card() {
        do {
            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            do {
                try ethree.unregister().startSync().get()
                XCTFail()
            } catch {}

            try ethree.register().startSync().get()
            try ethree.unregister().startSync().get()

            XCTAssert(try !ethree.hasLocalPrivateKey())

            let cards = try ethree.cardManager.searchCards(identities: [ethree.identity]).startSync().get()
            XCTAssert(cards.isEmpty)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test09_STE_44__register_with_keypair__should_store_provided_key() {
        do {
            let storageParams = try self.makeStorageParams()
            let keychainStorage = KeychainStorage(storageParams: storageParams)
            defer { try? keychainStorage.deleteAllEntries() }

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                storageParams: storageParams,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            let keyPair = try self.utils.crypto.generateKeyPair(ofType: .secp256r1)
            let exportedPrivateKey = try self.utils.crypto.exportPrivateKey(keyPair.privateKey)

            try ethree.register(with: keyPair).startSync().get()

            let keyEntry = try keychainStorage.retrieveEntry(withName: ethree.identity)
            XCTAssertEqual(exportedPrivateKey, keyEntry.data)

            let cards = try ethree.cardManager.searchCards(identities: [ethree.identity]).startSync().get()
            XCTAssertEqual(cards.first?.identity, ethree.identity)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
