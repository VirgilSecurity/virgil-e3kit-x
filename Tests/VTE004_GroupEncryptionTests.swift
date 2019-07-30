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
import VirgilCrypto
import VirgilSDK

class VTE004_GroupEncryptionTests: XCTestCase {
    var testUtils: TestUtils!
    let crypto = try! VirgilCrypto()

    override func setUp() {
        let consts = TestConfig.readFromBundle()

        self.testUtils = TestUtils(crypto: self.crypto, consts: consts)
    }

    private func setUpDevice() -> (EThree) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.testUtils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try! EThree.initialize(tokenCallback: tokenCallback).startSync().get()

        try! ethree.register().startSync().get()

        return ethree
    }

    func test_1__encrypt_decrypt__should_succeed() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()
        let ethree3 = self.setUpDevice()

        let identities = [ethree2.identity, ethree3.identity]

        let groupId = try! self.crypto.generateRandomData(ofSize: 100)

        // User1 creates group, encrypts
        let lookup = try! ethree1.lookupCards(of: identities).startSync().get()
        let group1 = try! ethree1.createGroup(id: groupId, with: lookup).startSync().get()

        let participants = Set(identities).union([ethree1.identity])
        XCTAssert(group1.participants == participants)

        let message = "Hello, \(ethree2.identity), \(ethree3.identity)!"
        let encrypted = try! group1.encrypt(text: message)

        // User2 updates group, decrypts
        let ethree1Card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()
        let group2 = try! ethree2.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()
        XCTAssert(group2.participants == participants)

        let card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()

        let decrypted = try! group2.decrypt(text: encrypted, from: card)

        XCTAssert(message == decrypted)
    }

    func test_2__add_remove_participants__should_succeed() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()
        let ethree3 = self.setUpDevice()
        let ethree4 = self.setUpDevice()

        // User 1 creates group
        let identities = [ethree2.identity, ethree3.identity]
        let groupId = try! self.crypto.generateRandomData(ofSize: 100)

        let lookup = try! ethree1.lookupCards(of: identities).startSync().get()

        let group1 = try! ethree1.createGroup(id: groupId, with: lookup).startSync().get()

        // User 2 and User 3 update it
        let ethree1Card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()

        let group2 = try! ethree2.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()

        let group3 = try! ethree3.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()

        // User 1 removes User3 and adds User 4
        let ethree4Card = try! ethree1.lookupCard(of: ethree4.identity).startSync().get()

        try! group1.add(participant: ethree4Card).startSync().get()
        try! group1.remove(participant: lookup[ethree3.identity]!).startSync().get()

        let newIdentities = [ethree2.identity, ethree4.identity]
        let participants = Set(newIdentities).union([ethree1.identity])
        XCTAssert(group1.participants == participants)

        // Other Users update groups
        try! group2.update().startSync().get()

        do {
            try group3.update().startSync().get()
            XCTFail()
        } catch {
            // FIXME
        }

        XCTAssert(group2.participants == participants)

        let group4 = try! ethree4.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()
        XCTAssert(group4.participants == participants)

        // User 1 encrypts message for group
        let message = "Hello, \(ethree2.identity)!"

        let encrypted = try! group1.encrypt(text: message)

        // Other Users try! to decrypt
        let decrypted2 = try! group2.decrypt(text: encrypted, from: ethree1Card)

        let notDecrypted3 = try? group3.decrypt(text: encrypted, from: ethree1Card)

        let decrypted4 = try! group4.decrypt(text: encrypted, from: ethree1Card)

        XCTAssert(decrypted2 == message)
        XCTAssert(notDecrypted3 == nil)
        XCTAssert(decrypted4 == message)
    }

    func test_3__pull_alien_group__should_throw_error() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()
        let ethree3 = self.setUpDevice()

        let identities = [ethree2.identity]

        let groupId = try! self.crypto.generateRandomData(ofSize: 100)

        let lookup = try! ethree1.lookupCards(of: identities).startSync().get()
        _ = try! ethree1.createGroup(id: groupId, with: lookup).startSync().get()

        let ethree1Card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()

        do {
            _ = try ethree3.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()
            XCTFail()
        } catch {
            // FIXME
        }
    }

    func test_4__pull_nonexistent_group__should_throw_error() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()
        let ethree3 = self.setUpDevice()

        let identities = [ethree2.identity]

        let groupId = try! self.crypto.generateRandomData(ofSize: 100)

        let lookup = try! ethree1.lookupCards(of: identities).startSync().get()
        _ = try! ethree1.createGroup(id: groupId, with: lookup).startSync().get()

        let ethree1Card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()

        let nonExistentGroupId = try! self.crypto.generateRandomData(ofSize: 100)

        do {
            _ = try ethree3.pullGroup(id: nonExistentGroupId, initiator: ethree1Card).startSync().get()
            XCTFail()
        } catch {
            // FIXME
        }
    }

    func test_5__pull_or_update_deleted_group__should_throw_error() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()

        let identities = [ethree2.identity]

        let groupId = try! self.crypto.generateRandomData(ofSize: 100)

        let lookup = try! ethree1.lookupCards(of: identities).startSync().get()
        let group1 = try! ethree1.createGroup(id: groupId, with: lookup).startSync().get()

        let ethree1Card = try! ethree2.lookupCard(of: ethree1.identity).startSync().get()
        let group2 = try! ethree2.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()

        try! group1.delete().startSync().get()

        do {
            try group2.update().startSync().get()
            XCTFail()
        } catch {
            // FIXME
        }

        do {
            _ = try ethree2.pullGroup(id: groupId, initiator: ethree1Card).startSync().get()
            XCTFail()
        } catch {
            // FIXME
        }
    }
}

