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

    private func setUpDevice() throws -> (EThree) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.testUtils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree.initialize(tokenCallback: tokenCallback).startSync().get()

        try ethree.register().startSync().get()

        return ethree
    }

    func test_1_encrypt_decrypt() {
        do {
            let ethree1 = try self.setUpDevice()
            let ethree2 = try self.setUpDevice()
            let ethree3 = try self.setUpDevice()

            let identities = [ethree2.identity, ethree3.identity]

            let participants = try ethree1.lookupCards(of: identities).startSync().get()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            // User1 creates group, encrypts
            let group1 = try ethree1.createGroup(id: groupId, with: participants).startSync().get()

            let message = "Hello, \(ethree2.identity), \(ethree3.identity)!"
            let encrypted = try group1.encrypt(text: message)

            // User2 updates group, decrypts
            try ethree2.fetchGroup(id: groupId, initiator: ethree1.identity).startSync().get()

            let group2 = try ethree2.retrieveGroup(id: groupId)!

            let decrypted = try group2.decrypt(text: encrypted)

            XCTAssert(message == decrypted)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_2_change_participants() {
        do {
            let ethree1 = try self.setUpDevice()
            let ethree2 = try self.setUpDevice()
            let ethree3 = try self.setUpDevice()
            let ethree4 = try self.setUpDevice()

            // User 1 creates group
            let identities = [ethree2.identity, ethree3.identity]
            let participants = try ethree1.lookupCards(of: identities).startSync().get()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let group1 = try ethree1.createGroup(id: groupId, with: participants).startSync().get()

            // User 2 and User 3 update it
            try ethree2.fetchGroup(id: groupId, initiator: ethree1.identity).startSync().get()
            let group2 = try ethree2.retrieveGroup(id: groupId)!

            try ethree3.fetchGroup(id: groupId, initiator: ethree1.identity).startSync().get()
            let group3 = try ethree3.retrieveGroup(id: groupId)!

            // User 1 removes User3 and adds User 4
            let newIdentities = [ethree2.identity, ethree4.identity]
            let newParticipants = try ethree1.lookupCards(of: newIdentities).startSync().get()

            try group1.changeParticipants(to: newParticipants).startSync().get()

            // Other Users update groups
            try group2.update(initiator: ethree1.identity).startSync().get()
            try group3.update(initiator: ethree1.identity).startSync().get()

            try ethree4.fetchGroup(id: groupId, initiator: ethree1.identity).startSync().get()
            let group4 = try ethree4.retrieveGroup(id: groupId)!

            // User 1 encrypts message for group
            let message = "Hello, \(ethree2.identity)!"

            let encrypted = try group1.encrypt(text: message)

            // Other Users try to decrypt
            let decrypted2 = try group2.decrypt(text: encrypted)

            let notDecrypted3 = try? group3.decrypt(text: encrypted)

            let decrypted4 = try group4.decrypt(text: encrypted)

            XCTAssert(decrypted2 == message)
            XCTAssert(notDecrypted3 == nil)
            XCTAssert(decrypted4 == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

