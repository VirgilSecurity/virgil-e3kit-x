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

class VTE004_MixtecTests: XCTestCase {
    let utils = TestUtils()

    var crypto: VirgilCrypto {
        return self.utils.crypto
    }

    private func setUpDevice() -> EThree {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try! EThree(identity: identity, tokenCallback: tokenCallback)

        try! ethree.register().startSync().get()

        return ethree
    }

    func test001_STE_26__create_with_invalid_participants_count__should_throw_error() {
        do {
            let ethree = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let card = try ethree.findUser(with: ethree.identity).startSync().get()

            var lookup: [String: Card] = [:]
            for _ in 0..<100 {
                let identity = UUID().uuidString
                lookup[identity] = card
            }

            do {
                _ = try ethree.createGroup(id: groupId, with: lookup).startSync().get()
                XCTFail()
            } catch GroupError.invalidParticipantsCount {}

            let newLookup = Dictionary(dictionaryLiteral: lookup.first!)

            let group = try ethree.createGroup(id: groupId, with: newLookup).startSync().get()

            XCTAssert(group.participants.count == 2)
            XCTAssert(group.participants.contains(ethree.identity))
            XCTAssert(group.participants.contains(newLookup.keys.first!))
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test002_STE_27__create__should_add_self() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId1 = try self.crypto.generateRandomData(ofSize: 100)
            let groupId2 = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree1.identity, ethree2.identity]).startSync().get()

            let group1 = try ethree1.createGroup(id: groupId1, with: lookup).startSync().get()
            let group2 = try ethree1.createGroup(id: groupId2, with: [ethree2.identity: lookup[ethree2.identity]!]).startSync().get()

            XCTAssert(group2.participants.contains(ethree1.identity))
            XCTAssert(group1.participants == group2.participants)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test003_STE_28__groupId__should_not_be_short() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 5)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()

            do {
                _ = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()
                XCTFail()
            } catch GroupError.shortGroupId {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test004_STE_29__get_group() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            XCTAssert(try ethree1.getGroup(id: groupId) == nil)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()

            let group = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let cachedGroup = try ethree1.getGroup(id: groupId)!

            XCTAssert(cachedGroup.participants == group.participants)
            XCTAssert(cachedGroup.initiator == group.initiator)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test005_STE_30__load_group() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()

            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card = try ethree2.findUser(with: ethree1.identity).startSync().get()

            let group2 = try ethree2.loadGroup(id: groupId, initiator: card).startSync().get()

            XCTAssert(group1.participants == group2.participants)
            XCTAssert(group1.initiator == group2.initiator)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test006_STE_31__load_alien_or_unexistent_group__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            do {
                _ = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            let lookup = try ethree1.findUsers(with: [ethree3.identity]).startSync().get()

            _ = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            do {
                _ = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test007_STE_32__actions_on_deleted_group__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()

            _ = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()

            try ethree1.deleteGroup(id: groupId).startSync().get()

            XCTAssert(try ethree1.getGroup(id: groupId) == nil)

            do {
                _ = try ethree1.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            do {
                try group2.update().startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            do {
                _ = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            XCTAssert(try ethree2.getGroup(id: groupId) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test008_STE_33__add_more_than_max__should_throw_error() {
        do {
            let ethree = self.setUpDevice()

            var participants: Set<String> = Set()

            for _ in 0..<100 {
                let identity = UUID().uuidString
                participants.insert(identity)
            }

            let sessionId = try self.crypto.generateRandomData(ofSize: 32)

            let ticket = try Ticket(crypto: self.crypto, sessionId: sessionId, participants: participants)
            let rawGroup = try RawGroup(info: GroupInfo(initiator: ethree.identity), tickets: [ticket])

            let group = try Group(rawGroup: rawGroup,
                                   crypto: self.crypto,
                                   localKeyStorage: ethree.localKeyStorage,
                                   groupManager: try ethree.getGroupManager(),
                                   lookupManager: ethree.lookupManager)

            let card = self.utils.publishCard()

            do {
                try group.add(participant: card).startSync().get()
                XCTFail()
            } catch GroupError.invalidParticipantsCount {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test009_STE_72__remove_last_participant__should_throw_error() {
        do {
            let ethree = self.setUpDevice()
            let card = try ethree.findUser(with: ethree.identity).startSync().get()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let group = try ethree.createGroup(id: groupId).startSync().get()

            do {
                try group.remove(participant: card).startSync().get()
                XCTFail()
            } catch GroupError.invalidParticipantsCount {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test010_STE_35__remove() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity, ethree3.identity]).startSync().get()

            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
            let group3 = try ethree3.loadGroup(id: groupId, initiator: card1).startSync().get()

            try group1.remove(participant: lookup[ethree2.identity]!).startSync().get()

            XCTAssert(!group1.participants.contains(ethree2.identity))

            try group3.update().startSync().get()

            XCTAssert(!group3.participants.contains(ethree2.identity))

            do {
                try group2.update().startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            do {
                _ = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch GroupError.groupWasNotFound {}

            XCTAssert(try ethree2.getGroup(id: groupId) == nil)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test011_STE_37__add() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()

            let card3 = try ethree1.findUser(with: ethree3.identity).startSync().get()
            try group1.add(participant: card3).startSync().get()

            let participants = Set([ethree1.identity, ethree2.identity, ethree3.identity])
            XCTAssert(group1.participants == participants)

            try group2.update().startSync().get()

            let group3 = try ethree3.loadGroup(id: groupId, initiator: card1).startSync().get()

            XCTAssert(group2.participants == participants)
            XCTAssert(group3.participants == participants)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test012_STE_36__change_group_by_noninitiator__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()
            let ethree4 = self.setUpDevice()

            let identities = [ethree2.identity, ethree3.identity]

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: identities).startSync().get()
            _ = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let ethree1Card = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let group2 = try ethree2.loadGroup(id: groupId, initiator: ethree1Card).startSync().get()

            do {
                try ethree2.deleteGroup(id: groupId).startSync().get()
                XCTFail()
            } catch GroupError.groupPermissionDenied {}

            do {
                try group2.remove(participant: lookup[ethree3.identity]!).startSync().get()
                XCTFail()
            } catch GroupError.groupPermissionDenied {}

            do {
                let ethree4Card = try ethree2.findUser(with: ethree4.identity).startSync().get()
                try group2.add(participant: ethree4Card).startSync().get()
                XCTFail()
            } catch GroupError.groupPermissionDenied {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test013_STE_38__decrypt_with_old_card__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()
            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()

            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()

            try ethree2.cleanUp()
            try ethree2.rotatePrivateKey().startSync().get()

            let encrypted = try group2.encrypt(text: "Some text")

            do {
                _ = try group1.decrypt(text: encrypted, from: card2)
                XCTFail()
            } catch GroupError.verificationFailed {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test014_STE_39__integration_encryption() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()

            let identities = [ethree2.identity]

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()

            // User1 creates group, encrypts
            let lookup = try ethree1.findUsers(with: identities).startSync().get()
            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()
            let message1 = UUID().uuidString
            let encrypted1 = try group1.encrypt(text: message1)
            let selfDecrypted1 = try group1.decrypt(text: encrypted1, from: card1)
            XCTAssert(selfDecrypted1 == message1)

            // User2 updates group, decrypts
            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()
            let decrypted1 = try group2.decrypt(text: encrypted1, from: card1)
            XCTAssert(message1 == decrypted1)

            // Add User3, encrypts
            let card3 = try ethree1.findUser(with: ethree3.identity).startSync().get()
            try group1.add(participant: card3).startSync().get()
            let message2 = UUID().uuidString
            let encrypted2 = try group1.encrypt(text: message2)
            let selfDecrypted2 = try group1.decrypt(text: encrypted2, from: card1)
            XCTAssert(selfDecrypted2 == message2)

            // Other updates, decrypts
            try group2.update().startSync().get()
            let group3 = try ethree3.loadGroup(id: groupId, initiator: card1).startSync().get()
            let decrypted22 = try group2.decrypt(text: encrypted2, from: card1)
            let decrypted23 = try group3.decrypt(text: encrypted2, from: card1)
            XCTAssert(decrypted22 == message2)
            XCTAssert(decrypted23 == message2)

            // Remove User2
            try group1.remove(participants: lookup).startSync().get()
            let message3 = UUID().uuidString
            let encrypted3 = try group1.encrypt(text: message3)
            let selfDecrypted3 = try group1.decrypt(text: encrypted3, from: card1)
            XCTAssert(selfDecrypted3 == message3)

            // Other updates, decrypts
            do {
                _ = try group2.decrypt(text: encrypted3, from: card1)
                XCTFail()
            } catch {}

            try group3.update().startSync().get()
            let decrypted3 = try group3.decrypt(text: encrypted3, from: card1)
            XCTAssert(decrypted3 == message3)

            // User3 rotates key
            try ethree3.cleanUp()
            try ethree3.rotatePrivateKey().startSync().get()

            do {
                try group3.update().startSync().get()
                XCTFail()
            } catch {}

            XCTAssert(try ethree3.getGroup(id: groupId) == nil)

            do {
                _ = try ethree3.loadGroup(id: groupId, initiator: card1).startSync().get()
                XCTFail()
            } catch {}

            // User 1 encrypts, reAdds User3
            let message4 = UUID().uuidString
            let encrypted4 = try group1.encrypt(text: message4)

            let newCard3 = try ethree1.findUser(with: ethree3.identity, forceReload: true).startSync().get()
            try group1.reAdd(participant: newCard3).startSync().get()

            let newGroup3 = try ethree3.loadGroup(id: groupId, initiator: card1).startSync().get()
            let decrypted4 = try newGroup3.decrypt(text: encrypted4, from: card1)
            XCTAssert(decrypted4 == message4)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test015_STE_42__decrypt_with_old_group__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()
            let ethree3 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity, ethree3.identity]).startSync().get()
            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()

            try group1.remove(participant: lookup[ethree3.identity]!).startSync().get()

            let message = UUID().uuidString
            let encrypted = try group1.encrypt(text: message)

            do {
                _ = try group2.decrypt(text: encrypted, from: card1)
                XCTFail()
            } catch GroupError.groupIsOutdated {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test016_STE_43__decrypt_with_old_group__should_throw_error() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let groupId = try self.crypto.generateRandomData(ofSize: 100)

            let lookup = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()
            let group1 = try ethree1.createGroup(id: groupId, with: lookup).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let group2 = try ethree2.loadGroup(id: groupId, initiator: card1).startSync().get()

            let date1 = Date()
            let message1 = UUID().uuidString
            let encrypted1 = try group2.encrypt(text: message1)

            sleep(1)

            try ethree2.cleanUp()
            try ethree2.rotatePrivateKey().startSync().get()

            let date2 = Date()
            let message2 = UUID().uuidString
            let encrypted2 = try group2.encrypt(text: message2)

            let card2 = try ethree1.findUser(with: ethree2.identity, forceReload: true).startSync().get()

            do {
                _ = try group1.decrypt(text: encrypted1, from: card2)
                XCTFail()
            } catch GroupError.verificationFailed {}

            do {
                _ = try group1.decrypt(text: encrypted1, from: card2, date: date2)
                XCTFail()
            } catch GroupError.verificationFailed {}

            let dectypted1 = try group1.decrypt(text: encrypted1, from: card2, date: date1)
            XCTAssert(message1 == dectypted1)

            do {
                _ = try group1.decrypt(text: encrypted2, from: card2, date: date1)
                XCTFail()
            } catch GroupError.verificationFailed {}

            let dectypted2 = try group1.decrypt(text: encrypted2, from: card2, date: date2)
            XCTAssert(message2 == dectypted2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test017_STE_45__compatibility() {
        do {
            let config = self.utils.config.Group

            // Init ethree instance
            let params = try KeychainStorageParams.makeKeychainStorageParams()
            let keychainStorage = KeychainStorage(storageParams: params)
            try? keychainStorage.deleteEntry(withName: config.Identity)

            let privateKeyData = Data(base64Encoded: config.PrivateKey)!
            _ = try keychainStorage.store(data: privateKeyData, withName: config.Identity, meta: nil)

            let tokenCallback: EThree.RenewJwtCallback = { completion in
                let token = self.utils.getTokenString(identity: config.Identity)

                completion(token, nil)
            }

            let ethree = try EThree(identity: config.Identity, tokenCallback: tokenCallback)

            // Load Group
            let initiatorCard = try ethree.findUser(with: config.Initiator).startSync().get()

            let groupIdData = Data(base64Encoded: config.GroupId)!
            let group = try ethree.loadGroup(id: groupIdData, initiator: initiatorCard).startSync().get()

            XCTAssert(group.participants == Set(config.Participants))

            // Decrypt
            let decrypted = try group.decrypt(text: config.EncryptedText, from: initiatorCard)

            XCTAssert(decrypted == config.OriginText)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test018_STE_46__string_identifier() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let identifier = UUID().uuidString

            let result = try ethree1.findUsers(with: [ethree2.identity]).startSync().get()
            _ = try ethree1.createGroup(id: identifier, with: result).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            _ = try ethree2.loadGroup(id: identifier, initiator: card1).startSync().get()

            _ = try ethree1.getGroup(id: identifier)
            _ = try ethree2.getGroup(id: identifier)

            try ethree1.deleteGroup(id: identifier).startSync().get()
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test019_STE_73__added_participant__should_decrypt_history() {
        do {
            let ethree1 = self.setUpDevice()
            let ethree2 = self.setUpDevice()

            let identifier = UUID().uuidString

            let group1 = try ethree1.createGroup(id: identifier).startSync().get()

            let message = UUID().uuidString
            let encrypted = try group1.encrypt(text: message)

            let card2 = try ethree1.findUser(with: ethree2.identity).startSync().get()
            try group1.add(participant: card2).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let group2 = try ethree2.loadGroup(id: identifier, initiator: card1).startSync().get()

            let decrypted = try group2.decrypt(text: encrypted, from: card1)

            XCTAssert(decrypted == message)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

