//
// Copyright (C) 2015-2020 Virgil Security Inc.
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

class VTE006_LookupTests: XCTestCase {
    let utils = TestUtils()

    func test01_STE_1() {
        let ethree = try! self.utils.setupDevice()

        let card1 = self.utils.publishCard()
        let card2 = self.utils.publishCard()
        let card3 = self.utils.publishCard(identity: card2.identity,
                                           previousCardId: card2.identifier)

        let lookup = try! ethree.findUsers(with: [card1.identity, card2.identity, card3.identity]).startSync().get()

        XCTAssert(lookup.count == 2)
        XCTAssert(lookup.contains(where: { $0.value.identifier == card1.identifier } ))
        XCTAssert(lookup.contains(where: { $0.value.identifier == card3.identifier } ))
    }

    func test02_STE_2() {
        let ethree = try! self.utils.setupDevice()

        do {
            _ = try ethree.findUsers(with: []).startSync().get()
            XCTFail()
        } catch EThreeError.missingIdentities {} catch {
            XCTFail()
        }
    }

    func test03_STE_23() {
        let ethree = try! self.utils.setupDevice()

        let card1 = self.utils.publishCard()

        let foundCard1 = try! ethree.findUser(with: card1.identity).startSync().get()

        XCTAssert(foundCard1.identifier == card1.identifier)

        let card2 = self.utils.publishCard(identity: card1.identity,
                                           previousCardId: card1.identifier)

        let foundCard2 = try! ethree.findUser(with: card1.identity).startSync().get()

        XCTAssert(foundCard2.identifier == foundCard1.identifier)

        let foundCard3 = try! ethree.findUser(with: card1.identity, forceReload: true).startSync().get()

        XCTAssert(foundCard3.identifier == card2.identifier)

        let cachedCard = ethree.findCachedUser(with: card1.identity)!

        XCTAssert(cachedCard.identifier == card2.identifier)
    }

    func test04_STE_24() {
        let ethree = try! self.utils.setupDevice()

        let card1 = self.utils.publishCard()
        _ = self.utils.publishCard(identity: card1.identity)

        do {
            _ = try ethree.findUser(with: card1.identity).startSync().get()
            XCTFail()
        } catch FindUsersError.duplicateCards {} catch {
            XCTFail()
        }
    }

    func test05_STE_25() {
        let card = self.utils.publishCard()

        class DummyClass: ChangedKeyDelegate {
            var called = false
            let identity: String

            init(identity: String) {
                self.identity = identity
            }

            func keyChanged(identity: String) {
                XCTAssert(identity == self.identity)
                self.called = true
            }
        }

        let delegate = DummyClass(identity: card.identity)

        let ethree = try! self.utils.setupDevice()

        _ = try! ethree.findUser(with: card.identity).startSync().get()

        let newCard = self.utils.publishCard(identity: card.identity,
                                             previousCardId: card.identifier)

        let newEThree = try! self.utils.setupEThree(identity: ethree.identity,
                                                    enableRatchet: false,
                                                    changedKeyDelegate: delegate)

        sleep(5)

        XCTAssert(delegate.called)

        let cachedCard = newEThree.findCachedUser(with: card.identity)!

        XCTAssert(cachedCard.identifier == newCard.identifier)
    }

    func test06_STE_47__checkResult() {
        let ethree = try! self.utils.setupDevice()

        let card = self.utils.publishCard()
        let dummyIdentity = UUID().uuidString

        let identities = [card.identity, dummyIdentity]

        do {
            _ = try ethree.findUsers(with: identities).startSync().get()
        }
        catch FindUsersError.cardWasNotFound {} catch {
            XCTFail()
        }

        let cards = try! ethree.findUsers(with: identities, checkResult: false).startSync().get()

        XCTAssert(cards.count == 1)
        XCTAssert(cards[card.identity]!.identifier == card.identifier)
    }

    func test07_STE_48__updateCachedCards() {
        let ethree1 = try! self.utils.setupDevice()
        let ethree2 = try! self.utils.setupDevice()

        let card2 = try! ethree1.findUser(with: ethree2.identity, forceReload: false).startSync().get()

        try! ethree2.cleanUp()
        try! ethree2.rotatePrivateKey().startSync().get()

        try! ethree1.updateCachedUsers().startSync().get()

        let newCard2 = try! ethree1.findUser(with: ethree2.identity, forceReload: false).startSync().get()

        XCTAssert(newCard2.previousCard?.identifier == card2.identifier)
    }
}
