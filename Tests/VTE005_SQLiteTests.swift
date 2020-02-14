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

import Foundation
import XCTest
@testable import VirgilE3Kit
import VirgilSDK
import VirgilCrypto

class VTE005_SQLiteTests: XCTestCase {
    
    private let cIdentity1 = "8DA6A11D-F8BC-4A1D-A221-CEE3A2D70631"
    private let cIdentity2 = "D4E8E4CA-6FB4-42B6-A3FF-DBBC19201DD6"
    
    private let cCardId1 = "b2e6c8bee5cfa40fa2ac2bc8961057600bced26bc5b29aab04014c5141a91bd4"
    private let cCardId2 = "9ff917a7a1aa0891b875d4a9e43972a0fb694879bf8987790c1615dd864a38a4"
    private let cCardId3 = "e66465a08232beb55e33b4ce5e8772d748911c9b830797336e1ce342c78829a2"
    
    private func copyPredefinedBase(identity: String) throws {
        let bundle = Bundle(for: VTE005_SQLiteTests.self)
        let dbUrl = bundle.url(forResource: "cards", withExtension: "sqlite")!
        
        var localUrl = try FileManager.default.url(for: .applicationSupportDirectory,
                                                   in: .userDomainMask,
                                                   appropriateFor: nil,
                                                   create: false)
        
        localUrl.appendPathComponent("VIRGIL_SQLITE")
        localUrl.appendPathComponent(identity)
        
        try FileManager.default.createDirectory(at: localUrl,
                                                withIntermediateDirectories: true,
                                                attributes: nil)
        
        localUrl.appendPathComponent("cards.sqlite")
        
        try FileManager.default.copyItem(at: dbUrl, to: localUrl)
    }
    
    private func checkCardsById(storage: SQLiteCardStorage) {
        let card1 = try! storage.getCard(cardId: self.cCardId1)!
        
        let card2 = try! storage.getCard(cardId: self.cCardId2)!
        
        let card3 = try! storage.getCard(cardId: self.cCardId3)!
        
        XCTAssert(card1.identity == self.cIdentity1)
        XCTAssert(card2.identity == self.cIdentity1)
        XCTAssert(card3.identity == self.cIdentity2)
        
        XCTAssert(card1.previousCardId == card2.identifier)
        XCTAssert(card2.previousCardId == nil)
        XCTAssert(card3.previousCardId == nil)
        
        XCTAssert(card1.previousCard == nil)
        XCTAssert(card2.previousCard == nil)
        XCTAssert(card3.previousCard == nil)
        
        XCTAssert(!card1.isOutdated)
        XCTAssert(card2.isOutdated)
        XCTAssert(!card3.isOutdated)
    }
    
    func test01__getCard__predefined_db__should_match() {
        let identity = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage = try! SQLiteCardStorage(userIdentifier: identity,
                                             crypto: crypto,
                                             verifier: verifier)
        
        self.checkCardsById(storage: storage)
    }
    
    private func checkCardsByIdentity(storage: SQLiteCardStorage) {
        let cards = try! storage.searchCards(identities: [self.cIdentity1, self.cIdentity2 ])
        
        XCTAssert(cards.count == 2)
        
        let card1 = cards.filter { $0.identity == self.cIdentity1}.first!
        let card2 = cards.filter { $0.identity == self.cIdentity2}.first!
        
        XCTAssert(card1.previousCardId != nil)
        XCTAssert(card2.previousCardId == nil)
        
        XCTAssert(card1.previousCard != nil)
        XCTAssert(card1.previousCard!.previousCard == nil)
        XCTAssert(card2.previousCard == nil)
        
        XCTAssert(!card1.isOutdated)
        XCTAssert(card1.previousCard!.isOutdated)
        XCTAssert(!card2.isOutdated)
    }
    
    func test02__searchCard__predefined_db__should_match() {
        let identity = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage = try! SQLiteCardStorage(userIdentifier: identity,
                                             crypto: crypto,
                                             verifier: verifier)

        self.checkCardsByIdentity(storage: storage)
    }
    
    func test03__store_card__predefined_cards__db_should_match() {
        let identity1 = UUID().uuidString
        let identity2 = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity2)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage1 = try! SQLiteCardStorage(userIdentifier: identity1,
                                              crypto: crypto,
                                              verifier: verifier)
        
        let storage2 = try! SQLiteCardStorage(userIdentifier: identity2,
                                              crypto: crypto,
                                              verifier: verifier)
        
        
        let cards = try! storage2.searchCards(identities: [self.cIdentity1, self.cIdentity2 ])
        
        try! storage1.storeCard(cards[0])
        try! storage1.storeCard(cards[1])
        
        self.checkCardsByIdentity(storage: storage1)
        self.checkCardsById(storage: storage1)
    }
    
    func test04__store__rotate_card__should_update_both_cards() {
        let identity1 = UUID().uuidString
        let identity2 = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity2)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage1 = try! SQLiteCardStorage(userIdentifier: identity1,
                                              crypto: crypto,
                                              verifier: verifier)
        
        let storage2 = try! SQLiteCardStorage(userIdentifier: identity2,
                                              crypto: crypto,
                                              verifier: verifier)
        
        
        let card1 = try! storage2.getCard(cardId: self.cCardId1)!
        
        let card2 = try! storage2.getCard(cardId: self.cCardId2)!
        
        let card3 = try! storage2.getCard(cardId: self.cCardId3)!
        
        card2.isOutdated = false
        try! storage1.storeCard(card2)
        
        try! storage1.storeCard(card1)
        
        try! storage1.storeCard(card3)
        
        self.checkCardsByIdentity(storage: storage1)
        self.checkCardsById(storage: storage1)
    }
    
    func test05__get_ids__predefined_cards__should_match() {
        let identity1 = UUID().uuidString
        let identity2 = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity2)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage1 = try! SQLiteCardStorage(userIdentifier: identity1,
                                              crypto: crypto,
                                              verifier: verifier)
        
        let storage2 = try! SQLiteCardStorage(userIdentifier: identity2,
                                              crypto: crypto,
                                              verifier: verifier)
        
        
        let cards = try! storage2.searchCards(identities: [self.cIdentity1, self.cIdentity2 ])
        
        try! storage1.storeCard(cards[0])
        try! storage1.storeCard(cards[1])
        
        let ids = try! storage1.getNewestCardIds()
        
        XCTAssert(ids.count == 2)
        
        XCTAssert(ids.contains(self.cCardId1))
        XCTAssert(ids.contains(self.cCardId3))
    }
    
    func test06__reset__predefined_db__should_be_empty() {
        let identity1 = UUID().uuidString
        let identity2 = UUID().uuidString
        
        try! self.copyPredefinedBase(identity: identity2)
        
        let crypto = try! VirgilCrypto()
        
        let verifier = VirgilCardVerifier(crypto: crypto)!
        
        let storage1 = try! SQLiteCardStorage(userIdentifier: identity1,
                                              crypto: crypto,
                                              verifier: verifier)
        
        let storage2 = try! SQLiteCardStorage(userIdentifier: identity2,
                                              crypto: crypto,
                                              verifier: verifier)
        
        
        let cards = try! storage2.searchCards(identities: [self.cIdentity1, self.cIdentity2 ])
        
        try! storage1.storeCard(cards[0])
        try! storage1.storeCard(cards[1])
        
        try! storage1.reset()
        
        let card1 = try! storage1.getCard(cardId: self.cCardId1)
        let card2 = try! storage1.getCard(cardId: self.cCardId2)
        let card3 = try! storage1.getCard(cardId: self.cCardId3)
        
        XCTAssert(card1 == nil)
        XCTAssert(card2 == nil)
        XCTAssert(card3 == nil)
        
        print(storage1.dbPath)
    }
}
