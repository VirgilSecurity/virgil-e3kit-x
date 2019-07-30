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

import VirgilSDK

public typealias LookupResult = [String: Card]

internal class LookupManager {
    internal let cardStorage: FileCardStorage
    internal let cardManager: CardManager

    internal let maxSearchCount = 50

    internal init(cardStorage: FileCardStorage, cardManager: CardManager) {
        self.cardStorage = cardStorage
        self.cardManager = cardManager
    }

    public func lookupCachedCards(of identities: [String]) throws -> LookupResult {
        guard !identities.isEmpty else {
            throw EThreeError.missingIdentities
        }

        var result: LookupResult = [:]

        try identities.forEach {
            result[$0] = try self.lookupCachedCard(of: $0)
        }

        return result
    }

    public func lookupCachedCard(of identity: String) throws -> Card {
        guard let card = self.cardStorage.retrieve(identity: identity) else {
            throw EThreeError.missingCachedCard
        }

        return card
    }

    public func lookupCards(of identities: [String], forceReload: Bool = false) throws -> LookupResult {
        guard !identities.isEmpty else {
            throw EThreeError.missingIdentities
        }

        var result: LookupResult = [:]

        var identitiesSet = Set(identities)

        if !forceReload {
            for identity in identitiesSet {
                if let card = self.cardStorage.retrieve(identity: identity) {
                    identitiesSet.remove(identity)
                    result[identity] = card
                }
            }
        }

        if !identitiesSet.isEmpty {
            let identitiesChunks = Array(identitiesSet).chunked(into: self.maxSearchCount)

            for identities in identitiesChunks {
                let cards = try self.cardManager.searchCards(identities: identities).startSync().get()

                for card in cards {
                    guard result[card.identity] == nil else {
                        throw EThreeError.duplicateCards
                    }

                    try self.cardStorage.store(card: card)

                    result[card.identity] = card
                }
            }
        }

        guard Set(result.keys) == Set(identities) else {
            throw EThreeError.cardWasNotFound
        }

        return result
    }

    public func lookupCard(of identity: String, forceReload: Bool = false) throws -> Card {
        let cards = try self.lookupCards(of: [identity])

        guard let card = cards[identity] else {
            throw EThreeError.cardWasNotFound
        }

        return card
    }
}
