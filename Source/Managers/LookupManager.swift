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

/// Typealias for the result of findUsers call
public typealias FindUsersResult = [String: Card]

internal class LookupManager {
    internal let cardStorage: SQLiteCardStorage
    internal let cardManager: CardManager

    internal private(set) weak var changedKeyDelegate: ChangedKeyDelegate?

    private let queue = DispatchQueue(label: "LookupManager", qos: .background)

    private let maxSearchCount = 50
    private let maxGetOutdatedCount = 1_000

    internal init(cardStorage: SQLiteCardStorage,
                  cardManager: CardManager,
                  changedKeyDelegate: ChangedKeyDelegate?) {
        self.cardStorage = cardStorage
        self.cardManager = cardManager
        self.changedKeyDelegate = changedKeyDelegate
    }

    internal typealias ErrorHandler = (Error?) -> Void

    internal func startUpdateCachedCards(completion: ErrorHandler? = nil) {
        self.queue.async {
            do {
                Log.debug("Updating cached cards started")

                let cardIds = try self.cardStorage.getNewestCardIds()

                let cardIdsChunked = cardIds.chunked(into: self.maxGetOutdatedCount)

                for cardIds in cardIdsChunked {
                    let outdatedIds = try self.cardManager.getOutdated(cardIds: cardIds).startSync().get()

                    for outdatedId in  outdatedIds {
                        Log.debug("Cached card with id: \(outdatedId) expired")

                        guard let outdatedCard = try self.cardStorage.getCard(cardId: outdatedId) else {
                            throw FindUsersError.missingCachedCard
                        }

                        if let changedKeyDelegate = self.changedKeyDelegate {
                            changedKeyDelegate.keyChanged(identity: outdatedCard.identity)
                        }

                        let newCard = try self.lookupCard(of: outdatedCard.identity, forceReload: true)

                        try self.cardStorage.storeCard(newCard)

                        Log.debug("Cached card with id: \(outdatedId) updated to card with id \(newCard.identifier)")
                    }
                }

                Log.debug("Updating cached card finished")

                completion?(nil)
            } catch {
                Log.error("Updating cached cards failed: \(error.localizedDescription)")

                completion?(error)
            }
        }
    }
}

extension LookupManager {
    internal func lookupCachedCards(of identities: [String], checkResult: Bool) throws -> FindUsersResult {
        guard !identities.isEmpty else {
            throw EThreeError.missingIdentities
        }

        var result: FindUsersResult = [:]

        let cards = try self.cardStorage.searchCards(identities: identities)

        for card in cards {
            result[card.identity] = card
        }

        if checkResult {
            guard Set(result.keys) == Set(identities) else {
                throw FindUsersError.missingCachedCard
            }
        }

        return result
    }

    internal func lookupCachedCard(of identity: String) throws -> Card {
        let cards = try self.cardStorage.searchCards(identities: [identity])

        guard cards.count < 2 else {
            throw FindUsersError.duplicateCards
        }

        guard let card = cards.first else {
            throw FindUsersError.missingCachedCard
        }

        return card
    }

    internal func lookupCards(of identities: [String],
                              forceReload: Bool,
                              checkResult: Bool) throws -> FindUsersResult {
        guard !identities.isEmpty else {
            throw EThreeError.missingIdentities
        }

        var result: FindUsersResult = [:]

        var identitiesSet = Set(identities)

        if !forceReload {
            let cards = try self.cardStorage.searchCards(identities: Array(identitiesSet))

            for card in cards {
                result[card.identity] = card
                identitiesSet.remove(card.identity)
            }
        }

        if !identitiesSet.isEmpty {
            let identitiesChunks = Array(identitiesSet).chunked(into: self.maxSearchCount)

            for identities in identitiesChunks {
                let cards = try self.cardManager.searchCards(identities: identities).startSync().get()

                for card in cards {
                    guard result[card.identity] == nil else {
                        throw FindUsersError.duplicateCards
                    }

                    try self.cardStorage.storeCard(card)

                    result[card.identity] = card
                }
            }
        }

        if checkResult {
            guard Set(result.keys) == Set(identities) else {
                throw FindUsersError.cardWasNotFound
            }
        }

        return result
    }

    internal func lookupCard(of identity: String, forceReload: Bool = false) throws -> Card {
        let cards = try self.lookupCards(of: [identity], forceReload: forceReload, checkResult: true)

        guard let card = cards[identity] else {
            throw FindUsersError.cardWasNotFound
        }

        return card
    }
}
