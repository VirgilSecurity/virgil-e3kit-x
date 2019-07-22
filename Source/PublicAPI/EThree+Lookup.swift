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

extension EThree {
    /// Typealias for the valid result of lookupPublicKeys call
    public typealias LookupResult = [String: Card]
    
    /// Retrieves user public keys from the cloud for encryption/verification.
    ///
    /// - Parameter identities: array of identities to search for
    /// - Returns: CallbackOperation<Void>
    public func lookupCards(of identities: [String], forceReload: Bool = false) -> GenericOperation<LookupResult> {
        return CallbackOperation { _, completion in
            do {
                guard !identities.isEmpty else {
                    throw EThreeError.missingIdentities
                }

                var result: LookupResult = [:]

                var identitiesSet = Set(identities)

                if !forceReload {
                    for identity in identitiesSet {
                        if let card = self.cardStorage.retrieveCard(identity: identity) {
                            identitiesSet.remove(identity)
                            result[identity] = card
                        }
                    }
                }

                if !identitiesSet.isEmpty {
                    let cards = try self.cardManager.searchCards(identities: Array(identitiesSet)).startSync().get()

                    for card in cards {
                        guard result[card.identity] == nil else {
                            throw EThreeError.duplicateCards
                        }

                        try self.cardStorage.store(card: card)

                        result[card.identity] = card
                    }
                }

                completion(result, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    public func lookupCard(of identity: String, forceReload: Bool = false) -> GenericOperation<Card> {
        return CallbackOperation { _, completion in
            do {
                var card: Card?

                if !forceReload {
                    card = self.cardStorage.retrieveCard(identity: identity)
                }

                if card == nil {
                    card = try self.cardManager.searchCards(identities: [identity]).startSync().get().first
                }

                guard let result = card else {
                    throw NSError()
                }

                completion(result, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
