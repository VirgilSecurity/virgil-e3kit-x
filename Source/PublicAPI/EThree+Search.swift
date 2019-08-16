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
import VirgilCrypto

// MARK: - Extension with find users operations
extension EThree {
    /// Returnes cards from local storage with given identities
    ///
    /// - Parameter identities: identities
    /// - Returns: `FindUsersResult`
    /// - Throws: corresponding error
    @objc public func findCachedUsers(with identities: [String]) throws -> FindUsersResult {
        return try self.lookupManager.lookupCachedCards(of: identities)
    }

    /// Returnes card from local storage with given identity
    ///
    /// - Parameter identity: identity
    /// - Returns: Card if it exists, nil otherwise
    @objc public func findCachedUser(with identity: String) -> Card? {
        return  try? self.lookupManager.lookupCachedCard(of: identity)
    }

    /// Retrieves users Cards from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identities: array of identities to find
    ///   - forceReload: will not use local cached cards if true
    /// - Returns: CallbackOperation<FindUsersResult>
    public func findUsers(with identities: [String], forceReload: Bool = false) -> GenericOperation<FindUsersResult> {
        return CallbackOperation { _, completion in
            do {
                let cards = try self.lookupManager.lookupCards(of: identities, forceReload: forceReload)

                completion(cards, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Retrieves user Card from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identity: identity to find
    ///   - forceReload: will not use local cached card if true
    /// - Returns: CallbackOperation<Card>
    public func findUser(with identity: String, forceReload: Bool = false) -> GenericOperation<Card> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.lookupManager.lookupCard(of: identity, forceReload: forceReload)

                completion(card, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Retrieves users public keys from the Virgil Cloud
    ///
    /// - Parameter identities: array of identities to find
    /// - Returns: CallbackOperation<LookupResult>
    @available(*, deprecated, message: "Use findUsers instead.")
    public func lookupPublicKeys(of identities: [String]) -> GenericOperation<LookupResult> {
        return CallbackOperation { _, completion in
            do {
                let cards = try self.findUsers(with: identities, forceReload: true).startSync().get()

                let result = cards.mapValues { $0.publicKey }

                completion(result, nil)
            }
            catch {
                completion(nil, error)
            }

        }
    }
}
