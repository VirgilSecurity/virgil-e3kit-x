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
import VirgilSDK
import VirgilCrypto

// MARK: - Extension with find users operations
extension EThree {
    /// Retrieves cards from local storage with given identities
    ///
    /// - Parameters:
    ///   - identities: identities of cards to retrieve
    ///   - checkResult: checks that cards for all identities were found if true
    /// - Returns: `FindUsersResult`
    /// - Throws: corresponding error
    @objc open func findCachedUsers(with identities: [String],
                                    checkResult: Bool = true) throws -> FindUsersResult {
        return try self.lookupManager.lookupCachedCards(of: identities, checkResult: checkResult)
    }

    /// Returnes card from local storage with given identity
    ///
    /// - Parameter identity: identity
    /// - Returns: Card if it exists, nil otherwise
    @objc open func findCachedUser(with identity: String) -> Card? {
        return  try? self.lookupManager.lookupCachedCard(of: identity)
    }

    /// Retrieves users Cards from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identities: array of identities to find
    ///   - forceReload: will not use local cached cards if true
    ///   - checkResult: checks that cards for all identities were found if true
    /// - Returns: CallbackOperation<FindUsersResult>
    open func findUsers(with identities: [String],
                        forceReload: Bool = false,
                        checkResult: Bool = true) -> GenericOperation<FindUsersResult> {
        return CallbackOperation { _, completion in
            do {
                let cards = try self.lookupManager.lookupCards(of: identities,
                                                               forceReload: forceReload,
                                                               checkResult: checkResult)

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
    open func findUser(with identity: String, forceReload: Bool = false) -> GenericOperation<Card> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.lookupManager.lookupCard(of: identity, forceReload: forceReload)

                completion(card, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Updates local cached cards
    open func updateCachedUsers() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.lookupManager.startUpdateCachedCards { error in
                if let error = error {
                    completion(nil, error)
                } else {
                    completion((), nil)
                }
            }
        }
    }
}
