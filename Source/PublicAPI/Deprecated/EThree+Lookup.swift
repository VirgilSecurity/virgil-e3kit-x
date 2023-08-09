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

// MARK: - Extension with deprecated lookup methods
extension EThree {
    /// Retrieves users public keys from the Virgil Cloud
    ///
    /// - Parameter identities: array of identities to find
    /// - Returns: CallbackOperation<LookupResult>
    @available(*, deprecated, message: "Use findUsers instead.")
    public func lookupPublicKeys(of identities: [String]) -> GenericOperation<LookupResult> {
        return CallbackOperation { _, completion in
            do {
                let cards = try self.findUsers(with: identities, forceReload: true).startSync()
                    .get()

                let result = cards.mapValues { $0.publicKey }

                completion(result, nil)
            } catch {
                completion(nil, error)
            }

        }
    }

    /// Retrieves users public keys from the Virgil Cloud
    ///
    /// - Parameters:
    ///   - identities: array of identities to find
    ///   - completion: completion handler
    ///   - lookupResult: dictionary with idenities as keys and found keys as values
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use findUsers instead.")
    @objc public func lookupPublicKeys(
        of identities: [String],
        completion: @escaping (
            _ lookupResult: LookupResult?,
            _ error: Error?
        ) -> Void
    ) {
        self.lookupPublicKeys(of: identities).start(completion: completion)
    }
}
