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

// MARK: - Extension with deprecated initialize methods
extension EThree {
    /// Initializes EThree with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - overrideVirgilPublicKey: Use this only while working with environments other than Virgil production
    ///   - serviceUrls: Service urls
    @available(*, deprecated, message: "Use constructor instead")
    public static func initialize(
        tokenCallback: @escaping RenewJwtCallback,
        changedKeyDelegate: ChangedKeyDelegate? = nil,
        storageParams: KeychainStorageParams? = nil,
        overrideVirgilPublicKey: String? = nil,
        serviceUrls: EThreeParams.ServiceUrls? = nil
    ) -> GenericOperation<EThree> {
        return CallbackOperation { _, completion in
            do {
                let accessTokenProvider = CachingJwtProvider { tokenCallback($1) }

                let tokenContext = TokenContext(service: "cards", operation: "")

                let getTokenOperation = CallbackOperation<AccessToken> { _, completion in
                    accessTokenProvider.getToken(with: tokenContext, completion: completion)
                }

                let token = try getTokenOperation.startSync().get()

                let params = EThreeParams(identity: token.identity(), tokenCallback: tokenCallback)

                params.changedKeyDelegate = changedKeyDelegate
                params.storageParams = storageParams
                params.overrideVirgilPublicKey = overrideVirgilPublicKey

                if let serviceUrls = serviceUrls {
                    params.serviceUrls = serviceUrls
                }

                let ethree = try EThree(params: params)

                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - overrideVirgilPublicKey: Use this only while working with environments other than Virgil production
    ///   - serviceUrls: Service urls
    ///   - completion: completion handler
    ///   - ethree: initialized EThree instance
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use constructor instead")
    @objc public static func initialize(
        tokenCallback: @escaping RenewJwtCallback,
        changedKeyDelegate: ChangedKeyDelegate? = nil,
        storageParams: KeychainStorageParams? = nil,
        overrideVirgilPublicKey: String? = nil,
        serviceUrls: EThreeParams.ServiceUrls? = nil,
        completion: @escaping (_ ethree: EThree?, _ error: Error?) -> Void
    ) {
        EThree.initialize(
            tokenCallback: tokenCallback,
            changedKeyDelegate: changedKeyDelegate,
            storageParams: storageParams,
            overrideVirgilPublicKey: overrideVirgilPublicKey,
            serviceUrls: serviceUrls
        )
        .start(completion: completion)
    }
}
