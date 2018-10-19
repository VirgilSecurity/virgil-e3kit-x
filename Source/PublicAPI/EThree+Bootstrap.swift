//
// Copyright (C) 2015-2018 Virgil Security Inc.
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
import VirgilCryptoApiImpl

extension EThree {
    @objc public static func initialize(appName: String? = nil, tokenCallback: @escaping RenewJwtCallback,
                                        completion: @escaping (EThree?, Error?) -> ()) {
        let renewTokenCallback: CachingJwtProvider.RenewJwtCallback = { _, completion in
            tokenCallback(completion)
        }

        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: renewTokenCallback)
        let tokenContext = TokenContext(service: "cards", operation: "publish")
        accessTokenProvider.getToken(with: tokenContext) { token, error in
            guard let identity = token?.identity(), error == nil else {
                completion(nil, EThreeError.gettingJwtFailed)
                return
            }
            do {
                let cardCrypto = VirgilCardCrypto()
                guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
                    completion(nil, EThreeError.verifierInitFailed)
                    return
                }
                let params = CardManagerParams(cardCrypto: cardCrypto,
                                               accessTokenProvider: accessTokenProvider,
                                               cardVerifier: verifier)
                let cardManager = CardManager(params: params)

                let ethree = try EThree(identity: identity, cardManager: cardManager, appName: appName)
                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    @objc public func bootstrap(password: String?, completion: @escaping (Error?) -> ()) {
        if let identityKeyPair = self.identityKeyPair {
            guard !identityKeyPair.isPublished else {
                completion(nil)
                return
            }
            let keyPair = VirgilKeyPair(privateKey: identityKeyPair.privateKey, publicKey: identityKeyPair.publicKey)

            self.publishCardThenUpdateLocal(keyPair: keyPair, completion: completion)
        } else {
            self.cardManager.searchCards(identity: self.identity) { cards, error in
                guard let cards = cards, error == nil else {
                    completion(error)
                    return
                }

                if cards.isEmpty {
                    self.signUp(password: password, completion: completion)
                } else {
                    self.signIn(password: password, completion: completion)
                }
            }
        }
    }
}
