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

// MARK: - Extension with authorization operations
extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - completion: completion handler
    ///   - ethree: initialized EThree instance
    ///   - error: corresponding error
    public static func initialize(tokenCallback: @escaping RenewJwtCallback,
                                        storageParams: KeychainStorageParams? = nil) -> GenericOperation<EThree> {
        return CallbackOperation { _, completion in
            do {
                let accessTokenProvider = CachingJwtProvider { tokenCallback($1) }

                let tokenContext = TokenContext(service: "cards", operation: "")

                let getTokenOperation = OperationUtils.makeGetTokenOperation(tokenContext: tokenContext, accessTokenProvider: accessTokenProvider)

                let token = try getTokenOperation.startSync().getResult()

                let crypto = try VirgilCrypto()
                let cardCrypto = VirgilCardCrypto(virgilCrypto: crypto)

                guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
                    throw EThreeError.verifierInitFailed
                }

                let params = CardManagerParams(cardCrypto: cardCrypto,
                                               accessTokenProvider: accessTokenProvider,
                                               cardVerifier: verifier)

                let version = VersionUtils.getVersion(bundleIdentitifer: "com.virgilsecurity.VirgilE3Kit")
                let connection = HttpConnection(adapters: [VirgilAgentAdapter(product: "e3kit", version: version)])
                let client = CardClient(connection: connection)
                params.cardClient = client

                let cardManager = CardManager(params: params)

                let ethree = try EThree(identity: token.identity(),
                                        crypto: crypto,
                                        cardManager: cardManager,
                                        storageParams: storageParams)

                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Generates new Private Key, publishes Card on Virgil Cards Service and saves Private Key in local storage
    ///
    /// - Parameters:
    ///   - completion: completion handler
    ///   - error: corresponding error
    public func register() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard try !self.localKeyManager.exists() else {
                        throw EThreeError.privateKeyExists
                    }

                    let cards = try self.cardManager.searchCards(identity: self.identity).startSync().getResult()

                    guard cards.isEmpty else {
                        throw EThreeError.userIsAlreadyRegistered
                    }

                    try self.publishCardThenSaveLocal()

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Generates new Private Key, publishes new Card to replace the current one on Virgil Cards Service
    /// and saves new Private Key in local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    public func rotatePrivateKey() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard try !self.localKeyManager.exists() else {
                        throw EThreeError.privateKeyExists
                    }

                    let cards = try self.cardManager.searchCards(identity: self.identity).startSync().getResult()

                    guard let card = cards.first else {
                        throw EThreeError.userIsNotRegistered
                    }

                    try self.publishCardThenSaveLocal(previousCardId: card.identifier)

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Revokes Card from Virgil Cards Service, deletes Private Key from local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    public func unregister() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let cards = try self.cardManager.searchCards(identity: self.identity).startSync().getResult()

                    guard let card = cards.first else {
                        throw EThreeError.userIsNotRegistered
                    }

                    try self.cardManager.revokeCard(withId: card.identifier).startSync().getResult()

                    try self.localKeyManager.delete()

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Deletes Private Key from local storage
    ///
    /// - Throws: KeychainStorageError
    @objc public func cleanUp() throws {
        try self.localKeyManager.delete()
    }
}
