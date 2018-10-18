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

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl

public enum EThreeError: Int, Error {
    case gettingJwtFailed = 1
    case verifierInitFailed = 2
    case keyIsNotVirgil = 3
    case strToDataFailed = 4
    case strFromDataFailed = 5
    case missingKeys = 6
}

open class EThree {
    public typealias JwtStringCallback = (String?, Error?) -> Void
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    public let identity: String
    public let crypto: VirgilCrypto
    public let keychainStorage: KeychainStorage
    public let privateKeyExporter: VirgilPrivateKeyExporter
    public let cardManager: CardManager

    internal struct IdentityKeyPair {
        internal let privateKey: VirgilPrivateKey
        internal let publicKey: VirgilPublicKey
        internal let isPublished: Bool
    }

    internal enum Keys: String {
        case isPublished
    }

    internal var identityKeyPair: IdentityKeyPair? {
        guard let keyEntry = try? self.keychainStorage.retrieveEntry(withName: self.identity),
            let key = try? self.privateKeyExporter.importPrivateKey(from: keyEntry.data),
            let meta = keyEntry.meta,
            let isPublishedString = meta[Keys.isPublished.rawValue],
            let identityKey = key as? VirgilPrivateKey,
            let publicKey = try? self.crypto.extractPublicKey(from: identityKey) else {
                return nil
        }
        let isPublished = NSString(string: isPublishedString).boolValue

        return IdentityKeyPair(privateKey: identityKey, publicKey: publicKey, isPublished: isPublished)
    }

    public static func initialize(tokenCallback: @escaping RenewJwtCallback,
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

                let ethree = try EThree(identity: identity, cardManager: cardManager)
                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    private init(identity: String, cardManager: CardManager) throws {
        self.identity = identity
        self.crypto = VirgilCrypto()
        let keychainStorageParams = try KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: keychainStorageParams)
        self.privateKeyExporter = VirgilPrivateKeyExporter()
        self.cardManager = cardManager
    }
}
