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

@objc(VTEEThreeError) public enum EThreeError: Int, Error {
    case gettingJwtFailed = 1
    case verifierInitFailed = 2
    case keyIsNotVirgil = 3
    case strToDataFailed = 4
    case strFromDataFailed = 5
    case missingKeys = 6
    case passwordRequired = 7
    case notBootstrapped = 8
    case missingAppName = 9
    case missingIdentities = 10
}

@objc(VTEEThree) open class EThree: NSObject {
    public typealias JwtStringCallback = (String?, Error?) -> Void
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    @objc public let identity: String
    @objc public let crypto: VirgilCrypto
    @objc public let privateKeyExporter: VirgilPrivateKeyExporter
    @objc public let cardManager: CardManager
    internal let localKeyManager: LocalKeyManager
    internal let cloudKeyManager: CloudKeyManager

    internal init(identity: String, cardManager: CardManager) throws {
        self.identity = identity
        self.crypto = VirgilCrypto()
        self.privateKeyExporter = VirgilPrivateKeyExporter()
        self.cardManager = cardManager
        
        let storageParams = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)
        self.localKeyManager = LocalKeyManager(identity: identity, privateKeyExporter: self.privateKeyExporter,
                                               crypto: self.crypto, keychainStorage: keychainStorage)
        self.cloudKeyManager = CloudKeyManager(identity: identity, accessTokenProvider: cardManager.accessTokenProvider,
                                               privateKeyExporter: self.privateKeyExporter, keychainStorage: keychainStorage)
    }
}

extension EThree {
    internal func publishCardThenUpdateLocal(keyPair: VirgilKeyPair, completion: @escaping (Error?) -> ()) {
        self.cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey,
                                     identity: self.identity) { cards, error in
            guard error == nil else {
                completion(error)
                return
            }

            do {
                try self.localKeyManager.update(isPublished: true)
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    internal func buildKeyPair(from data: Data) throws -> VirgilKeyPair {
        let key = try self.privateKeyExporter.importPrivateKey(from: data)
        guard let virgilPrivateKey = key as? VirgilPrivateKey else {
            throw EThreeError.keyIsNotVirgil
        }
        let publicKey = try self.crypto.extractPublicKey(from: virgilPrivateKey)

        return VirgilKeyPair(privateKey: virgilPrivateKey, publicKey: publicKey)
    }
}
