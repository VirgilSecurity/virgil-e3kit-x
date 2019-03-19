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

import Foundation
import VirgilSDK
import VirgilCrypto

/// Declares error types and codes for EThree
///
/// - verifierInitFailed: Initialization of VirgilCardVerifier failed
/// - keyIsNotVirgil: Casting Key to Virgil Key failed
/// - strToDataFailed: String to Data failed
/// - strFromDataFailed: Data to String failed
/// - missingPrivateKey: missing Private Keys. You should call `register()` of `retrievePrivateKey()`
/// - missingPublicKey: missing Public Key
/// - missingIdentities: got empty array of identities to lookup for
/// - userIsAlreadyRegistered: user is already registered
/// - userIsNotRegistered: user is not registered
/// - privateKeyExists: private key already exists in local key storage
@objc(VTEEThreeError) public enum EThreeError: Int, Error {
    case verifierInitFailed = 1
    case keyIsNotVirgil = 2
    case strToDataFailed = 3
    case strFromDataFailed = 4
    case missingPrivateKey = 5
    case missingPublicKey = 6
    case missingIdentities = 7
    case userIsAlreadyRegistered = 8
    case userIsNotRegistered = 9
    case privateKeyExists = 10
}

@objc(VTEEThree) open class EThree: NSObject {
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    /// Identity of user. Obtained from tokenCollback
    @objc public let identity: String
    /// VirgilCrypto instance
    @objc public let crypto: VirgilCrypto
    /// CardManager instance
    @objc public let cardManager: CardManager

    internal let localKeyManager: LocalKeyManager
    internal let cloudKeyManager: CloudKeyManager

    internal let semaphore = DispatchSemaphore(value: 1)

    internal init(identity: String, crypto: VirgilCrypto, cardManager: CardManager, storageParams: KeychainStorageParams? = nil) throws {
        self.identity = identity
        self.crypto = crypto
        self.cardManager = cardManager

        let storageParams = try storageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)

        self.localKeyManager = LocalKeyManager(identity: identity,
                                               crypto: self.crypto,
                                               keychainStorage: keychainStorage)

        self.cloudKeyManager = try CloudKeyManager(identity: identity,
                                                   accessTokenProvider: cardManager.accessTokenProvider,
                                                   crypto: self.crypto,
                                                   keychainStorage: keychainStorage)

        super.init()
    }

    /// Checks existance of private key in keychain storage
    ///
    /// - Returns: true if private key exists in keychain storage
    /// - Throws: KeychainStorageError
    public func hasLocalPrivateKey() throws -> Bool {
        return try self.localKeyManager.exists()
    }

    internal func publishCardThenSaveLocal(previousCardId: String? = nil, completion: @escaping (Error?) -> Void) {
        do {
            let keyPair = try self.crypto.generateKeyPair()

            self.cardManager.publishCard(privateKey: keyPair.privateKey,
                                         publicKey: keyPair.publicKey,
                                         identity: self.identity,
                                         previousCardId: previousCardId) { _, error in
                guard error == nil else {
                    completion(error)
                    return
                }

                do {
                    let data = try self.crypto.exportPrivateKey(keyPair.privateKey)
                    
                    try self.localKeyManager.store(data: data)

                    completion(nil)
                } catch {
                    completion(error)
                }
            }
        } catch {
            completion(error)
        }
    }
}
