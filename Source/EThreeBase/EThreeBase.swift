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

@objc(VTEEThreeBase) open class EThreeBase: NSObject {
    /// Typealias for the valid result of lookupPublicKeys call
    public typealias LookupResult = [String: VirgilPublicKey]
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    /// Identity of user. Obtained from tokenCollback
    @objc public let identity: String

    /// CardManager instance
    @objc public let cardManager: CardManager

    /// AccessTokenProvider
    @objc public let accessTokenProvider: AccessTokenProvider

    /// VirgilCrypto instance
    @objc public var crypto: VirgilCrypto {
        return self.cardManager.crypto
    }

    /// ChangedKeyDelegate to notify changing of User's keys
    @objc public var changedKeyDelegate: ChangedKeyDelegate? {
        return self.lookupManager.changedKeyDelegate
    }

    internal let localKeyStorage: LocalKeyStorage
    internal let cloudKeyManager: CloudKeyManager
    internal let lookupManager: LookupManager

    internal let queue = DispatchQueue(label: "EThreeBaseQueue")

    internal convenience init(identity: String,
                              accessTokenProvider: AccessTokenProvider,
                              changedKeyDelegate: ChangedKeyDelegate?,
                              storageParams: KeychainStorageParams?) throws {
        let crypto = try VirgilCrypto()

        guard let verifier = VirgilCardVerifier(crypto: crypto) else {
            throw EThreeError.verifierInitFailed
        }

        let params = CardManagerParams(crypto: crypto,
                                       accessTokenProvider: accessTokenProvider,
                                       cardVerifier: verifier)

        let client = CardClient(accessTokenProvider: accessTokenProvider,
                                serviceUrl: CardClient.defaultURL,
                                connection: EThree.getConnection(),
                                retryConfig: ExpBackoffRetry.Config())

        params.cardClient = client

        let cardManager = CardManager(params: params)

        let storageParams = try storageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)

        let localKeyStorage = LocalKeyStorage(identity: identity,
                                              crypto: crypto,
                                              keychainStorage: keychainStorage)

        let cloudKeyManager = try CloudKeyManager(identity: identity,
                                                  crypto: crypto,
                                                  accessTokenProvider: accessTokenProvider)

        let sqliteCardStorage = try SQLiteCardStorage(userIdentifier: identity, crypto: crypto, verifier: verifier)
        let lookupManager = LookupManager(cardStorage: sqliteCardStorage,
                                          cardManager: cardManager,
                                          changedKeyDelegate: changedKeyDelegate)

        try self.init(identity: identity,
                      cardManager: cardManager,
                      accessTokenProvider: accessTokenProvider,
                      localKeyStorage: localKeyStorage,
                      cloudKeyManager: cloudKeyManager,
                      lookupManager: lookupManager)
    }

    internal init(identity: String,
                  cardManager: CardManager,
                  accessTokenProvider: AccessTokenProvider,
                  localKeyStorage: LocalKeyStorage,
                  cloudKeyManager: CloudKeyManager,
                  lookupManager: LookupManager) throws {
        self.identity = identity
        self.cardManager = cardManager
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage
        self.cloudKeyManager = cloudKeyManager
        self.lookupManager = lookupManager

        super.init()

        if try localKeyStorage.exists() {
            try self.privateKeyChanged()
        }

        lookupManager.startUpdateCachedCards()
    }
}
