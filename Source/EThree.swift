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
import VirgilCrypto
import VirgilSDK
import VirgilSDKRatchet

/// Main class containing all features of E3Kit
@objc(VTEEThree) open class EThree: NSObject {
    /// Typealias for the valid result of lookupPublicKeys call
    public typealias LookupResult = [String: VirgilPublicKey]
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void
    /// Typealias for callback used below
    public typealias PublishCardCallback = (RawSignedModel) throws -> Card

    /// Identity of user
    @objc public let identity: String

    /// CardManager instance
    @objc public let cardManager: CardManager

    /// AccessTokenProvider
    @objc public let accessTokenProvider: AccessTokenProvider

    /// LocalKeyStorage
    @objc public let localKeyStorage: LocalKeyStorage

    /// Offline init
    @objc public let offlineInit: Bool

    /// VirgilCrypto instance
    @objc public var crypto: VirgilCrypto {
        return self.cardManager.crypto
    }

    /// ChangedKeyDelegate to notify changing of User's keys
    @objc public var changedKeyDelegate: ChangedKeyDelegate? {
        return self.lookupManager.changedKeyDelegate
    }

    internal let keyPairType: KeyPairType
    internal let enableRatchet: Bool
    internal let enableRatchetPqc: Bool
    internal let keyRotationInterval: TimeInterval
    internal let appGroup: String?
    internal let appName: String?

    internal let cloudKeyManager: CloudKeyManager
    internal let cloudRatchetStorage: CloudRatchetStorage

    internal let lookupManager: LookupManager

    internal var tempChannelManager: TempChannelManager?
    internal var groupManager: GroupManager?
    internal var secureChat: SecureChat?
    internal var timer: RepeatingTimer?

    internal let serviceUrls: EThreeParams.ServiceUrls

    internal let queue = DispatchQueue(label: "EThreeQueue")

    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: User identity
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - keyPairType: key pair type
    ///   - enableRatchet: enable ratchet
    ///   - keyRotationInverval: key rotation interval for ratchet
    /// - Throws: corresponding error
    /// - Important: identity should be the same as in JWT generated at server side
    @objc public convenience init(
        identity: String,
        tokenCallback: @escaping RenewJwtCallback,
        changedKeyDelegate: ChangedKeyDelegate? = nil,
        storageParams: KeychainStorageParams? = nil,
        keyPairType: KeyPairType = Defaults.keyPairType,
        enableRatchet: Bool = Defaults.enableRatchet,
        enableRatchetPqc: Bool = Defaults.enableRatchetPqc,
        keyRotationInterval: TimeInterval = Defaults.keyRotationInterval
    ) throws {
        let params = EThreeParams(identity: identity, tokenCallback: tokenCallback)
        params.changedKeyDelegate = changedKeyDelegate
        params.storageParams = storageParams
        params.keyPairType = keyPairType
        params.enableRatchet = enableRatchet
        params.enableRatchetPqc = enableRatchetPqc
        params.keyRotationInterval = keyRotationInterval

        try self.init(params: params)
    }

    /// Init
    /// - Parameter params: params
    @objc public convenience init(params: EThreeParams) throws {
        let crypto = try VirgilCrypto()

        guard let verifier = VirgilCardVerifier(crypto: crypto) else {
            throw EThreeError.verifierInitFailed
        }

        if let virgilPublicKeyStr = params.overrideVirgilPublicKey {
            guard let virgilPublicKeyData = Data(base64Encoded: virgilPublicKeyStr) else {
                throw EThreeError.verifierInitFailed
            }

            let virgilPublicKey: VirgilPublicKey

            do {
                virgilPublicKey = try crypto.importPublicKey(from: virgilPublicKeyData)
            } catch {
                throw EThreeError.verifierInitFailed
            }

            verifier.verifyVirgilSignature = false

            let credentials = VerifierCredentials(
                signer: VirgilCardVerifier.virgilSignerIdentifier,
                publicKey: virgilPublicKey)
            let whitelist = try Whitelist(verifiersCredentials: [credentials])

            verifier.whitelists = [whitelist]
        }

        let accessTokenProvider = CachingJwtProvider(initialJwt: params.initialJwt) {
            params.tokenCallback($1)
        }

        let cardManagerParams = CardManagerParams(
            crypto: crypto,
            accessTokenProvider: accessTokenProvider,
            cardVerifier: verifier)

        let cardClient = CardClient(
            accessTokenProvider: accessTokenProvider,
            serviceUrl: params.serviceUrls.cardServiceUrl,
            connection: EThree.getConnection(),
            retryConfig: ExpBackoffRetry.Config())

        cardManagerParams.cardClient = cardClient

        let cardManager = CardManager(params: cardManagerParams)

        let storageParams =
            try params.storageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)

        let localKeyStorage = LocalKeyStorage(
            identity: params.identity,
            crypto: crypto,
            keychainStorage: keychainStorage)

        let cloudKeyManager = try CloudKeyManager(
            identity: params.identity,
            crypto: crypto,
            accessTokenProvider: accessTokenProvider,
            keyknoxServiceUrl: params.serviceUrls.keyknoxServiceUrl,
            pythiaServiceUrl: params.serviceUrls.pythiaServiceUrl)

        let sqliteCardStorage = try SQLiteCardStorage(
            appGroup: params.appGroup,
            userIdentifier: params.identity,
            crypto: crypto,
            verifier: verifier)

        let lookupManager = LookupManager(
            cardStorage: sqliteCardStorage,
            cardManager: cardManager,
            changedKeyDelegate: params.changedKeyDelegate)

        let cloudRatchetStorage = try CloudRatchetStorage(
            accessTokenProvider: accessTokenProvider,
            localKeyStorage: localKeyStorage,
            keyknoxServiceUrl: params.serviceUrls.keyknoxServiceUrl)

        try self.init(
            identity: params.identity,
            cardManager: cardManager,
            accessTokenProvider: accessTokenProvider,
            localKeyStorage: localKeyStorage,
            cloudKeyManager: cloudKeyManager,
            lookupManager: lookupManager,
            cloudRatchetStorage: cloudRatchetStorage,
            serviceUrls: params.serviceUrls,
            keyPairType: params.keyPairType,
            enableRatchet: params.enableRatchet,
            enableRatchetPqc: params.enableRatchetPqc,
            appGroup: params.appGroup,
            appName: params.storageParams?.appName,
            keyRotationInterval: params.keyRotationInterval,
            offlineInit: params.offlineInit)
    }

    internal init(
        identity: String,
        cardManager: CardManager,
        accessTokenProvider: AccessTokenProvider,
        localKeyStorage: LocalKeyStorage,
        cloudKeyManager: CloudKeyManager,
        lookupManager: LookupManager,
        cloudRatchetStorage: CloudRatchetStorage,
        serviceUrls: EThreeParams.ServiceUrls,
        keyPairType: KeyPairType,
        enableRatchet: Bool,
        enableRatchetPqc: Bool,
        appGroup: String?,
        appName: String?,
        keyRotationInterval: TimeInterval,
        offlineInit: Bool
    ) throws {
        self.identity = identity
        self.cardManager = cardManager
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage
        self.cloudKeyManager = cloudKeyManager
        self.lookupManager = lookupManager
        self.cloudRatchetStorage = cloudRatchetStorage
        self.serviceUrls = serviceUrls
        self.keyPairType = keyPairType
        self.enableRatchet = enableRatchet
        self.enableRatchetPqc = enableRatchetPqc
        self.appGroup = appGroup
        self.appName = appName
        self.keyRotationInterval = keyRotationInterval
        self.offlineInit = offlineInit

        super.init()

        if try localKeyStorage.exists() {
            try self.privateKeyChanged()
        }

        if !offlineInit {
            lookupManager.startUpdateCachedCards()
        }
    }
}
