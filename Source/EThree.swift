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

/// Main class containing all features of E3Kit
@objc(VTEEThree) open class EThree: NSObject {
    /// Typealias for the valid result of lookupPublicKeys call
    public typealias LookupResult = [String: VirgilPublicKey]
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    /// Identity of user
    @objc public let identity: String

    /// CardManager instance
    @objc public let cardManager: CardManager

    /// AccessTokenProvider
    @objc public let accessTokenProvider: AccessTokenProvider

    /// VirgilCrypto instance
    @objc public var crypto: VirgilCrypto {
        return self.cardManager.crypto
    }

    /// [ChangedKeyDelegate](x-source-tag://ChangedKeyDelegate) to notify changing of User's keys
    @objc public var changedKeyDelegate: ChangedKeyDelegate? {
        return self.lookupManager.changedKeyDelegate
    }

    internal let localKeyStorage: LocalKeyStorage
    internal let cloudKeyManager: CloudKeyManager
    internal let lookupManager: LookupManager
    internal var groupManager: GroupManager?

    internal let queue = DispatchQueue(label: "EThreeQueue")

    /// Initializer
    ///
    /// - Parameter params: [EThreeParams](x-source-tag://EThreeParams) with needed parameters
    /// - Throws: corresponding error
    @objc public convenience init(params: EThreeParams) throws {
    #if os(iOS)
        try self.init(identity: params.identity,
                      tokenCallback: params.tokenCallback,
                      biometricProtection: params.biometricProtection,
                      biometricPromt: params.biometricPromt,
                      loadKeyStrategy: params.loadKeyStrategy,
                      keyCacheLifeTime: params.keyCacheLifeTime,
                      changedKeyDelegate: params.changedKeyDelegate,
                      storageParams: params.storageParams)
    #else
        try self.init(identity: params.identity,
                      tokenCallback: params.tokenCallback,
                      changedKeyDelegate: params.changedKeyDelegate,
                      storageParams: params.storageParams)
    #endif
    }

#if os(iOS)
    // swiftlint:disable line_length

    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: User identity
    ///   - tokenCallback: callback to get Virgil access token
    ///   - biometricProtection: will use biometric or passcode protection of key if true. Default value - false.
    ///   - biometricPromt: User promt for UI
    ///   - loadKeyStrategy: [LoadKeyStrategy](x-source-tag://LoadKeyStrategy)
    ///   - keyCacheLifeTime: defines how long cached key can be used before retrieved again
    ///   - changedKeyDelegate: [ChangedKeyDelegate](x-source-tag://ChangedKeyDelegate) to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    /// - Throws: corresponding error
    /// - Important: identity should be the same as in JWT generated at server side
    /// - Note: To use TouchId or FaceId, in addion `biometricProtection` to being enabled,
    ///  `NSFaceIDUsageDescription` key should be included in your app’s Info.plist file.
    /// See [here](https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id)
    /// more info
    /// - Note: `biometricalProtection` flag does not resave all entries with new options.
    /// Use `setBiometricalProtection` method for this purpose
    @objc public convenience init(identity: String,
                                  tokenCallback: @escaping RenewJwtCallback,
                                  biometricProtection: Bool,
                                  biometricPromt: String? = nil,
                                  loadKeyStrategy: LoadKeyStrategy = .instant,
                                  keyCacheLifeTime: TimeInterval = 1_800,
                                  changedKeyDelegate: ChangedKeyDelegate? = nil,
                                  storageParams: KeychainStorageParams? = nil) throws {
        let crypto = try VirgilCrypto()

        var localKeyStorageParams = LocalKeyStorageParams(identity: identity,
                                                          crypto: crypto,
                                                          keychainStorageParams: storageParams)

        localKeyStorageParams.biometricProtection = biometricProtection
        localKeyStorageParams.biometricPromt = biometricPromt

        let localKeyStorage: LocalKeyStorage
        switch loadKeyStrategy {
        case .instant:
            localKeyStorage = try InstantLoadKeyStorage(params: localKeyStorageParams)
        case .onFirstNeed:
            localKeyStorage = try OnFirstNeedKeyStorage(params: localKeyStorageParams)
        case .onlyOnUse:
            localKeyStorage = try OnlyOnUseKeyStorage(params: localKeyStorageParams)
        }

        try self.init(identity: identity,
                      crypto: crypto,
                      tokenCallback: tokenCallback,
                      localKeyStorage: localKeyStorage,
                      changedKeyDelegate: changedKeyDelegate)
    }

    // swiftlint:enable line_length
#endif

    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: User identity
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: [ChangedKeyDelegate](x-source-tag://ChangedKeyDelegate)
    ///                         to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    /// - Throws: corresponding error
    /// - Important: identity should be the same as in JWT generated at server side
    @objc public convenience init(identity: String,
                                  tokenCallback: @escaping RenewJwtCallback,
                                  changedKeyDelegate: ChangedKeyDelegate? = nil,
                                  storageParams: KeychainStorageParams? = nil) throws {
        let crypto = try VirgilCrypto()

        let params = LocalKeyStorageParams(identity: identity,
                                           crypto: crypto,
                                           keychainStorageParams: storageParams)

        let localKeyStorage = try InstantLoadKeyStorage(params: params)

        try self.init(identity: identity,
                      crypto: crypto,
                      tokenCallback: tokenCallback,
                      localKeyStorage: localKeyStorage,
                      changedKeyDelegate: changedKeyDelegate)
    }

    internal convenience init(identity: String,
                              crypto: VirgilCrypto,
                              tokenCallback: @escaping RenewJwtCallback,
                              localKeyStorage: LocalKeyStorage,
                              changedKeyDelegate: ChangedKeyDelegate?) throws {
        let crypto = crypto
        let accessTokenProvider = CachingJwtProvider { tokenCallback($1) }

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

    internal func getGroupManager() throws -> GroupManager {
        guard let manager = self.groupManager else {
            throw EThreeError.missingPrivateKey
        }

        return manager
    }
}
