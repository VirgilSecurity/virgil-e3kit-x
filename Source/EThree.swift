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
import VirgilSDKRatchet

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

    /// ChangedKeyDelegate to notify changing of User's keys
    @objc public var changedKeyDelegate: ChangedKeyDelegate? {
        return self.lookupManager.changedKeyDelegate
    }

    internal var keyWrapper: PrivateKeyWrapper {
        return self.localKeyStorage.keyWrapper
    }

    internal let enableRatchet: Bool
    internal let keyRotationInterval: TimeInterval

    internal let localKeyStorage: LocalKeyStorage
    internal let cloudKeyManager: CloudKeyManager
    internal let cloudRatchetStorage: CloudRatchetStorage

    internal let lookupManager: LookupManager

    internal var tempChannelManager: TempChannelManager?
    internal var groupManager: GroupManager?
    internal var secureChat: SecureChat?
    internal var timer: RepeatingTimer?

    internal let queue = DispatchQueue(label: "EThreeQueue")

    var ethree: EThree!

    // TODO: init EThree instance

    open func inAppUsage(password: String) throws {
        // Derive separate passwords for login and backup from single one
        let backupPassword = try EThree.derivePasswords(from: password).backupPassword

        self.initUser(backupPassword: backupPassword).start { _, error in
            guard error == nil else {
                // Error handling here
                if let error = error as? EThreeError, error == .wrongPassword {
                    // Wrong password case
                }
                else {
                    // Unknown error handling
                }
                return
            }
            // User is initialized!
        }
    }

    /// Initializes user on current device
    /// - Parameters:
    ///   - identity: identity of user
    ///   - password: user password
    open func initUser(backupPassword: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                // Clean up local Private Key if exists
                if try self.ethree.hasLocalPrivateKey() {
                   try self.ethree.cleanUp()
                }

                do {
                   let selfCard = try self.ethree.findUser(with: self.ethree.identity, forceReload: true)
                       .startSync()
                       .get()

                   // Self Card found, current user exists on Virgil Cloud
                   try self.restoreUser(backupPassword: backupPassword, selfCard: selfCard)
                }
                catch FindUsersError.cardWasNotFound {
                   // Self Card was not found, user is not registered on VirgilCloud
                   try self.createUser(backupPassword: backupPassword)
                }

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Registeres user on Virgil Cloud and backs up Private Key
    /// - Parameter password: backup password
    open func createUser(backupPassword: String) throws {
        do {
            try self.ethree.register().startSync().get()

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
        }
        catch CloudKeyStorageError.entryAlreadyExists {
            // For some reason Private Key backup already exists.
            // We should reset it and back up new one
            try self.ethree.resetPrivateKeyBackup().startSync().get()

            // This sleep prevents throttling on Virgil Pythia service
            sleep(2)

            try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()
        }
    }

    /// Restores user Private Key
    /// - Parameters:
    ///   - password: backup password
    ///   - selfCard: Self Card
    open func restoreUser(backupPassword: String, selfCard: Card) throws {
        do {
            try self.ethree.restorePrivateKey(password: backupPassword).startSync().get()

            // Checking if restored Private Key matches active Self Card
            if try !self.isLocalKeyValid(card: selfCard) {
               // Reset invalid backup
               try self.ethree.resetPrivateKeyBackup().startSync().get()

               // This sleep prevents throttling on Virgil Pythia service
               sleep(2)

               try self.rotateKey(backupPassword: backupPassword)
            }
        }
        catch CloudKeyStorageError.entryNotFound {
            // This sleep prevents throttling on Virgil Pythia service
            sleep(2)

            try self.rotateKey(backupPassword: backupPassword)
        }
    }

    /// Checks if restored Private Key matches active Self Card
    /// - Parameter card: Self Card to check
    open func isLocalKeyValid(card: Card) throws -> Bool {
        // Retrieve local Private Key
        let params = try KeychainStorageParams.makeKeychainStorageParams()
        let keychain = KeychainStorage(storageParams: params)
        let entry = try keychain.retrieveEntry(withName: self.ethree.identity)
        let keyPair = try self.crypto.importPrivateKey(from: entry.data)

        // Check that id of Self Card Public Key matches local Private Key one
        return card.publicKey.identifier == keyPair.identifier
    }

    /// Performs rotate operation
    /// - Parameter password: backup password
    open func rotateKey(backupPassword: String) throws {
        // Clean up local Private Key if exists
        if try self.ethree.hasLocalPrivateKey() {
           try self.ethree.cleanUp()
        }

        try self.ethree.rotatePrivateKey().startSync().get()
        try self.ethree.backupPrivateKey(password: backupPassword).startSync().get()

        // You need to notify other contacts that they need to find this user
        // with forceReload=true to update cached card of him
        try self.notifyContactsAboutRotate()
    }

    // Notifies other contacts that they need to find this user
    // with forceReload=true to update cached card of him
    open func notifyContactsAboutRotate() throws {
        // TODO: Fill me
    }






    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: User identity
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    /// - Throws: corresponding error
    /// - Important: identity should be the same as in JWT generated at server side
    @objc public convenience init(identity: String,
                                  tokenCallback: @escaping RenewJwtCallback,
                                  changedKeyDelegate: ChangedKeyDelegate? = nil,
                                  storageParams: KeychainStorageParams? = nil,
                                  enableRatchet: Bool = Defaults.enableRatchet,
                                  keyRotationInterval: TimeInterval = Defaults.keyRotationInterval) throws {

        let params = EThreeParams(identity: identity, tokenCallback: tokenCallback)

        params.changedKeyDelegate = changedKeyDelegate
        params.storageParams = storageParams
        params.enableRatchet = enableRatchet
        params.keyRotationInterval = keyRotationInterval

        try self.init(params: params)
    }

    /// Initializer
    /// - Parameter params: `EThreeParams` with parameters
    @objc public convenience init(params: EThreeParams) throws {
        let crypto = try VirgilCrypto()
        let accessTokenProvider = CachingJwtProvider { params.tokenCallback($1) }

        let keyStrorageParams = try LocalKeyStorageParams(identity: params.identity,
                                                          crypto: crypto,
                                                          storageParams: params.storageParams)
    #if os(iOS)
        keyStrorageParams.biometricProtection = params.biometricProtection
        keyStrorageParams.accessTime = params.keyCacheLifeTime
        keyStrorageParams.cleanOnEnterBackground = params.cleanKeyCacheOnEnterBackground
        keyStrorageParams.requestOnEnterForeground = params.requestKeyOnEnterForeground
        keyStrorageParams.enterForegroundErrorCallback = params.enterForegroundErrorCallback
    #endif

        let localKeyStorage = try LocalKeyStorage(params: keyStrorageParams)

        guard let verifier = VirgilCardVerifier(crypto: crypto) else {
            throw EThreeError.verifierInitFailed
        }

        let client = CardClient(accessTokenProvider: accessTokenProvider,
                                serviceUrl: CardClient.defaultURL,
                                connection: EThree.getConnection(),
                                retryConfig: ExpBackoffRetry.Config())

        let managerParams = CardManagerParams(crypto: crypto,
                                              accessTokenProvider: accessTokenProvider,
                                              cardVerifier: verifier)
        managerParams.cardClient = client

        let cardManager = CardManager(params: managerParams)

        let cloudKeyManager = try CloudKeyManager(identity: params.identity,
                                                  crypto: crypto,
                                                  accessTokenProvider: accessTokenProvider,
                                                  keyWrapper: localKeyStorage.keyWrapper)

        let sqliteCardStorage = try SQLiteCardStorage(userIdentifier: params.identity,
                                                      crypto: crypto,
                                                      verifier: verifier)
        let lookupManager = LookupManager(cardStorage: sqliteCardStorage,
                                          cardManager: cardManager,
                                          changedKeyDelegate: params.changedKeyDelegate)

        let cloudRatchetStorage = try CloudRatchetStorage(identity: params.identity,
                                                          crypto: crypto,
                                                          accessTokenProvider: accessTokenProvider,
                                                          keyWrapper: localKeyStorage.keyWrapper)

        try self.init(identity: params.identity,
                      cardManager: cardManager,
                      accessTokenProvider: accessTokenProvider,
                      localKeyStorage: localKeyStorage,
                      cloudKeyManager: cloudKeyManager,
                      lookupManager: lookupManager,
                      cloudRatchetStorage: cloudRatchetStorage,
                      enableRatchet: params.enableRatchet,
                      keyRotationInterval: params.keyRotationInterval)
    }

    internal init(identity: String,
                  cardManager: CardManager,
                  accessTokenProvider: AccessTokenProvider,
                  localKeyStorage: LocalKeyStorage,
                  cloudKeyManager: CloudKeyManager,
                  lookupManager: LookupManager,
                  cloudRatchetStorage: CloudRatchetStorage,
                  enableRatchet: Bool,
                  keyRotationInterval: TimeInterval) throws {
        self.identity = identity
        self.cardManager = cardManager
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage
        self.cloudKeyManager = cloudKeyManager
        self.lookupManager = lookupManager
        self.cloudRatchetStorage = cloudRatchetStorage
        self.enableRatchet = enableRatchet
        self.keyRotationInterval = keyRotationInterval

        super.init()

        if try localKeyStorage.exists() {
            try self.privateKeyChanged()
        }

        lookupManager.startUpdateCachedCards()
    }
}
