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
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    /// Identity of user. Obtained from tokenCollback
    @objc public let identity: String
    /// VirgilCrypto instance
    @objc public var crypto: VirgilCrypto {
        return cardManager.crypto
    }
    /// CardManager instance
    @objc public let cardManager: CardManager

    @objc public let accessTokenProvider: AccessTokenProvider

    internal let localKeyStorage: LocalKeyStorage
    internal let cloudKeyManager: CloudKeyManager

    internal let queue = DispatchQueue(label: "EThreeQueue")

    private var lookupManager: LookupManager?
    private var groupManager: GroupManager?

    internal convenience init(identity: String,
                              accessTokenProvider: AccessTokenProvider,
                              storageParams: KeychainStorageParams? = nil) throws {
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

        let cloudKeyManager = try CloudKeyManager(identity: identity, crypto: crypto, accessTokenProvider: accessTokenProvider)

        var groupManager: GroupManager?
        var lookupManager: LookupManager?
        if let selfKeyPair = try? localKeyStorage.retrieveKeyPair() {

            let ticketStorage = try FileGroupStorage(identity: identity, crypto: crypto, identityKeyPair: selfKeyPair)
            let cloudTicketStorage = try CloudTicketStorage(accessTokenProvider: accessTokenProvider, localKeyStorage: localKeyStorage)
            groupManager = GroupManager(identity: identity, localStorage: ticketStorage, cloudStorage: cloudTicketStorage)

            let cardStorage = try FileCardStorage(identity: identity, crypto: crypto, identityKeyPair: selfKeyPair)
            lookupManager = LookupManager(cardStorage: cardStorage, cardManager: cardManager)
        }

        self.init(identity: identity,
                  cardManager: cardManager,
                  accessTokenProvider: accessTokenProvider,
                  localKeyStorage: localKeyStorage,
                  cloudKeyManager: cloudKeyManager,
                  lookupManager: lookupManager,
                  groupManager: groupManager)
    }

    internal init(identity: String,
                  cardManager: CardManager,
                  accessTokenProvider: AccessTokenProvider,
                  localKeyStorage: LocalKeyStorage,
                  cloudKeyManager: CloudKeyManager,
                  lookupManager: LookupManager?,
                  groupManager: GroupManager?) {
        self.identity = identity
        self.cardManager = cardManager
        self.accessTokenProvider = accessTokenProvider
        self.localKeyStorage = localKeyStorage
        self.cloudKeyManager = cloudKeyManager
        self.lookupManager = lookupManager
        self.groupManager = groupManager

        super.init()
    }

    func privateKeyChanged() throws {
        let selfKeyPair = try localKeyStorage.retrieveKeyPair()

        let localStorage = try FileGroupStorage(identity: self.identity, crypto: crypto, identityKeyPair: selfKeyPair)
        let cloudStorage = try CloudTicketStorage(accessTokenProvider: accessTokenProvider, localKeyStorage: localKeyStorage)
        self.groupManager = GroupManager(identity: self.identity, localStorage: localStorage, cloudStorage: cloudStorage)

        let cardStorage = try FileCardStorage(identity: self.identity, crypto: crypto, identityKeyPair: selfKeyPair)
        self.lookupManager = LookupManager(cardStorage: cardStorage, cardManager: cardManager)
    }

    func privateKeyDeleted() throws {
        try self.groupManager?.localStorage.reset()

        self.groupManager = nil
        self.lookupManager = nil
    }

    internal func getGroupManager() throws -> GroupManager {
        guard let storage = self.groupManager else {
            throw NSError()
        }

        return storage
    }

    internal func getLookupManager() throws -> LookupManager {
        guard let manager = self.lookupManager else {
            throw NSError()
        }

        return manager
    }

    internal func computeSessionId(from identifier: Data) -> Data {
        return self.crypto.computeHash(for: identifier).subdata(in: 0..<32)
    }

    internal static func getConnection() -> HttpConnection {
        let version = VersionUtils.getVersion(bundleIdentitifer: "com.virgilsecurity.VirgilE3Kit")
        let adapters = [VirgilAgentAdapter(product: "e3kit", version: version)]

        return HttpConnection(adapters: adapters)
    }

    internal func publishCardThenSaveLocal(previousCardId: String? = nil) throws {
        let keyPair = try self.crypto.generateKeyPair()

        _ = try self.cardManager.publishCard(privateKey: keyPair.privateKey,
                                             publicKey: keyPair.publicKey,
                                             identity: self.identity,
                                             previousCardId: previousCardId).startSync().get()

        let data = try self.crypto.exportPrivateKey(keyPair.privateKey)

        try self.localKeyStorage.store(data: data)

        try self.privateKeyChanged()
    }
}
