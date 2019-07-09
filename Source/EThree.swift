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
    @objc public let crypto: VirgilCrypto
    /// CardManager instance
    @objc public let cardManager: CardManager

    internal let localKeyManager: LocalKeyManager
    internal let cloudKeyManager: CloudKeyManager

    internal let queue = DispatchQueue(label: "EThreeQueue")

    internal init(identity: String,
                  accessTokenProvider: AccessTokenProvider,
                  cardManager: CardManager,
                  storageParams: KeychainStorageParams? = nil) throws {
        self.identity = identity
        self.crypto = cardManager.crypto
        self.cardManager = cardManager

        let storageParams = try storageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)

        self.localKeyManager = LocalKeyManager(identity: identity,
                                               crypto: self.crypto,
                                               keychainStorage: keychainStorage)

        self.cloudKeyManager = try CloudKeyManager(identity: identity,
                                                   accessTokenProvider: accessTokenProvider,
                                                   crypto: self.crypto,
                                                   keychainStorage: keychainStorage)

        super.init()
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

        try self.localKeyManager.store(data: data)
    }
}
