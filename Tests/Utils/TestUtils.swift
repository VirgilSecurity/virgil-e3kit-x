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

import VirgilE3Kit
import VirgilCrypto
import VirgilSDK
import VirgilSDKPythia

@objc(VTETestUtils) public class TestUtils: NSObject {
    private let crypto: VirgilCrypto
    private let consts: TestConfig

    @objc public init(crypto: VirgilCrypto, consts: TestConfig) {
        self.crypto = crypto
        self.consts = consts
    }

    @objc public func getTokenString(identity: String) -> String {
        let jwt = self.getToken(identity: identity, ttl: 1000)

        return jwt.stringRepresentation()
    }

    @objc public func getToken(identity: String, ttl: TimeInterval = 1000) -> AccessToken {
        let privateKeyData = Data(base64Encoded: self.consts.ApiPrivateKey)
        let keyPair = try! self.crypto.importPrivateKey(from: privateKeyData!)

        let generator = try! JwtGenerator(apiKey: keyPair.privateKey,
                                         apiPublicKeyIdentifier: self.consts.ApiKeyId,
                                         crypto: self.crypto,
                                         appId: self.consts.AppId,
                                         ttl: ttl)

        let jwt = try! generator.generateToken(identity: identity)

        return jwt
    }

    @objc public func publishCard(identity: String?) throws -> Card {
        let keyPair = try self.crypto.generateKeyPair()
        let exportedPublicKey = try self.crypto.exportPublicKey(keyPair.publicKey)

        let identity = identity ?? UUID().uuidString

        let content = RawCardContent(identity: identity, publicKey: exportedPublicKey, createdAt: Date())
        let snapshot = try content.snapshot()

        let rawCard = RawSignedModel(contentSnapshot: snapshot)

        let token = self.getToken(identity: identity)

        let serviceUrl = URL(string: self.consts.ServiceURL)!

        let provider = ConstAccessTokenProvider(accessToken: token)

        let cardClient = CardClient(accessTokenProvider: provider,
                                    serviceUrl: serviceUrl,
                                    connection: nil,
                                    retryConfig: ExpBackoffRetry.Config())

        let signer = ModelSigner(crypto: self.crypto)

        try! signer.selfSign(model: rawCard, privateKey: keyPair.privateKey)

        let responseRawCard = try cardClient.publishCard(model: rawCard)
        let card = try CardManager.parseCard(from: responseRawCard, crypto: crypto)

        return card
    }

    @objc public func isPublicKeysEqual(keys1: [VirgilPublicKey], keys2: [VirgilPublicKey]) -> Bool {
        for key1 in keys1 {
            let data1 = try! self.crypto.exportPublicKey(key1)
            var found = false

            for key2 in keys2 {
                let data2 = try! self.crypto.exportPublicKey(key2)
                if data1 == data2 {
                    found = true
                }
            }

            if (!found) {
                return false
            }
        }

        return true
    }

    @objc public func setUpSyncKeyStorage(password: String,
                                          keychainStorage: KeychainStorage,
                                          identity: String,
                                          completion: @escaping (SyncKeyStorage?, Error?) -> Void) {
        let provider = CachingJwtProvider(renewTokenCallback: { tokenContext, completion in
            let token = self.getTokenString(identity: identity)

            completion(token, nil);
        })

        let context = try! BrainKeyContext.makeContext(accessTokenProvider: provider)
        let brainKey = BrainKey(context: context)

        brainKey.generateKeyPair(password: password, brainKeyId: nil) { keyPair, error in
            let cloudKeyStorage = try! CloudKeyStorage(accessTokenProvider: provider,
                                                       crypto: self.crypto,
                                                       publicKeys: [keyPair!.publicKey],
                                                       privateKey: keyPair!.privateKey)
            let syncKeyStorage = SyncKeyStorage(identity: identity, keychainStorage: keychainStorage, cloudKeyStorage: cloudKeyStorage)

            syncKeyStorage.sync { completion(syncKeyStorage, $0) }
        }
    }
}
