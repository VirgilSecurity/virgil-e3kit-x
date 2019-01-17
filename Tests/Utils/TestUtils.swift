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
import VirgilE3Kit
import VirgilCryptoApiImpl
import VirgilSDK
import VirgilSDKKeyknox
import VirgilSDKPythia

@objc(VTETestUtils) public class TestUtils: NSObject {
    private let crypto: VirgilCrypto
    private let consts: VTETestsConst

    @objc init(crypto: VirgilCrypto, consts: VTETestsConst) {
        self.crypto = crypto
        self.consts = consts
    }

    @objc internal func getTokenString(identity: String) -> String {
        let jwt = self.getToken(identity: identity, ttl: 1000)

        return jwt.stringRepresentation()
    }

    @objc internal func getToken(identity: String, ttl: TimeInterval) -> AccessToken {
        let exporter = VirgilPrivateKeyExporter(virgilCrypto: self.crypto, password: nil)
        let privateKeyData = Data(base64Encoded: self.consts.apiPrivateKeyBase64)
        let privateKey = try! exporter.importPrivateKey(from: privateKeyData!)

        let tokenSigner = VirgilAccessTokenSigner(virgilCrypto: self.crypto)
        let generator = JwtGenerator(apiKey: privateKey,
                                     apiPublicKeyIdentifier: self.consts.apiPublicKeyId,
                                     accessTokenSigner: tokenSigner,
                                     appId: self.consts.applicationId,
                                     ttl: ttl)

        let jwt = try! generator.generateToken(identity: identity)

        return jwt
    }

    @objc internal func publishCard(identity: String?) throws -> Card {
        let keyPair = try self.crypto.generateKeyPair()
        let exportedPublicKey = self.crypto.exportPublicKey(keyPair.publicKey)

        let identity = identity ?? UUID().uuidString

        let content = RawCardContent(identity: identity, publicKey: exportedPublicKey, createdAt: Date())
        let snapshot = try content.snapshot()

        let rawCard = RawSignedModel(contentSnapshot: snapshot)

        let token = self.getTokenString(identity: identity)

        let cardCrypto = VirgilCardCrypto(virgilCrypto: self.crypto)
        let cardClient = self.consts.serviceURL == nil ? CardClient() : CardClient(serviceUrl: self.consts.serviceURL!)

        let signer = ModelSigner(cardCrypto: cardCrypto)

        try! signer.selfSign(model: rawCard, privateKey: keyPair.privateKey)

        let responseRawCard = try cardClient.publishCard(model: rawCard, token: token)
        let card = try CardManager.parseCard(from: responseRawCard, cardCrypto: cardCrypto)

        return card
    }

    @objc internal func isPublicKeysEqual(keys1: [VirgilPublicKey], keys2: [VirgilPublicKey]) -> Bool {
        for key1 in keys1 {
            let data1 = self.crypto .exportPublicKey(key1)
            var found = false

            for key2 in keys2 {
                let data2 = self.crypto.exportPublicKey(key2)
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

    @objc internal func setUpSyncKeyStorage(password: String,
                                            keychainStorage: KeychainStorage,
                                            identity: String,
                                            completion: @escaping (SyncKeyStorage?, Error?) -> Void) {
        let provider = CachingJwtProvider(renewTokenCallback: { tokenContext, completion in
            let token = self.getTokenString(identity: identity)

            completion(token, nil);
        })

        let context = BrainKeyContext.makeContext(accessTokenProvider: provider)
        let brainKey = BrainKey(context: context)

        brainKey.generateKeyPair(password: password, brainKeyId: nil) { keyPair, error in
            let cloudKeyStorage = try! CloudKeyStorage(accessTokenProvider: provider,
                                                       publicKeys: [keyPair!.publicKey],
                                                       privateKey: keyPair!.privateKey)
            let syncKeyStorage = SyncKeyStorage(identity: identity, keychainStorage: keychainStorage, cloudKeyStorage: cloudKeyStorage)

            syncKeyStorage.sync { completion(syncKeyStorage, $0) }
        }
    }
}
