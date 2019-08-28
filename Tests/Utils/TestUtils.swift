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
    @objc public let crypto: VirgilCrypto
    @objc public let config: TestConfig

    @objc public override init() {
        self.crypto = try! VirgilCrypto()
        self.config = TestConfig.readFromBundle()

        super.init()
    }

    @objc public func getTokenString(identity: String) -> String {
        let jwt = self.getToken(identity: identity, ttl: 1000)

        return jwt.stringRepresentation()
    }

    @objc public func getToken(identity: String, ttl: TimeInterval = 1000) -> AccessToken {
        let privateKeyData = Data(base64Encoded: self.config.ApiPrivateKey)
        let keyPair = try! self.crypto.importPrivateKey(from: privateKeyData!)

        let generator = try! JwtGenerator(apiKey: keyPair.privateKey,
                                          apiPublicKeyIdentifier: self.config.ApiKeyId,
                                          crypto: self.crypto,
                                          appId: self.config.AppId,
                                          ttl: ttl)

        let jwt = try! generator.generateToken(identity: identity)

        return jwt
    }

    @objc public func publishCard(identity: String? = nil, previousCardId: String? = nil) -> Card {
        let keyPair = try! self.crypto.generateKeyPair()
        let exportedPublicKey = try! self.crypto.exportPublicKey(keyPair.publicKey)

        let identity = identity ?? UUID().uuidString

        let content = RawCardContent(identity: identity,
                                     publicKey: exportedPublicKey,
                                     previousCardId: previousCardId,
                                     createdAt: Date())
        let snapshot = try! content.snapshot()

        let rawCard = RawSignedModel(contentSnapshot: snapshot)

        let token = self.getToken(identity: identity)

        let serviceUrl = URL(string: self.config.ServiceURL)!

        let provider = ConstAccessTokenProvider(accessToken: token)

        let cardClient = CardClient(accessTokenProvider: provider,
                                    serviceUrl: serviceUrl,
                                    connection: nil,
                                    retryConfig: ExpBackoffRetry.Config())

        let signer = ModelSigner(crypto: self.crypto)

        try! signer.selfSign(model: rawCard, privateKey: keyPair.privateKey)

        let responseRawCard = try! cardClient.publishCard(model: rawCard)
        let card = try! CardManager.parseCard(from: responseRawCard, crypto: crypto)

        return card
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

extension TestUtils {
    @objc public func isCardsEqual(card1: Card?, card2: Card?) -> Bool {
        if card1 == card2 {
            return true
        }

        guard let card1 = card1, let card2 = card2 else {
            return false
        }

        let selfSignature1 = card1.signatures.first { $0.signer == "self" }
        let selfSignature2 = card2.signatures.first { $0.signer == "self" }

        return card1.identifier == card2.identifier &&
            card1.identity == card2.identity &&
            card1.version == card2.version &&
            card1.isOutdated == card2.isOutdated &&
            card1.createdAt == card2.createdAt &&
            card1.previousCardId == card2.previousCardId &&
            self.isCardsEqual(card1: card1.previousCard, card2: card2.previousCard) &&
            self.isCardSignaturesEqual(signature1: selfSignature1, signature2: selfSignature2)
    }

    @objc public func isCardSignaturesEqual(signature1: CardSignature?, signature2: CardSignature?) -> Bool {
        if signature1 == signature2 {
            return true
        }

        guard let signature1 = signature1, let signature2 = signature2 else {
            return false
        }

        return signature1.signer == signature2.signer &&
            signature1.signature == signature2.signature &&
            signature1.snapshot == signature2.snapshot &&
            signature1.extraFields == signature2.extraFields
    }

    @objc public func isCardsEqual(cards1: [Card], cards2: [Card]) -> Bool {
        for card1 in cards1 {

            var found = false
            for card2 in cards2 {
                if self.isCardsEqual(card1: card1, card2: card2) {
                    found = true
                }
            }

            if (!found) {
                return false
            }
        }

        return true
    }
}
