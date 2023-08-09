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
import VirgilE3Kit

@objc(VTETestConfig) public class TestConfig: NSObject, Decodable {
    @objc public let ApiKeyId: String
    @objc public let ApiPrivateKey: String
    @objc public let AppId: String
    @objc public let ServicePublicKey: String?

    public let Group: GroupConfig
    public let TemporaryChannel: TemporaryConfig
    @objc public let ServiceUrls: ServiceUrls

    public struct GroupConfig: Decodable {
        public let GroupId: String
        public let Initiator: String
        public let Participants: [String]
        public let Identity: String
        public let PrivateKey: String
        public let OriginText: String
        public let EncryptedText: String
    }

    public struct TemporaryConfig: Decodable {
        public let Identity: String
        public let Initiator: String
        public let PrivateKey: String
        public let OriginText: String
        public let EncryptedText: String
    }

    @objc public class ServiceUrls: NSObject, Decodable {
        public let Card: String
        public let Keyknox: String
        public let Ratchet: String

        @objc public func get() -> EThreeParams.ServiceUrls {
            let cardServiceUrl = URL(string: self.Card)!
            let keyknoxServiceUrl = URL(string: self.Keyknox)!
            let ratchetServiceUrl = URL(string: self.Ratchet)!

            return EThreeParams.ServiceUrls(
                cardServiceUrl: cardServiceUrl,
                keyknoxServiceUrl: keyknoxServiceUrl,
                ratchetServiceUrl: ratchetServiceUrl
            )
        }
    }

    @objc public static func readFromBundle() -> TestConfig {
        let configFileUrl = Bundle.module.url(forResource: "TestConfig", withExtension: "plist")!
        let data = try! Data(contentsOf: configFileUrl)

        return try! PropertyListDecoder().decode(TestConfig.self, from: data)
    }
}
