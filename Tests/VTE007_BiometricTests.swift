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

import XCTest
import VirgilE3Kit
import VirgilCrypto

class VTE007_BiometricTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice(identity: String? = nil, biometricalProtection: Bool, biometricalPromt: String? = nil) -> EThree {
        let identity = identity ?? UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        return try! EThree(identity: identity,
                           tokenCallback: tokenCallback,
                           biometricProtection: biometricalProtection,
                           biometricPromt: biometricalPromt)
    }

    func test01__init() {
        let ethree = self.setUpDevice(biometricalProtection: true)

        try! ethree.register().startSync().get()

        let ethree1 = self.setUpDevice(identity: ethree.identity,
                                       biometricalProtection: true,
                                       biometricalPromt: "Custom promt")

        XCTAssert(try ethree1.hasLocalPrivateKey())
    }

    func test02__enable__biometric() {
        let ethree = self.setUpDevice(biometricalProtection: false)

        try! ethree.register().startSync().get()

        try! ethree.setBiometricProtection(to: true)

        let ethree1 = self.setUpDevice(identity: ethree.identity, biometricalProtection: false)

        XCTAssert(try ethree1.hasLocalPrivateKey())
    }

    func test03__disable__biometric() {
        let ethree = self.setUpDevice(biometricalProtection: true)

        try! ethree.register().startSync().get()

        try! ethree.setBiometricProtection(to: false)

        let ethree1 = self.setUpDevice(identity: ethree.identity, biometricalProtection: true)

        XCTAssert(try ethree1.hasLocalPrivateKey())
    }

    func test04__cleanUp() {
        let ethree = self.setUpDevice(biometricalProtection: true)

        try! ethree.register().startSync().get()

        try! ethree.cleanUp()

        XCTAssert(try !ethree.hasLocalPrivateKey())
    }

    func test05__config() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let bundle = Bundle(for: TestConfig.self)
        let configFileUrl = bundle.url(forResource: "EThreeParams", withExtension: "plist")!
        let params = try! EThreeParams(identity: identity, tokenCallback: tokenCallback, configUrl: configFileUrl)

        XCTAssert(params.biometricProtection)
        XCTAssert(params.biometricPromt == "New promt")
        XCTAssert(params.loadKeyStrategy == .instant)
        XCTAssert(params.keyCacheLifeTime == 30)
    }

    func test06__key_cache_lifetime() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let params = EThreeParams(identity: identity, tokenCallback: tokenCallback)

        params.biometricProtection = true
        params.loadKeyStrategy = .instant
        params.keyCacheLifeTime = 3

        let ethree = try! EThree(params: params)
        try! ethree.register().startSync().get()

        let message = "message"

        _ = try! ethree.encrypt(text: message)

        sleep(1)

        _  = try! ethree.encrypt(text: message)

        sleep(3)

        _  = try! ethree.encrypt(text: message)
    }
}
